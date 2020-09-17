# -*- coding: utf-8 -*-
from __future__ import absolute_import

import datetime
import pytz

from django.contrib.auth.models import User
from django.db import transaction
from django.conf import settings
from rest_framework import serializers

from kobo.static_lists import SECTORS, COUNTRIES, LANGUAGES
from hub.models import ExtraUserDetail
from kpi.deployment_backends.kc_access.utils import get_kc_profile_data
from kpi.deployment_backends.kc_access.utils import set_kc_require_auth
from kpi.fields import WritableJSONField
from kpi.utils.gravatar_url import gravatar_url


class CurrentUserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    server_time = serializers.SerializerMethodField()
    date_joined = serializers.SerializerMethodField()
    projects_url = serializers.SerializerMethodField()
    gravatar = serializers.SerializerMethodField()
    languages = serializers.SerializerMethodField()
    extra_details = WritableJSONField(source='extra_details.data')
    current_password = serializers.CharField(write_only=True, required=False)
    new_password = serializers.CharField(write_only=True, required=False)
    git_rev = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = (
            'username',
            'first_name',
            'last_name',
            'email',
            'server_time',
            'date_joined',
            'projects_url',
            'is_superuser',
            'gravatar',
            'is_staff',
            'last_login',
            'languages',
            'extra_details',
            'current_password',
            'new_password',
            'git_rev',
        )

    def get_server_time(self, obj):
        # Currently unused on the front end
        return datetime.datetime.now(tz=pytz.UTC).strftime(
            '%Y-%m-%dT%H:%M:%SZ')

    def get_date_joined(self, obj):
        return obj.date_joined.astimezone(pytz.UTC).strftime(
            '%Y-%m-%dT%H:%M:%SZ')

    def get_projects_url(self, obj):
        return '/'.join((settings.KOBOCAT_URL, obj.username))

    def get_gravatar(self, obj):
        return gravatar_url(obj.email)

    def get_languages(self, obj):
        return settings.LANGUAGES

    def get_git_rev(self, obj):
        request = self.context.get('request', False)
        if settings.EXPOSE_GIT_REV or (request and request.user.is_superuser):
            return settings.GIT_REV
        else:
            return False

    def to_representation(self, obj):
        if obj.is_anonymous():
            return {'message': 'user is not logged in'}
        rep = super(CurrentUserSerializer, self).to_representation(obj)
        if settings.UPCOMING_DOWNTIME:
            # setting is in the format:
            # [dateutil.parser.parse('6pm edt').isoformat(), countdown_msg]
            rep['upcoming_downtime'] = settings.UPCOMING_DOWNTIME
        # TODO: Find a better location for SECTORS and COUNTRIES
        # as the functionality develops. (possibly in tags?)
        rep['available_sectors'] = SECTORS
        rep['available_countries'] = COUNTRIES
        rep['all_languages'] = LANGUAGES
        if not rep['extra_details']:
            rep['extra_details'] = {}
        # `require_auth` needs to be read from KC every time
        if settings.KOBOCAT_URL and settings.KOBOCAT_INTERNAL_URL:
            rep['extra_details']['require_auth'] = get_kc_profile_data(
                obj.pk).get('require_auth', False)

        return rep

    def update(self, instance, validated_data):
        # "The `.update()` method does not support writable dotted-source
        # fields by default." --DRF
        extra_details = validated_data.pop('extra_details', False)
        if extra_details:
            extra_details_obj, created = ExtraUserDetail.objects.get_or_create(
                user=instance)
            # `require_auth` needs to be written back to KC
            if settings.KOBOCAT_URL and settings.KOBOCAT_INTERNAL_URL and \
                    'require_auth' in extra_details['data']:
                set_kc_require_auth(
                    instance.pk, extra_details['data']['require_auth'])
            extra_details_obj.data.update(extra_details['data'])
            extra_details_obj.save()
        current_password = validated_data.pop('current_password', False)
        new_password = validated_data.pop('new_password', False)
        if all((current_password, new_password)):
            with transaction.atomic():
                if instance.check_password(current_password):
                    instance.set_password(new_password)
                    instance.save()
                else:
                    raise serializers.ValidationError({
                        'current_password': 'Incorrect current password.'
                    })
        elif any((current_password, new_password)):
            raise serializers.ValidationError(
                'current_password and new_password must both be sent ' \
                'together; one or the other cannot be sent individually.'
            )
        return super(CurrentUserSerializer, self).update(
            instance, validated_data)
