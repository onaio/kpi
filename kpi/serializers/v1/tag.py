# coding: utf-8
from rest_framework import serializers
from rest_framework.reverse import reverse
from taggit.models import Tag

from kpi.models import Asset, Collection, TagUid
from kpi.models.object_permission import get_anonymous_user


class TagSerializer(serializers.ModelSerializer):
    url = serializers.SerializerMethodField('_get_tag_url', read_only=True)
    assets = serializers.SerializerMethodField('_get_assets', read_only=True)
    collections = serializers.SerializerMethodField(
        '_get_collections', read_only=True)
    parent = serializers.SerializerMethodField(
        '_get_parent_url', read_only=True)
    uid = serializers.ReadOnlyField(source='taguid.uid')

    class Meta:
        model = Tag
        fields = ('name', 'url', 'assets', 'collections', 'parent', 'uid')

    def _get_parent_url(self, obj):
        return reverse('tag-list', request=self.context.get('request', None))

    def _get_assets(self, obj):
        request = self.context.get('request', None)
        user = request.user
        # Check if the user is anonymous. The
        # django.contrib.auth.models.AnonymousUser object doesn't work for
        # queries.
        if user.is_anonymous:
            user = get_anonymous_user()
        return [reverse('asset-detail', args=(sa.uid,), request=request)
                for sa in Asset.objects.filter(tags=obj, owner=user).all()]

    def _get_collections(self, obj):
        request = self.context.get('request', None)
        user = request.user
        # Check if the user is anonymous. The
        # django.contrib.auth.models.AnonymousUser object doesn't work for
        # queries.
        if user.is_anonymous:
            user = get_anonymous_user()
        return [reverse('collection-detail', args=(coll.uid,), request=request)
                for coll in Collection.objects.filter(tags=obj, owner=user)
                .all()]

    def _get_tag_url(self, obj):
        request = self.context.get('request', None)
        uid = TagUid.objects.get_or_create(tag=obj)[0].uid
        return reverse('tag-detail', args=(uid,), request=request)


class TagListSerializer(TagSerializer):

    class Meta:
        model = Tag
        fields = ('name', 'url', )
