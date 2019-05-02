<<<<<<< HEAD
# coding: utf-8
=======
# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import

>>>>>>> Moved current views and serializers under 'v1' parent folder
from rest_framework import exceptions
from rest_framework import mixins
from rest_framework import viewsets

from kpi.models import AuthorizedApplication, OneTimeAuthenticationKey
from kpi.models.authorized_application import ApplicationTokenAuthentication
from kpi.serializers import OneTimeAuthenticationKeySerializer


class OneTimeAuthenticationKeyViewSet(
        mixins.CreateModelMixin,
        viewsets.GenericViewSet
):
    authentication_classes = [ApplicationTokenAuthentication]
    queryset = OneTimeAuthenticationKey.objects.none()
    serializer_class = OneTimeAuthenticationKeySerializer

    def create(self, request, *args, **kwargs):
        if type(request.auth) is not AuthorizedApplication:
            # Only specially-authorized applications are allowed to create
            # one-time authentication keys via this endpoint
            raise exceptions.PermissionDenied()
<<<<<<< HEAD
        return super().create(
=======
        return super(OneTimeAuthenticationKeyViewSet, self).create(
>>>>>>> Moved current views and serializers under 'v1' parent folder
            request, *args, **kwargs)
