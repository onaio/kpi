<<<<<<< HEAD
# coding: utf-8
from django.contrib.auth.models import User
from rest_framework import viewsets, mixins, exceptions

=======
# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import

from django.contrib.auth.models import User
from rest_framework import viewsets, mixins, exceptions
>>>>>>> Moved current views and serializers under 'v1' parent folder
from kpi.models import AuthorizedApplication
from kpi.models.authorized_application import ApplicationTokenAuthentication
from kpi.serializers import CreateUserSerializer


class AuthorizedApplicationUserViewSet(mixins.CreateModelMixin,
                                       viewsets.GenericViewSet):
    authentication_classes = [ApplicationTokenAuthentication]
    queryset = User.objects.all()
    serializer_class = CreateUserSerializer
    lookup_field = 'username'

    def create(self, request, *args, **kwargs):
        if type(request.auth) is not AuthorizedApplication:
            # Only specially-authorized applications are allowed to create
            # users via this endpoint
            raise exceptions.PermissionDenied()
<<<<<<< HEAD
        return super().create(request, *args, **kwargs)
=======
        return super(AuthorizedApplicationUserViewSet, self).create(
            request, *args, **kwargs)
>>>>>>> Moved current views and serializers under 'v1' parent folder
