<<<<<<< HEAD
# coding: utf-8
from kpi.serializers import UserSerializer
from kpi.views.v2.user import UserViewSet as UserViewSetV2


class UserViewSet(UserViewSetV2):
    """
    ## This document is for a deprecated version of kpi's API.

    **Please upgrade to latest release `/api/v2/users/`**

    This viewset provides only the `detail` action; `list` is *not* provided to
    avoid disclosing every username in the database
    """

    serializer_class = UserSerializer
=======
# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import

from django.contrib.auth.models import User
from rest_framework import exceptions, mixins, viewsets

from kpi.models.authorized_application import ApplicationTokenAuthentication
from kpi.serializers import UserSerializer


class UserViewSet(viewsets.GenericViewSet, mixins.RetrieveModelMixin):
    """
    This viewset provides only the `detail` action; `list` is *not* provided to
    avoid disclosing every username in the database
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    lookup_field = 'username'

    def __init__(self, *args, **kwargs):
        super(UserViewSet, self).__init__(*args, **kwargs)
        self.authentication_classes += [ApplicationTokenAuthentication]

    def list(self, request, *args, **kwargs):
        raise exceptions.PermissionDenied()
>>>>>>> Moved current views and serializers under 'v1' parent folder
