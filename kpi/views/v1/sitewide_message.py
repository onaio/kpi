<<<<<<< HEAD
# coding: utf-8
=======
# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import

>>>>>>> Moved current views and serializers under 'v1' parent folder
from rest_framework import viewsets

from hub.models import SitewideMessage
from kpi.serializers import SitewideMessageSerializer


class SitewideMessageViewSet(viewsets.ModelViewSet):
    queryset = SitewideMessage.objects.all()
    serializer_class = SitewideMessageSerializer
