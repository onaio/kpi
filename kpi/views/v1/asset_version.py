<<<<<<< HEAD
# coding: utf-8
from kpi.serializers import AssetVersionListSerializer, AssetVersionSerializer
from kpi.views.v2.asset_version import \
    AssetVersionViewSet as AssetVersionViewSetV2


class AssetVersionViewSet(AssetVersionViewSetV2):
    """
    ## This document is for a deprecated version of kpi's API.

    **Please upgrade to latest release `/api/v2/assets/{uid}/versions`**
    """
=======
# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import

from rest_framework import viewsets
from rest_framework_extensions.mixins import NestedViewSetMixin
from kpi.filters import AssetOwnerFilterBackend
from kpi.models import AssetVersion
from kpi.serializers import AssetVersionListSerializer, AssetVersionSerializer


class AssetVersionViewSet(NestedViewSetMixin, viewsets.ModelViewSet):
    model = AssetVersion
    lookup_field = 'uid'
    filter_backends = (
            AssetOwnerFilterBackend,
        )
>>>>>>> Moved current views and serializers under 'v1' parent folder

    def get_serializer_class(self):
        if self.action == 'list':
            return AssetVersionListSerializer
        else:
            return AssetVersionSerializer
<<<<<<< HEAD
=======

    def get_queryset(self):
        _asset_uid = self.get_parents_query_dict()['asset']
        _deployed = self.request.query_params.get('deployed', None)
        _queryset = self.model.objects.filter(asset__uid=_asset_uid)
        if _deployed is not None:
            _queryset = _queryset.filter(deployed=_deployed)
        if self.action == 'list':
            # Save time by only retrieving fields from the DB that the
            # serializer will use
            _queryset = _queryset.only(
                'uid', 'deployed', 'date_modified', 'asset_id')
        # `AssetVersionListSerializer.get_url()` asks for the asset UID
        _queryset = _queryset.select_related('asset__uid')
        return _queryset
>>>>>>> Moved current views and serializers under 'v1' parent folder
