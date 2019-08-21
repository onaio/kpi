# coding: utf-8
from __future__ import (unicode_literals, print_function,
                        absolute_import, division)

from kpi.serializers.v2.asset_version import \
    AssetVersionListSerializer as AssetVersionListSerializerV2, \
    AssetVersionSerializer as AssetVersionSerializerV2


class AssetVersionListSerializer(AssetVersionListSerializerV2):
    pass


class AssetVersionSerializer(AssetVersionSerializerV2):
    pass
