# coding: utf-8
from __future__ import (unicode_literals, print_function,
                        absolute_import, division)

from django.core.urlresolvers import reverse
from formpack.utils.expand_content import SCHEMA_VERSION
from rest_framework import status
from rest_framework.test import APITestCase

from kpi.models import Asset


class BaseTestCase(APITestCase):

    URL_NAMESPACE = None

    def _get_endpoint(self, endpoint):
        if hasattr(self, 'URL_NAMESPACE') and self.URL_NAMESPACE is not None:
            endpoint = '{}:{}'.format(self.URL_NAMESPACE, endpoint) \
                if self.URL_NAMESPACE else endpoint
        return endpoint


class BaseAssetTestCase(BaseTestCase):

    EMPTY_SURVEY = {'survey': [], 'schema': SCHEMA_VERSION, 'settings': {}}

    def create_asset(self, asset_type='survey'):
        """ Create a new, empty asset as the currently logged-in user """
        data = {
            'content': '{}',
            'asset_type': asset_type,
        }
        list_url = reverse(self._get_endpoint('asset-list'))
        response = self.client.post(list_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED,
                         msg=response.data)
        sa = Asset.objects.order_by('date_created').last()
        self.assertEqual(sa.content, self.EMPTY_SURVEY)
        return response
