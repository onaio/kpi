# coding: utf-8
from __future__ import (unicode_literals, print_function,
                        absolute_import, division)

import copy
import json
from hashlib import md5

from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from django.utils.six.moves import cStringIO as StringIO
from formpack.utils.expand_content import SCHEMA_VERSION
from rest_framework import status

from kpi.constants import (
    PERM_CHANGE_ASSET,
    PERM_VIEW_ASSET,
    PERM_VIEW_SUBMISSIONS,
    PERM_PARTIAL_SUBMISSIONS,
)

from kpi.models import Asset
from kpi.models import AssetFile
from kpi.models import AssetVersion
from kpi.serializers.v2.asset import AssetListSerializer
from kpi.tests.base_test_case import BaseTestCase
from kpi.tests.kpi_test_case import KpiTestCase
from kpi.urls.router_api_v2 import URL_NAMESPACE as ROUTER_URL_NAMESPACE


EMPTY_SURVEY = {'survey': [], 'schema': SCHEMA_VERSION, 'settings': {}}


class AssetsListApiTests(BaseTestCase):
    fixtures = ['test_data']

    URL_NAMESPACE = ROUTER_URL_NAMESPACE

    def setUp(self):
        self.client.login(username='someuser', password='someuser')
        self.list_url = reverse(self._get_endpoint('asset-list'))

    def test_login_as_other_users(self):
        self.client.logout()
        self.client.login(username='admin', password='pass')
        self.client.logout()
        self.client.login(username='anotheruser', password='anotheruser')
        self.client.logout()

    def test_create_asset(self):
        """
        Ensure we can create a new asset
        """
        data = {
            'content': '{}',
            'asset_type': 'survey',
        }
        response = self.client.post(self.list_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED,
                         msg=response.data)
        sa = Asset.objects.order_by('date_created').last()
        self.assertEqual(sa.content, EMPTY_SURVEY)
        return response

    def test_delete_asset(self):
        self.client.logout()
        self.client.login(username='anotheruser', password='anotheruser')
        creation_response = self.test_create_asset()
        asset_url = creation_response.data['url']
        response = self.client.delete(asset_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK,
                         msg=response.data)

    def test_asset_list_matches_detail(self):
        detail_response = self.test_create_asset()
        list_response = self.client.get(self.list_url)
        self.assertEqual(list_response.status_code, status.HTTP_200_OK,
                         msg=list_response.data)
        expected_list_data = {
            field: detail_response.data[field]
            for field in AssetListSerializer.Meta.fields
        }
        list_result_detail = None
        for result in list_response.data['results']:
            if result['uid'] == expected_list_data['uid']:
                list_result_detail = result
                break
        self.assertIsNotNone(list_result_detail)
        self.assertDictEqual(expected_list_data, dict(list_result_detail))

    def test_assets_hash(self):
        another_user = User.objects.get(username="anotheruser")
        user_asset = Asset.objects.first()
        user_asset.save()
        user_asset.assign_perm(another_user, "view_asset")

        self.client.logout()
        self.client.login(username="anotheruser", password="anotheruser")
        creation_response = self.test_create_asset()

        another_user_asset = another_user.assets.last()
        another_user_asset.save()

        versions_ids = [
            user_asset.version_id,
            another_user_asset.version_id
        ]
        versions_ids.sort()
        expected_hash = md5("".join(versions_ids)).hexdigest()
        hash_url = reverse("asset-hash-list")
        hash_response = self.client.get(hash_url)
        self.assertEqual(hash_response.data.get("hash"), expected_hash)


class AssetVersionApiTests(BaseTestCase):
    fixtures = ['test_data']

    URL_NAMESPACE = ROUTER_URL_NAMESPACE

    def setUp(self):
        self.client.login(username='someuser', password='someuser')
        self.asset = Asset.objects.first()
        self.asset.save()
        self.version = self.asset.asset_versions.first()
        self.version_list_url = reverse(self._get_endpoint('asset-version-list'),
                                        args=(self.asset.uid,))

    def test_asset_version(self):
        self.assertEqual(Asset.objects.count(), 2)
        self.assertEqual(AssetVersion.objects.count(), 1)
        resp = self.client.get(self.version_list_url, format='json')
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data['count'], 1)
        _version_detail_url = resp.data['results'][0].get('url')
        resp2 = self.client.get(_version_detail_url, format='json')
        self.assertTrue('survey' in resp2.data['content'])
        self.assertEqual(len(resp2.data['content']['survey']), 2)

    def test_asset_version_content_hash(self):
        resp = self.client.get(self.version_list_url, format='json')
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        first_version = resp.data['results'][0]
        asset = AssetVersion.objects.get(uid=first_version['uid']).asset
        self.assertEqual(first_version['content_hash'],
                         asset.latest_version.content_hash)
        resp2 = self.client.get(first_version['url'], format='json')
        self.assertEqual(resp2.data['content_hash'],
                         asset.latest_version.content_hash)

    def test_restricted_access_to_version(self):
        self.client.logout()
        self.client.login(username='anotheruser', password='anotheruser')
        resp = self.client.get(self.version_list_url, format='json')
        self.assertEqual(resp.data['count'], 0)
        _version_detail_url = reverse(self._get_endpoint('asset-version-detail'),
                                      args=(self.asset.uid, self.version.uid))
        resp2 = self.client.get(_version_detail_url)
        self.assertEqual(resp2.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(resp2.data['detail'], 'Not found.')


class AssetsDetailApiTests(BaseTestCase):
    fixtures = ['test_data']

    URL_NAMESPACE = ROUTER_URL_NAMESPACE

    def setUp(self):
        self.client.login(username='someuser', password='someuser')
        url = reverse(self._get_endpoint('asset-list'))
        data = {'content': '{}', 'asset_type': 'survey'}
        self.r = self.client.post(url, data, format='json')
        self.asset = Asset.objects.get(uid=self.r.data.get('uid'))
        self.asset_url = self.r.data['url']
        self.assertEqual(self.r.status_code, status.HTTP_201_CREATED)
        self.asset_uid = self.r.data['uid']

    def test_asset_exists(self):
        resp = self.client.get(self.asset_url, format='json')
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

    def test_can_update_asset_settings(self):
        data = {
            'settings': json.dumps({
                'mysetting': 'value'
            }),
        }
        resp = self.client.patch(self.asset_url, data, format='json')
        self.assertEqual(resp.data['settings'], {'mysetting': "value"})

    def test_asset_has_deployment_data(self):
        response = self.client.get(self.asset_url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get('deployment__active'), False)
        self.assertEqual(response.data.get('has_deployment'), False)

    def test_asset_deployment_data_updates(self):
        deployment_url = reverse(self._get_endpoint('asset-deployment'),
                                 kwargs={'uid': self.asset_uid})

        response1 = self.client.post(deployment_url, {
                'backend': 'mock',
                'active': True,
            })

        self.assertEqual(response1.data.get("asset").get('deployment__active'), True)
        self.assertEqual(response1.data.get("asset").get('has_deployment'), True)

        response2 = self.client.get(self.asset_url, format='json')
        self.assertEqual(response2.data.get('deployment__active'), True)
        self.assertEqual(response2.data['has_deployment'], True)

    def test_can_clone_asset(self):
        response = self.client.post(reverse(self._get_endpoint('asset-list')),
                                    format='json',
                                    data={
                                       'clone_from': self.r.data.get('uid'),
                                       'name': 'clones_name',
                                    })
        self.assertEqual(response.status_code, 201)
        new_asset = Asset.objects.get(uid=response.data.get('uid'))
        self.assertEqual(new_asset.content, EMPTY_SURVEY)
        self.assertEqual(new_asset.name, 'clones_name')

    def test_can_clone_version_of_asset(self):
        v1_uid = self.asset.asset_versions.first().uid
        self.asset.content = {'survey': [{'type': 'note', 'label': 'v2'}]}
        self.asset.save()
        self.assertEqual(self.asset.asset_versions.count(), 2)
        v2_uid = self.asset.asset_versions.first().uid
        self.assertNotEqual(v1_uid, v2_uid)

        self.asset.content = {'survey': [{'type': 'note', 'label': 'v3'}]}
        self.asset.save()
        self.assertEqual(self.asset.asset_versions.count(), 3)
        response = self.client.post(reverse(self._get_endpoint('asset-list')),
                                    format='json',
                                    data={
                                       'clone_from_version_id': v2_uid,
                                       'clone_from': self.r.data.get('uid'),
                                       'name': 'clones_name',
                                    })

        self.assertEqual(response.status_code, 201)
        new_asset = Asset.objects.get(uid=response.data.get('uid'))
        self.assertEqual(new_asset.content['survey'][0]['label'], ['v2'])
        self.assertEqual(new_asset.content['translations'], [None])

    def test_deployed_version_pagination(self):
        PAGE_LENGTH = 100
        version = self.asset.latest_version
        preexisting_count = self.asset.deployed_versions.count()
        version.deployed = True
        for i in range(PAGE_LENGTH + 11):
            version.uid = ''
            version.pk = None
            version.save()
        self.assertEqual(
            preexisting_count + PAGE_LENGTH + 11,
            self.asset.deployed_versions.count()
        )
        response = self.client.get(self.asset_url, format='json')
        self.assertEqual(
            response.data['deployed_versions']['count'],
            self.asset.deployed_versions.count()
        )
        self.assertEqual(
            len(response.data['deployed_versions']['results']),
            PAGE_LENGTH
        )

    def check_asset_writable_json_field(self, field_name, **kwargs):
        expected_default = kwargs.get('expected_default', {})
        test_data = kwargs.get(
            'test_data',
            {'test_field': 'test value for {}'.format(field_name)}
        )
        # Check the default value
        response = self.client.get(self.asset_url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data[field_name], expected_default)
        # Update
        response = self.client.patch(
            self.asset_url, format='json',
            data={field_name: json.dumps(test_data)}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Verify
        response = self.client.get(self.asset_url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data[field_name], test_data)

    def test_report_custom_field(self):
        self.check_asset_writable_json_field('report_custom')

    def test_report_styles_field(self):
        test_data = copy.deepcopy(self.asset.report_styles)
        test_data['default'] = {'report_type': 'vertical'}
        self.check_asset_writable_json_field(
            'report_styles',
            expected_default=self.asset.report_styles,
            test_data=test_data
        )

    def test_map_styles_field(self):
        self.check_asset_writable_json_field('map_styles')

    def test_map_custom_field(self):
        self.check_asset_writable_json_field('map_custom')

    def test_asset_version_id_and_content_hash(self):
        response = self.client.get(self.asset_url, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(self.asset.version_id, self.asset.latest_version.uid)
        self.assertEqual(response.data['version_id'],
                         self.asset.version_id)
        self.assertEqual(response.data['version__content_hash'],
                         self.asset.latest_version.content_hash)

    def test_submission_count(self):
        anotheruser = User.objects.get(username='anotheruser')
        self.asset.deploy(backend='mock', active=True)
        submissions = [
            {
                "__version__": self.asset.latest_deployed_version.uid,
                "q1": "a1",
                "q2": "a2",
                "id": 1,
                "_submitted_by": ""
            },
            {
                "__version__": self.asset.latest_deployed_version.uid,
                "q1": "a3",
                "q2": "a4",
                "id": 2,
                "_submitted_by": anotheruser.username
            }
        ]

        self.asset.deployment.mock_submissions(submissions)
        partial_perms = {
            PERM_VIEW_SUBMISSIONS: [{
                '_submitted_by': anotheruser.username
            }]
        }
        self.asset.assign_perm(anotheruser, PERM_PARTIAL_SUBMISSIONS,
                               partial_perms=partial_perms)

        response = self.client.get(self.asset_url, format='json')
        self.assertEqual(response.data['deployment__submission_count'], 2)
        self.client.logout()
        self.client.login(username='anotheruser', password='anotheruser')
        response = self.client.get(self.asset_url, format='json')
        self.assertEqual(response.data['deployment__submission_count'], 1)


class AssetsXmlExportApiTests(KpiTestCase):

    # @TODO Migrate to v2
    pass


class ObjectRelationshipsTests(BaseTestCase):

    # @TODO Migrate to v2
    pass


class AssetsSettingsFieldTest(KpiTestCase):
    fixtures = ['test_data']

    URL_NAMESPACE = ROUTER_URL_NAMESPACE

    def test_query_settings(self):
        asset_title = 'asset_title'
        content = {'settings': [{'id_string': 'titled_asset'}],
                 'survey': [{'label': 'Q1 Label.', 'type': 'decimal'}]}
        self.login('someuser', 'someuser')
        asset = self.create_asset(None, json.dumps(content), format='json')
        self.assert_object_in_object_list(asset)
        # Note: This is not an API method, but an ORM one.
        self.assertFalse(Asset.objects.filter(settings__id_string='titled_asset'))


class AssetExportTaskTest(BaseTestCase):

    # @TODO Migrate to v2
    pass


class AssetFileTest(BaseTestCase):
    fixtures = ['test_data']

    URL_NAMESPACE = ROUTER_URL_NAMESPACE

    def setUp(self):
        self.client.login(username='someuser', password='someuser')
        self.current_username = 'someuser'
        self.asset = Asset.objects.filter(owner__username='someuser').first()
        self.list_url = reverse(self._get_endpoint('asset-file-list'), args=[self.asset.uid])
        # TODO: change the fixture so every asset's owner has all expected
        # permissions?  For now, call `save()` to recalculate permissions and
        # verify the result
        self.asset.save()
        self.assertListEqual(
            sorted(list(self.asset.get_perms(self.asset.owner))),
            sorted(list(Asset.get_assignable_permissions(False) +
                        Asset.CALCULATED_PERMISSIONS))
        )

    @staticmethod
    def absolute_reverse(*args, **kwargs):
        return 'http://testserver/' + reverse(*args, **kwargs).lstrip('/')

    def get_asset_file_content(self, url):
        response = self.client.get(url)
        return ''.join(response.streaming_content)

    @property
    def asset_file_payload(self):
        return {
            'file_type': 'map_layer',
            'name': 'Dinagat Islands',
            'content':
                StringIO(json.dumps(
                    {
                        "type": "Feature",
                        "geometry": {
                            "type": "Point",
                            "coordinates": [125.6, 10.1]
                        },
                        "properties": {
                            "name": "Dinagat Islands"
                        }
                    }
                )),
            'metadata': json.dumps({'source': 'http://geojson.org/'}),
        }

    def switch_user(self, *args, **kwargs):
        self.client.logout()
        self.client.login(*args, **kwargs)
        self.current_username = kwargs['username']

    def create_asset_file(self):
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(json.loads(response.content)['count'], 0)
        response = self.client.post(self.list_url, self.asset_file_payload)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        return response

    def verify_asset_file(self, response):
        posted_payload = self.asset_file_payload
        response_dict = json.loads(response.content)
        self.assertEqual(
            response_dict['asset'],
            self.absolute_reverse(self._get_endpoint('asset-detail'), args=[self.asset.uid])
        )
        self.assertEqual(
            response_dict['user'],
            self.absolute_reverse(self._get_endpoint('user-detail'),
                                  args=[self.current_username])
        )
        self.assertEqual(
            response_dict['user__username'],
            self.current_username,
        )
        self.assertEqual(
            json.dumps(response_dict['metadata']),
            posted_payload['metadata']
        )
        for field in 'file_type', 'name':
            self.assertEqual(response_dict[field], posted_payload[field])
        # Content via the direct URL to the file
        posted_payload['content'].seek(0)
        expected_content = posted_payload['content'].read()
        self.assertEqual(
            self.get_asset_file_content(response_dict['content']),
            expected_content
        )
        return response_dict['uid']

    def test_owner_can_create_file(self):
        self.verify_asset_file(self.create_asset_file())

    def test_owner_can_delete_file(self):
        af_uid = self.verify_asset_file(self.create_asset_file())
        detail_url = reverse(self._get_endpoint('asset-file-detail'),
                             args=(self.asset.uid, af_uid))
        response = self.client.delete(detail_url)
        self.assertTrue(response.status_code, status.HTTP_204_NO_CONTENT)
        # TODO: test that the file itself is removed

    def test_editor_can_create_file(self):
        anotheruser = User.objects.get(username='anotheruser')
        self.assertListEqual(list(self.asset.get_perms(anotheruser)), [])
        self.asset.assign_perm(anotheruser, PERM_CHANGE_ASSET)
        self.assertTrue(self.asset.has_perm(anotheruser, PERM_CHANGE_ASSET))
        self.switch_user(username='anotheruser', password='anotheruser')
        self.verify_asset_file(self.create_asset_file())

    def test_editor_can_delete_file(self):
        anotheruser = User.objects.get(username='anotheruser')
        self.assertListEqual(list(self.asset.get_perms(anotheruser)), [])
        self.asset.assign_perm(anotheruser, PERM_CHANGE_ASSET)
        self.assertTrue(self.asset.has_perm(anotheruser, PERM_CHANGE_ASSET))
        self.switch_user(username='anotheruser', password='anotheruser')
        af_uid = self.verify_asset_file(self.create_asset_file())
        detail_url = reverse(self._get_endpoint('asset-file-detail'),
                             args=(self.asset.uid, af_uid))
        response = self.client.delete(detail_url)
        self.assertTrue(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_viewer_can_access_file(self):
        af_uid = self.verify_asset_file(self.create_asset_file())
        detail_url = reverse(self._get_endpoint('asset-file-detail'),
                             args=(self.asset.uid, af_uid))
        anotheruser = User.objects.get(username='anotheruser')
        self.assertListEqual(list(self.asset.get_perms(anotheruser)), [])
        self.asset.assign_perm(anotheruser, PERM_VIEW_ASSET)
        self.assertTrue(self.asset.has_perm(anotheruser, PERM_VIEW_ASSET))
        self.switch_user(username='anotheruser', password='anotheruser')
        response = self.client.get(detail_url)
        self.assertTrue(response.status_code, status.HTTP_200_OK)

    def test_viewer_cannot_create_file(self):
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(json.loads(response.content)['count'], 0)

        self.switch_user(username='anotheruser', password='anotheruser')
        anotheruser = User.objects.get(username='anotheruser')
        self.assertListEqual(list(self.asset.get_perms(anotheruser)), [])
        self.asset.assign_perm(anotheruser, PERM_VIEW_ASSET)
        self.assertTrue(self.asset.has_perm(anotheruser, PERM_VIEW_ASSET))
        response = self.client.post(self.list_url, self.asset_file_payload)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        self.switch_user(username='someuser', password='someuser')
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(json.loads(response.content)['count'], 0)

    def test_viewer_cannot_delete_file(self):
        af_uid = self.verify_asset_file(self.create_asset_file())
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(json.loads(response.content)['count'], 1)
        detail_url = reverse(self._get_endpoint('asset-file-detail'),
                             args=(self.asset.uid, af_uid))

        self.switch_user(username='anotheruser', password='anotheruser')
        anotheruser = User.objects.get(username='anotheruser')
        self.assertListEqual(list(self.asset.get_perms(anotheruser)), [])
        self.asset.assign_perm(anotheruser, PERM_VIEW_ASSET)
        self.assertTrue(self.asset.has_perm(anotheruser, PERM_VIEW_ASSET))
        response = self.client.delete(detail_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        self.switch_user(username='someuser', password='someuser')
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(json.loads(response.content)['count'], 1)

    def test_unprivileged_user_cannot_access_file(self):
        af_uid = self.verify_asset_file(self.create_asset_file())
        detail_url = reverse(self._get_endpoint('asset-file-detail'),
                             args=(self.asset.uid, af_uid))
        anotheruser = User.objects.get(username='anotheruser')
        self.assertListEqual(list(self.asset.get_perms(anotheruser)), [])
        self.switch_user(username='anotheruser', password='anotheruser')
        response = self.client.get(detail_url)
        self.assertTrue(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_anon_cannot_access_file(self):
        af_uid = self.verify_asset_file(self.create_asset_file())
        detail_url = reverse(self._get_endpoint('asset-file-detail'),
                             args=(self.asset.uid, af_uid))

        self.client.logout()
        response = self.client.get(detail_url)
        self.assertTrue(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_files_are_filtered_by_parent_asset(self):
        af1_uid = self.verify_asset_file(self.create_asset_file())
        af1 = AssetFile.objects.get(uid=af1_uid)
        af1.asset = self.asset.clone()
        af1.asset.owner = self.asset.owner
        af1.asset.save()
        af1.save()
        af2_uid = self.verify_asset_file(self.create_asset_file())
        af2 = AssetFile.objects.get(uid=af2_uid)

        for af in af1, af2:
            response = self.client.get(
                reverse(self._get_endpoint('asset-file-list'), args=[af.asset.uid]))
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            asset_files = json.loads(response.content)['results']
            self.assertEqual(len(asset_files), 1)
            self.assertEqual(asset_files[0]['uid'], af.uid)
