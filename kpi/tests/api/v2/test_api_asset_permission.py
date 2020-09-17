# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from rest_framework import status

from kpi.constants import PERM_VIEW_ASSET, PERM_CHANGE_ASSET
from kpi.models import Asset
from kpi.models.object_permission import get_anonymous_user
from kpi.tests.kpi_test_case import KpiTestCase
from kpi.urls.router_api_v2 import URL_NAMESPACE as ROUTER_URL_NAMESPACE


class BaseApiAssetPermissionTestCase(KpiTestCase):

    fixtures = ["test_data"]

    URL_NAMESPACE = ROUTER_URL_NAMESPACE

    def setUp(self):
        self.admin = User.objects.get(username='admin')
        self.someuser = User.objects.get(username='someuser')
        self.anotheruser = User.objects.get(username='anotheruser')

        self.client.login(username='admin', password='pass')
        self.asset = self.create_asset('An asset to be shared')

        self.someuser_detail_url = reverse(
            self._get_endpoint('user-detail'),
            kwargs={'username': self.someuser.username})

        self.anotheruser_detail_url = reverse(
            self._get_endpoint('user-detail'),
            kwargs={'username': self.anotheruser.username})

        self.view_asset_permission_detail_url = reverse(
            self._get_endpoint('permission-detail'),
            kwargs={'codename': PERM_VIEW_ASSET})

        self.change_asset_permission_detail_url = reverse(
            self._get_endpoint('permission-detail'),
            kwargs={'codename': PERM_CHANGE_ASSET})

        self.asset_permissions_list_url = reverse(
            self._get_endpoint('asset-permission-list'),
            kwargs={'parent_lookup_asset': self.asset.uid}
        )


class ApiAssetPermissionTestCase(BaseApiAssetPermissionTestCase):

    def _logged_user_gives_permission(self, username, permission):
        """
        Uses the API to grant `permission` to `username`
        """
        data = {
            'user': getattr(self, '{}_detail_url'.format(username)),
            'permission': getattr(self, '{}_permission_detail_url'.format(permission))
        }
        response = self.client.post(self.asset_permissions_list_url,
                                    data, format='json')
        return response

    def test_owner_can_give_permissions(self):
        # Current user is `self.admin`
        response = self._logged_user_gives_permission('someuser', PERM_VIEW_ASSET)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_viewers_can_not_give_permissions(self):
        self._logged_user_gives_permission('someuser', PERM_VIEW_ASSET)
        self.client.login(username='someuser', password='someuser')
        # Current user is now: `self.someuser`
        response = self._logged_user_gives_permission('anotheruser', PERM_VIEW_ASSET)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_editors_can_give_permissions(self):
        self._logged_user_gives_permission('someuser', PERM_CHANGE_ASSET)
        self.client.login(username='someuser', password='someuser')
        # Current user is now: `self.someuser`
        response = self._logged_user_gives_permission('anotheruser', PERM_VIEW_ASSET)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_anonymous_can_not_give_permissions(self):
        self.client.logout()
        response = self._logged_user_gives_permission('someuser', PERM_VIEW_ASSET)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class ApiAssetPermissionListTestCase(BaseApiAssetPermissionTestCase):
    """
    TODO Refactor tests - Redundant codes
    """
    fixtures = ["test_data"]

    URL_NAMESPACE = ROUTER_URL_NAMESPACE

    def setUp(self):
        super(ApiAssetPermissionListTestCase, self).setUp()

        self.asset.assign_perm(self.someuser, PERM_CHANGE_ASSET)
        self.asset.assign_perm(self.anotheruser, PERM_VIEW_ASSET)

    def test_viewers_see_only_their_own_assignments_and_owner_s(self):

        # Checks if can see all permissions
        self.client.login(username='anotheruser', password='anotheruser')
        permission_list_response = self.client.get(self.asset_permissions_list_url,
                                                   format='json')
        self.assertEqual(permission_list_response.status_code, status.HTTP_200_OK)
        admin_perms = self.asset.get_perms(self.admin)
        anotheruser_perms = self.asset.get_perms(self.anotheruser)
        results = permission_list_response.data.get('results')

        # `anotheruser` can only see the owner's permissions `self.admin` and
        # `anotheruser`'s permissions. Should not see `someuser`s ones.
        expected_perms = []
        for admin_perm in admin_perms:
            if admin_perm in Asset.get_assignable_permissions():
                expected_perms.append((self.admin.username, admin_perm))
        for anotheruser_perm in anotheruser_perms:
            if anotheruser_perm in Asset.get_assignable_permissions():
                expected_perms.append((self.anotheruser.username, anotheruser_perm))

        expected_perms = sorted(expected_perms, key=lambda element: (element[0],
                                                                     element[1]))
        obj_perms = []
        for assignment in results:
            object_permission = self.url_to_obj(assignment.get('url'))
            obj_perms.append((object_permission.user.username,
                              object_permission.permission.codename))

        obj_perms = sorted(obj_perms, key=lambda element: (element[0],
                                                           element[1]))

        self.assertEqual(expected_perms, obj_perms)

    def test_editors_see_all_assignments(self):

        self.client.login(username='someuser', password='someuser')
        permission_list_response = self.client.get(self.asset_permissions_list_url,
                                                   format='json')
        self.assertEqual(permission_list_response.status_code, status.HTTP_200_OK)
        admin_perms = self.asset.get_perms(self.admin)
        someuser_perms = self.asset.get_perms(self.someuser)
        anotheruser_perms = self.asset.get_perms(self.anotheruser)
        results = permission_list_response.data.get('results')

        # As an editor of the asset. `someuser` should see all.
        expected_perms = []
        for admin_perm in admin_perms:
            if admin_perm in Asset.get_assignable_permissions():
                expected_perms.append((self.admin.username, admin_perm))
        for someuser_perm in someuser_perms:
            if someuser_perm in Asset.get_assignable_permissions():
                expected_perms.append((self.someuser.username, someuser_perm))
        for anotheruser_perm in anotheruser_perms:
            if anotheruser_perm in Asset.get_assignable_permissions():
                expected_perms.append((self.anotheruser.username, anotheruser_perm))

        expected_perms = sorted(expected_perms, key=lambda element: (element[0],
                                                                     element[1]))
        obj_perms = []
        for assignment in results:
            object_permission = self.url_to_obj(assignment.get('url'))
            obj_perms.append((object_permission.user.username,
                              object_permission.permission.codename))

        obj_perms = sorted(obj_perms, key=lambda element: (element[0],
                                                           element[1]))

        self.assertEqual(expected_perms, obj_perms)

    def test_anonymous_get_only_owner_s_assignments(self):

        self.client.logout()
        self.asset.assign_perm(get_anonymous_user(), PERM_VIEW_ASSET)
        permission_list_response = self.client.get(self.asset_permissions_list_url,
                                                   format='json')
        self.assertEqual(permission_list_response.status_code, status.HTTP_200_OK)
        admin_perms = self.asset.get_perms(self.admin)
        results = permission_list_response.data.get('results')

        # Get admin permissions.
        expected_perms = []
        for admin_perm in admin_perms:
            if admin_perm in Asset.get_assignable_permissions():
                expected_perms.append((self.admin.username, admin_perm))

        expected_perms = sorted(expected_perms, key=lambda element: (element[0],
                                                                     element[1]))
        obj_perms = []
        for assignment in results:
            object_permission = self.url_to_obj(assignment.get('url'))
            obj_perms.append((object_permission.user.username,
                              object_permission.permission.codename))

        obj_perms = sorted(obj_perms, key=lambda element: (element[0],
                                                           element[1]))
        self.assertEqual(expected_perms, obj_perms)
