# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from rest_framework import status

from kpi.constants import PERM_VIEW_SUBMISSIONS, \
    PERM_PARTIAL_SUBMISSIONS
from kpi.models import Asset
from kpi.tests.base_test_case import BaseTestCase
from kpi.urls.router_api_v2 import URL_NAMESPACE as ROUTER_URL_NAMESPACE


class BaseSubmissionTestCase(BaseTestCase):
    """
    DataViewset uses `BrowsableAPIRenderer` as the first renderer.
    Force JSON to test the API by specifying `format`, `HTTP_ACCEPT` or 
    `content_type`
    """

    fixtures = ["test_data"]

    URL_NAMESPACE = ROUTER_URL_NAMESPACE

    def setUp(self):
        self.client.login(username="someuser", password="someuser")
        self.someuser = User.objects.get(username="someuser")
        self.anotheruser = User.objects.get(username="anotheruser")
        asset_template = Asset.objects.get(id=1)
        self.asset = Asset.objects.create(content=asset_template.content,
                                          owner=self.someuser,
                                          asset_type='survey')

        self.asset.deploy(backend='mock', active=True)
        self.asset.save()

        v_uid = self.asset.latest_deployed_version.uid
        self.submissions = [
            {
                "__version__": v_uid,
                "q1": "a1",
                "q2": "a2",
                "id": 1,
                "_validation_status": {
                    "by_whom": "someuser",
                    "timestamp": 1547839938,
                    "uid": "validation_status_on_hold",
                    "color": "#0000ff",
                    "label": "On Hold"
                },
                "submitted_by": ""
            },
            {
                "__version__": v_uid,
                "q1": "a3",
                "q2": "a4",
                "id": 2,
                "_validation_status": {
                    "by_whom": "someuser",
                    "timestamp": 1547839938,
                    "uid": "validation_status_approved",
                    "color": "#0000ff",
                    "label": "On Hold"
                },
                "submitted_by": "someuser"
            }
        ]
        self.asset.deployment.mock_submissions(self.submissions)
        self.asset.deployment.set_namespace(self.URL_NAMESPACE)
        self.submission_url = self.asset.deployment.submission_list_url

    def _other_user_login(self, shared_asset=False):
        self.client.logout()
        self.client.login(username="anotheruser", password="anotheruser")
        if shared_asset:
            self.asset.assign_perm(self.anotheruser, PERM_VIEW_SUBMISSIONS)


class SubmissionApiTests(BaseSubmissionTestCase):

    def test_create_submission(self):
        v_uid = self.asset.latest_deployed_version.uid
        submission = {
            "q1": "a5",
            "q2": "a6",
        }
        # Owner
        response = self.client.post(self.submission_url, data=submission)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

        # Shared
        self._other_user_login(True)
        response = self.client.post(self.submission_url, data=submission)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        # Anonymous
        self.client.logout()
        response = self.client.post(self.submission_url, data=submission)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_list_submissions_owner(self):
        response = self.client.get(self.submission_url, {"format": "json"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, self.submissions)

    def test_list_submissions_not_shared_other(self):
        self._other_user_login()
        response = self.client.get(self.submission_url, {"format": "json"})
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_list_submissions_shared_other(self):
        self._other_user_login(True)
        response = self.client.get(self.submission_url, {"format": "json"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, self.submissions)

    def test_list_submissions_with_partial_permissions(self):
        self._other_user_login()
        partial_perms = {
            PERM_VIEW_SUBMISSIONS: [{'_submitted_by': self.someuser.username}]
        }
        response = self.client.get(self.submission_url, {"format": "json"})
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

        self.asset.assign_perm(self.anotheruser, PERM_PARTIAL_SUBMISSIONS,
                               partial_perms=partial_perms)
        response = self.client.get(self.submission_url, {"format": "json"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(self.asset.deployment.submission_count == 2)
        # User `anotheruser` should only see submissions where `submitted_by`
        # is filled up and equals to `someuser`
        self.assertTrue(len(response.data) == 1)

    def test_list_submissions_anonymous(self):
        self.client.logout()
        response = self.client.get(self.submission_url, {"format": "json"})
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_retrieve_submission_owner(self):
        submission = self.submissions[0]
        url = self.asset.deployment.get_submission_detail_url(submission.get("id"))

        response = self.client.get(url, {"format": "json"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, submission)

    def test_retrieve_submission_not_shared_other(self):
        self._other_user_login()
        submission = self.submissions[0]
        url = self.asset.deployment.get_submission_detail_url(submission.get("id"))
        response = self.client.get(url, {"format": "json"})
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_retrieve_submission_shared_other(self):
        self._other_user_login(True)
        submission = self.submissions[0]
        url = self.asset.deployment.get_submission_detail_url(submission.get("id"))
        response = self.client.get(url, {"format": "json"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, submission)

    def test_retrieve_submission_with_partial_permissions(self):
        self._other_user_login()
        partial_perms = {
            PERM_VIEW_SUBMISSIONS: [{'_submitted_by': self.someuser.username}]
        }
        self.asset.assign_perm(self.anotheruser, PERM_PARTIAL_SUBMISSIONS,
                               partial_perms=partial_perms)

        # Try first submission submitted by unknown
        submission = self.submissions[0]
        url = self.asset.deployment.get_submission_detail_url(submission.get("id"))
        response = self.client.get(url, {"format": "json"})
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

        # Try second submission submitted by someuser
        submission = self.submissions[1]
        url = self.asset.deployment.get_submission_detail_url(submission.get("id"))
        response = self.client.get(url, {"format": "json"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_delete_submission_owner(self):
        submission = self.submissions[0]
        url = self.asset.deployment.get_submission_detail_url(submission.get("id"))

        response = self.client.delete(url,
                                      content_type="application/json",
                                      HTTP_ACCEPT="application/json")
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_delete_submission_anonymous(self):
        self.client.logout()
        submission = self.submissions[0]
        url = self.asset.deployment.get_submission_detail_url(submission.get("id"))

        response = self.client.delete(url,
                                      content_type="application/json",
                                      HTTP_ACCEPT="application/json")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_delete_submission_not_shared_other(self):
        self._other_user_login()
        submission = self.submissions[0]
        url = self.asset.deployment.get_submission_detail_url(submission.get("id"))

        response = self.client.delete(url,
                                      content_type="application/json",
                                      HTTP_ACCEPT="application/json")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_delete_submission_shared_other_no_write(self):
        self._other_user_login(True)
        submission = self.submissions[0]
        url = self.asset.deployment.get_submission_detail_url(submission.get("id"))
        response = self.client.delete(url,
                                      content_type="application/json",
                                      HTTP_ACCEPT="application/json")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_delete_submission_shared_other_write(self):
        self._other_user_login(True)
        self.asset.assign_perm(self.anotheruser, "change_submissions")
        submission = self.submissions[0]
        url = self.asset.deployment.get_submission_detail_url(submission.get("id"))
        response = self.client.delete(url,
                                      content_type="application/json",
                                      HTTP_ACCEPT="application/json")
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)


class SubmissionEditApiTests(BaseSubmissionTestCase):

    def setUp(self):
        super(SubmissionEditApiTests, self).setUp()
        self.submission = self.submissions[0]
        self.submission_url = reverse(self._get_endpoint('submission-edit'), kwargs={
            "parent_lookup_asset": self.asset.uid,
            "pk": self.submission.get("id")
        })

    def test_trigger_signal(self):
        response = self.client.get(self.submission_url, {"format": "json"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        expected_response = {
            "url": "http://server.mock/enketo/{}".format(self.submission.get("id"))
        }
        self.assertEqual(response.data, expected_response)

    def test_get_edit_link_submission_anonymous(self):
        self.client.logout()
        response = self.client.get(self.submission_url, {"format": "json"})
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_get_edit_link_submission_shared_other(self):
        self._other_user_login()
        response = self.client.get(self.submission_url, {"format": "json"})
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class SubmissionValidationStatusApiTests(BaseSubmissionTestCase):

    # @TODO Test PATCH

    def setUp(self):
        super(SubmissionValidationStatusApiTests, self).setUp()
        self.submission = self.submissions[0]
        self.validation_status_url = self.asset.deployment.get_submission_validation_status_url(
            self.submission.get("id"))

    def test_submission_validate_status_owner(self):
        response = self.client.get(self.validation_status_url, {"format": "json"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, self.submission.get("_validation_status"))

    def test_submission_validate_status_not_shared_other(self):
        self._other_user_login()
        response = self.client.get(self.validation_status_url, {"format": "json"})
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_submission_validate_status_other(self):
        self._other_user_login(True)
        response = self.client.get(self.validation_status_url, {"format": "json"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, self.submission.get("_validation_status"))

    def test_submission_validate_status_anonymous(self):
        self.client.logout()
        response = self.client.get(self.validation_status_url, {"format": "json"})
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
