# coding: utf-8
import re

from django.urls import reverse
from rest_framework import status

from kpi.constants import INSTANCE_FORMAT_TYPE_JSON, INSTANCE_FORMAT_TYPE_XML
from .base_backend import BaseDeploymentBackend


class MockDeploymentBackend(BaseDeploymentBackend):
    """
    Only used for unit testing and interface testing.

    defines the interface for a deployment backend.

    # TODO. Stop using protected property `_deployment_data`.
    """

    def bulk_assign_mapped_perms(self):
        pass

    def connect(self, active=False):
        self.store_data({
                'backend': 'mock',
                'identifier': 'mock://%s' % self.asset.uid,
                'active': active,
            })

    def redeploy(self, active=None):
        """
        Replace (overwrite) the deployment, keeping the same identifier, and
        optionally changing whether the deployment is active
        """
        if active is None:
            active = self.active
        self.set_active(active)

    def set_active(self, active):
        self.store_data({
                'active': bool(active),
            })

    def set_namespace(self, namespace):
        self.store_data({
            'namespace': namespace,
        })

    def get_enketo_survey_links(self):
        # `self` is a demo Enketo form, but there's no guarantee it'll be
        # around forever.
        return {
            'offline_url': 'https://enke.to/_/#self',
            'url': 'https://enke.to/::self',
            'iframe_url': 'https://enke.to/i/::self',
            'preview_url': 'https://enke.to/preview/::self',
            # 'preview_iframe_url': 'https://enke.to/preview/i/::self',
        }

    @property
    def submission_list_url(self):
        # This doesn't really need to be implemented.
        # We keep it to stay close to `KobocatDeploymentBackend`
        view_name = 'submission-list'
        namespace = self.asset._deployment_data.get('namespace', None)
        if namespace is not None:
            view_name = '{}:{}'.format(namespace, view_name)
        return reverse(view_name, kwargs={"parent_lookup_asset": self.asset.uid})

    def get_submission_detail_url(self, submission_pk):
        # This doesn't really need to be implemented.
        # We keep it to stay close to `KobocatDeploymentBackend`
        url = '{list_url}{pk}/'.format(
            list_url=self.submission_list_url,
            pk=submission_pk
        )
        return url

    def get_submission_edit_url(self, submission_pk, user, params=None):
        """
        Gets edit URL of the submission in a format FE can understand

        :param submission_pk: int
        :param user: User
        :param params: dict
        :return: dict
        """

        return {
            "data": {
                "url": "http://server.mock/enketo/{}".format(submission_pk)
            }
        }

    def get_submission_validation_status_url(self, submission_pk):
        # This doesn't really need to be implemented.
        # We keep it to stay close to `KobocatDeploymentBackend`
        url = '{detail_url}validation_status/'.format(
            detail_url=self.get_submission_detail_url(submission_pk)
        )
        return url

    def delete_submission(self, pk, user):
        """
        Deletes submission
        :param pk: int
        :param user: User
        :return: JSON
        """
        # No need to delete data, just fake it
        return {
            "content_type": "application/json",
            "status": status.HTTP_204_NO_CONTENT,
        }

    def get_data_download_links(self):
        return {}

    def _submission_count(self):
        submissions = self.asset._deployment_data.get('submissions', [])
        return len(submissions)

    def _mock_submission(self, submission):
        """
        @TODO may be useless because of mock_submissions. Remove if it's not used anymore anywhere else.
        :param submission:
        """
        submissions = self.asset._deployment_data.get('submissions', [])
        submissions.append(submission)
        self.store_data({
            'submissions': submissions,
            })

    def mock_submissions(self, submissions):
        """
        Insert dummy submissions into `asset._deployment_data`
        :param submissions: list
        """
        self.store_data({"submissions": submissions})
        self.asset.save(create_version=False)

    def get_submissions(self, requesting_user_id,
                        format_type=INSTANCE_FORMAT_TYPE_JSON,
                        instance_ids=[], **kwargs):
        """
        Retrieves submissions on `format_type`.
        It can be filtered on instances ids.

        Args:
            requesting_user_id (int)
            format_type (str): INSTANCE_FORMAT_TYPE_JSON|INSTANCE_FORMAT_TYPE_XML
            instance_ids (list): Instance ids to retrieve
            kwargs (dict): Filters to pass to MongoDB. See
                https://docs.mongodb.com/manual/reference/operator/query/

        Returns:
            (dict|str|`None`): Depending of `format_type`, it can return:
                - Mongo JSON representation as a dict
                - Instances' XML as string
                - `None` if no results
        """

        submissions = self.asset._deployment_data.get("submissions", [])
        kwargs['instance_ids'] = instance_ids
        params = self.validate_submission_list_params(requesting_user_id,
                                                      format_type=format_type,
                                                      **kwargs)
        permission_filters = params['permission_filters']

        if len(instances_ids) > 0:
            if format_type == INSTANCE_FORMAT_TYPE_XML:
                instance_ids = [str(instance_id) for instance_id in instance_ids]
                # ugly way to find matches, but it avoids to load each xml in memory.
                pattern = r'<{id_field}>({instance_ids})<\/{id_field}>'.format(
                    instance_ids='|'.join(instance_ids),
                    id_field=self.INSTANCE_ID_FIELDNAME
                )
                submissions = [submission for submission in submissions
                               if re.search(pattern, submission)]
            else:
                instance_ids = [int(instance_id) for instance_id in instance_ids]
                submissions = [submission for submission in submissions
                               if submission.get(self.INSTANCE_ID_FIELDNAME)
                               in instance_ids]

        if permission_filters:
            submitted_by = [k.get('_submitted_by') for k in permission_filters]
            if format_type == INSTANCE_FORMAT_TYPE_XML:
                # TODO handle `submitted_by` too.
                raise NotImplementedError
            else:
                submissions = [submission for submission in submissions
                               if submission.get('_submitted_by') in submitted_by]

        # Python-only attribute used by `kpi.views.v2.data.DataViewSet.list()`
        self.current_submissions_count = len(submissions)

        # TODO: support other query parameters?
        if 'limit' in params:
            submissions = submissions[:params['limit']]

        return submissions

    def get_validation_status(self, submission_pk, params, user):
        submission = self.get_submission(submission_pk, user.id,
                                         INSTANCE_FORMAT_TYPE_JSON)
        return {
            "data": submission.get("_validation_status")
        }

    def set_validation_status(self, submission_pk, data, user, method):
        pass

    def set_validation_statuses(self, data, user, method):
        pass

    def set_has_kpi_hooks(self):
        """
        Store results in self.asset._deployment_data
        """
        has_active_hooks = self.asset.has_active_hooks
        self.store_data({
            "has_kpi_hooks": has_active_hooks,
        })

    def calculated_submission_count(self, requesting_user_id, **kwargs):
        params = self.validate_submission_list_params(requesting_user_id,
                                                      validate_count=True,
                                                      **kwargs)
        instances = self.get_submissions(requesting_user_id, **params)
        return len(instances)
