# coding: utf-8
from __future__ import (unicode_literals, print_function,
                        absolute_import, division)

from kpi.constants import PERM_SHARE_SUBMISSIONS


class ObjectPermissionHelper(object):

    @staticmethod
    def user_can_share(affected_object, user_object, codename=''):
        """
        Return `True` if `user` is allowed to grant and revoke
        `codename` on `affected_object`. For `Collection`, this is always
        the same as checking that `user` has the
        `share_collection` permission on `affected_object`. For `Asset`,
        the result is determined by either `share_asset` or
        `share_submissions`, depending on the `codename`.

        :type affected_object: :py:class:Asset or :py:class:Collection
        :type user_object: auth.User
        :type codename: str
        :rtype bool
        """
        # affected_object can be deferred which doesn't return the expected
        # model_name. Using `concrete_model` does.
        model_name = affected_object._meta.concrete_model._meta.model_name
        if model_name == 'asset' and codename.endswith('_submissions'):
            share_permission = PERM_SHARE_SUBMISSIONS
        else:
            share_permission = 'share_{}'.format(model_name)
        return affected_object.has_perm(user_object, share_permission)

    @classmethod
    def get_assignments_queryset(cls, affected_object, user):

        # `affected_object.permissions` is a `GenericRelation(ObjectPermission)`
        # Don't Prefetch `content_object`.
        # See `AssetPermissionAssignmentSerializer.to_representation()`
        queryset = affected_object.permissions. \
            select_related('permission',
                           'user').all()

        # Filtering is done in `get_queryset` instead of FilteredBackend class
        # because it's specific to `ObjectPermission`.
        if not user or user.is_anonymous():
            queryset = queryset.filter(user_id=affected_object.owner_id)
        elif not cls.user_can_share(affected_object, user):
            # Display only users' permissions if they are not allowed to modify
            # others' permissions
            queryset = queryset.filter(user_id__in=[user.pk,
                                                    affected_object.owner_id])

        return queryset
