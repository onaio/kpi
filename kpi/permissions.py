# coding: utf-8
from __future__ import (unicode_literals, print_function,
                        absolute_import, division)

from abc import ABCMeta, abstractmethod

from django.http import Http404
from rest_framework import exceptions, permissions
from six import add_metaclass

from kpi.models.asset import Asset
from kpi.models.collection import Collection
from kpi.models.object_permission import get_anonymous_user
from kpi.constants import PERM_PARTIAL_SUBMISSIONS


# FIXME: Move to `object_permissions` module.
def get_perm_name(perm_name_prefix, model_instance):
    """
    Get the type-specific permission name for a model from a permission name
    prefix and a model instance.

    Example:
        >>>get_perm_name('view', my_asset)
        'view_asset'

    :param perm_name_prefix: Prefix of the desired permission name (i.e.
        "view_", "change_", or "delete_").
    :type perm_name_prefix: str
    :param model_instance: An instance of the model for which the permission
        name is desired.
    :type model_instance: :py:class:`Collection` or :py:class:`Asset`
    :return: The computed permission name.
    :rtype: str
    """
    if not perm_name_prefix[-1] == '_':
        perm_name_prefix += '_'
    perm_name = perm_name_prefix + model_instance._meta.model_name
    return perm_name


@add_metaclass(ABCMeta)
class AbstractParentObjectNestedObjectPermission(permissions.BasePermission):
    """
    Main abstract class for Asset/Collection and related objects permissions
    Common methods are property are defined within this class.
    """

    @property
    def perms_map(self):
        raise NotImplementedError

    @abstractmethod
    def has_permission(self, request, view):
        # This method should be overridden in subclasses
        return False

    def has_object_permission(self, request, view, obj):
        # Because authentication checks have already executed via has_permission,
        # always return True.
        return True

    @classmethod
    def _get_parent_object(cls, view):
        """
        Returns parent object from the view (`Asset` or `Collection`)
        The view must have a property `asset` or `collection`
        It's easily done with `AssetNestedObjectViewsetMixin (kpi.utils.viewset_mixins.py)
        :param view: ViewSet
        :return: Asset/Collection
        """
        if cls.MODEL_NAME == 'collection':
            return cls._get_collection(view)
        else:
            return cls._get_asset(view)

    def _get_user_permissions(self, object_, user):
        """
        Returns a list of `user`'s permission for `asset`
        :param object_: Asset/Collection
        :param user: auth.User
        :return: list
        """
        return list(object_.get_perms(user))

    def get_required_permissions(self, method):
        """
        Given a model and an HTTP method, return the list of permission
        codes that the user is required to have.

        :param method: str. e.g. Mostly keys of `perms_map`
        :return:
        """
        app_label = self.APP_LABEL

        kwargs = {
            'app_label': app_label,
            'model_name': self.MODEL_NAME
        }

        try:
            perm_list = self.perms_map[method]
        except KeyError:
            raise exceptions.MethodNotAllowed(method)

        perms = [perm % kwargs for perm in perm_list]
        # Because `ObjectPermissionMixin.get_perms()` returns codenames only, remove the
        # `app_label` prefix before returning
        return [perm.replace("{}.".format(app_label), "") for perm in perms]


class BaseAssetNestedObjectPermission(AbstractParentObjectNestedObjectPermission):
    """
    Base class for Asset and related objects permissions
    """

    MODEL_NAME = Asset._meta.model_name
    APP_LABEL = Asset._meta.app_label

    @staticmethod
    def _get_asset(view):
        """
        Returns Asset from the view.
        The view must have a property `asset`.
        It's easily done with `AssetNestedObjectViewsetMixin (kpi.utils.viewset_mixins.py)
        :param view: ViewSet
        :return: Asset
        """
        return view.asset


class BaseCollectionNestedObjectPermission(AbstractParentObjectNestedObjectPermission):
    """
    Base class for Collection and related objects permissions
    """

    MODEL_NAME = Collection._meta.model_name
    APP_LABEL = Collection._meta.app_label

    @staticmethod
    def _get_collection(view):
        """
        Returns Collection from the view.
        The view must have a property `collection`.
        It's easily done with `CollectionNestedObjectViewsetMixin (kpi.utils.viewset_mixins.py)
        :param view: ViewSet
        :return: Collection
        """
        return view.collection


class AssetNestedObjectPermission(BaseAssetNestedObjectPermission):
    """
    Permissions for nested objects of Asset.
    Users need `*_asset` permissions to operate on these objects
    """

    perms_map = {
        'GET': ['%(app_label)s.view_asset'],
        'POST': ['%(app_label)s.change_asset'],
    }

    perms_map['OPTIONS'] = perms_map['GET']
    perms_map['HEAD'] = perms_map['GET']
    perms_map['PUT'] = perms_map['POST']
    perms_map['PATCH'] = perms_map['POST']
    perms_map['DELETE'] = perms_map['POST']

    def has_permission(self, request, view):
        if not request.user:
            return False
        elif request.user.is_superuser:
            return True

        parent_object = self._get_parent_object(view)

        user = request.user
        if user.is_anonymous():
            user = get_anonymous_user()

        user_permissions = self._get_user_permissions(parent_object, user)
        view_permissions = self.get_required_permissions("GET")
        can_view = set(view_permissions).issubset(user_permissions)

        try:
            required_permissions = self.get_required_permissions(request.method)
        except exceptions.MethodNotAllowed as e:
            # Only reveal the HTTP 405 if the user has view access
            if can_view:
                raise e
            else:
                raise Http404

        has_perm = set(required_permissions).issubset(user_permissions)

        if has_perm:
            # Access granted!
            return True

        if not has_perm and can_view:
            # If users are allowed to view, we want to show them HTTP 403
            return False

        # Don't reveal the existence of this object to users who do not have
        # permission to view it
        raise Http404


class AssetEditorNestedObjectPermission(AssetNestedObjectPermission):
    """
    Permissions for objects that are nested under Asset whose only users can
    change/edit.
    Others should receive a 404 response (instead of 403) to avoid revealing existence
    of objects.
    """

    required_permissions = ['%(app_label)s.change_asset',
                            '%(app_label)s.view_submissions']
    perms_map = {
        'GET': required_permissions,
        'POST': required_permissions,
        'PUT': required_permissions,
        'PATCH': required_permissions,
        'DELETE': required_permissions
    }


class CollectionNestedObjectPermission(BaseCollectionNestedObjectPermission,
                                       AssetNestedObjectPermission):
    """
    Permissions for nested objects of Collection.
    Users need `*_collection` permissions to operate on these objects
    """

    perms_map = {
        'GET': ['%(app_label)s.view_collection'],
        'POST': ['%(app_label)s.change_collection'],
    }

    perms_map['OPTIONS'] = perms_map['GET']
    perms_map['HEAD'] = perms_map['GET']
    perms_map['PUT'] = perms_map['POST']
    perms_map['PATCH'] = perms_map['POST']
    perms_map['DELETE'] = perms_map['POST']


# FIXME: Name is no longer accurate.
class IsOwnerOrReadOnly(permissions.DjangoObjectPermissions):
    """
    Custom permission to only allow owners of an object to edit it.
    """

    # Setting this to False allows real permission checking on AnonymousUser.
    # With the default of True, anonymous requests are categorically rejected.
    authenticated_users_only = False

    perms_map = permissions.DjangoObjectPermissions.perms_map
    perms_map['GET'] = ['%(app_label)s.view_%(model_name)s']
    perms_map['OPTIONS'] = perms_map['GET']
    perms_map['HEAD'] = perms_map['GET']


class PostMappedToChangePermission(IsOwnerOrReadOnly):
    """
    Maps POST requests to the change_model permission instead of DRF's default
    of add_model
    """
    perms_map = IsOwnerOrReadOnly.perms_map
    perms_map['POST'] = ['%(app_label)s.change_%(model_name)s']


class SubmissionPermission(AssetNestedObjectPermission):
    """
    Permissions for submissions.
    """

    MODEL_NAME = "submissions"  # Hardcode model_name to match permissions

    perms_map = {
        'GET': ['%(app_label)s.view_%(model_name)s'],
        'OPTIONS': ['%(app_label)s.view_%(model_name)s'],
        'HEAD': ['%(app_label)s.view_%(model_name)s'],
        'POST': ['%(app_label)s.add_%(model_name)s'],
        'PATCH': ['%(app_label)s.change_%(model_name)s'],
        'DELETE': ['%(app_label)s.change_%(model_name)s'],
    }

    def _get_user_permissions(self, asset, user):
        """
        Overrides parent method to include partial permissions (which are
        specific to submissions)

        :param asset: Asset
        :param user: auth.User
        :return: list
        """
        user_permissions = super(SubmissionPermission, self)._get_user_permissions(
            asset, user)

        if PERM_PARTIAL_SUBMISSIONS in user_permissions:
            # Merge partial permissions with permissions to find out if there
            # is a match within required permissions.
            # Restricted users will be narrowed down in MongoDB query.
            partial_perms = asset.get_partial_perms(user.id)
            if partial_perms:
                user_permissions = list(set(
                    user_permissions + partial_perms
                ))

        return user_permissions


class EditSubmissionPermission(SubmissionPermission):
    perms_map = {
        'GET': ['%(app_label)s.change_%(model_name)s'],
    }


class SubmissionValidationStatusPermission(SubmissionPermission):
    perms_map = {
        'GET': ['%(app_label)s.view_%(model_name)s'],
        'PATCH': ['%(app_label)s.validate_%(model_name)s'],
        'DELETE': ['%(app_label)s.validate_%(model_name)s'],
    }

