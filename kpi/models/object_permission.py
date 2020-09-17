# coding: utf-8
import copy
import re
from django.apps import apps
from django.conf import settings
from django.db import models, transaction
from django.shortcuts import _get_queryset
from django_request_cache import cache_for_request

from kpi.constants import PREFIX_PARTIAL_PERMS
from kpi.deployment_backends.kc_access.utils import (
    remove_applicable_kc_permissions,
    assign_applicable_kc_permissions
)
from kpi.fields.kpi_uid import KpiUidField
from kpi.utils.cache import void_cache_for_request


def perm_parse(perm, obj=None):
    if obj is not None:
        obj_app_label = ContentType.objects.get_for_model(obj).app_label
    else:
        obj_app_label = None
    try:
        app_label, codename = perm.split('.', 1)
        if obj_app_label is not None and app_label != obj_app_label:
            raise ValidationError('The given object does not belong to the app '
                                  'specified in the permission string.')
    except ValueError:
        app_label = obj_app_label
        codename = perm
    return app_label, codename

def get_models_with_object_permissions():
    """
    Return a list of all models that inherit from `ObjectPermissionMixin`
    """
    models = []
    for model in apps.get_models():
        if issubclass(model, ObjectPermissionMixin):
            models.append(model)
    return models

def get_all_objects_for_user(user, klass):
    """
    Return all objects of type klass to which user has been assigned any
    permission.
    """
    return klass.objects.filter(pk__in=ObjectPermission.objects.filter(
        user=user,
        content_type=ContentType.objects.get_for_model(klass)
    ).values_list('object_id', flat=True))


def get_objects_for_user(
    user,
    perms,
    klass=None,
    all_perms_required=True,
    intersect_pks_threshold=100,
):
    """
    A simplified version of django-guardian's get_objects_for_user shortcut.
    Returns queryset of objects for which a given ``user`` has *all*
    permissions present at ``perms``.
    :param user: ``User`` or ``AnonymousUser`` instance for which objects would
      be returned.
    :param perms: single permission string, or sequence of permission strings
      which should be checked.
      If ``klass`` parameter is not given, those should be full permission
      names rather than only codenames (i.e. ``auth.change_user``). If more than
      one permission is present within sequence, their content type **must** be
      the same or ``ValidationError`` exception will be raised.
    :param klass: may be a Model, Manager or QuerySet object. If not given
      this parameter will be computed based on given ``params``.
    :param all_perms_required: If False, users should have at least one
      of the `perms`
    :param intersect_pks_threshold: a kludge to deal with performance problems;
      see https://github.com/kobotoolbox/kpi/issues/2671. In short, if the
      number of items satisfying the permissions checks exceeds this threshold,
      intersect the PKs of those items with the PKs from the ``klass`` queryset
      before building an `__in` query. This EVALUATES the queryset and may
      worsen performance; if so, set to `False` to disable.
    """
    if isinstance(perms, str):
        perms = [perms]
    ctype = None
    app_label = None
    codenames = set()

    # Compute codenames set and ctype if possible
    for perm in perms:
        if '.' in perm:
            new_app_label, codename = perm.split('.', 1)
            if app_label is not None and app_label != new_app_label:
                raise ValidationError("Given perms must have same app "
                                      "label (%s != %s)" % (app_label,
                                                            new_app_label))
            else:
                app_label = new_app_label
        else:
            codename = perm
        codenames.add(codename)
        if app_label is not None:
            new_ctype = ContentType.objects.get(app_label=app_label,
                                                permission__codename=codename)
            if ctype is not None and ctype != new_ctype:
                raise ValidationError("Computed ContentTypes do not match "
                                      "(%s != %s)" % (ctype, new_ctype))
            else:
                ctype = new_ctype

    # Compute queryset and ctype if still missing
    if ctype is None and klass is None:
        raise ValidationError("Cannot determine content type")
    elif ctype is None and klass is not None:
        queryset = _get_queryset(klass)
        ctype = ContentType.objects.get_for_model(queryset.model)
    elif ctype is not None and klass is None:
        queryset = _get_queryset(ctype.model_class())
    else:
        queryset = _get_queryset(klass)
        if ctype.model_class() != queryset.model:
            raise ValidationError("Content type for given perms and "
                                  "klass differs")

    # At this point, we should have both ctype and queryset and they should
    # match which means: ctype.model_class() == queryset.model
    # we should also have ``codenames`` list

    # Check if the user is anonymous. The
    # django.contrib.auth.models.AnonymousUser object doesn't work for
    # queries, and it's nice to be able to pass in request.user blindly.
    if user.is_anonymous():
        user = get_anonymous_user()

    # Now we should extract list of pk values for which we would filter queryset
    user_obj_perms_queryset = (ObjectPermission.objects
        .filter(user=user)
        .filter(permission__content_type=ctype)
        .filter(permission__codename__in=codenames)
        .filter(deny=False))

    if len(codenames) > 1 and all_perms_required:
        counts = user_obj_perms_queryset.values('object_id').annotate(
            object_pk_count=models.Count('object_id'))
        user_obj_perms_queryset = counts.filter(object_pk_count__gte=len(codenames))

    values = user_obj_perms_queryset.values_list('object_id', flat=True)
    values = list(values)

    # Maybe there are 22,000+ objects that allow anonymous acess, but we're
    # only interested in the <200 that are part of discoverable collections;
    # see https://github.com/kobotoolbox/kpi/issues/2671.
    # Having to filter `ObjectPermission` and then use the resulting
    # `object_id`s in a `pk__in` query is awful, and we'll dispense with it
    # after `collection` becomes an `asset_type` and we ditch
    # `GenericForeignKey` permissions
    values_len = len(values)
    if (
        intersect_pks_threshold is not False
        and values_len > intersect_pks_threshold
    ):
        # It's not ideal to evaluate the queryset here, but we can't keep
        # passing around tens of thousands of IDs willy-nilly
        if queryset[:values_len].count() < values_len:
            useful_values = set(values).intersection(
                queryset.values_list('pk', flat=True)
            )
            return queryset.filter(pk__in=useful_values)

    return queryset.filter(pk__in=values)


@cache_for_request
def get_anonymous_user():
    """ Return a real User in the database to represent AnonymousUser. """
    try:
        user = User.objects.get(pk=settings.ANONYMOUS_USER_ID)
    except User.DoesNotExist:
        username = getattr(
            settings,
            'ANONYMOUS_DEFAULT_USERNAME_VALUE',
            'AnonymousUser'
        )
        user = User.objects.create(
            pk=settings.ANONYMOUS_USER_ID,
            username=username
        )
    return user


class ObjectPermissionManager(models.Manager):
    def _rewrite_query_args(self, method, content_object, **kwargs):
        """ Rewrite content_object into object_id and content_type, then pass
        those together with **kwargs to the given method. """
        content_type = ContentType.objects.get_for_model(content_object)
        kwargs['object_id'] = content_object.pk
        kwargs['content_type'] = content_type
        return method(**kwargs)

    def get_for_object(self, content_object, **kwargs):
        """ Wrapper to allow get() queries using a generic foreign key. """
        return self._rewrite_query_args(
            super().get, content_object, **kwargs)

    def filter(self, *args, **kwargs):
        return super().filter(*args, **kwargs)

    def filter_for_object(self, content_object, **kwargs):
        """ Wrapper to allow filter() queries using a generic foreign key. """
        return self._rewrite_query_args(
            super().filter, content_object, **kwargs)

    def get_or_create_for_object(self, content_object, **kwargs):
        """ Wrapper to allow get_or_create() calls using a generic foreign
        key. """
        return self._rewrite_query_args(
            super().get_or_create, content_object, **kwargs)


class ObjectPermission(models.Model):
    """ An application of an auth.Permission instance to a specific
    content_object. Call ObjectPermission.objects.get_for_object() or
    filter_for_object() to run queries using the content_object field. """
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    permission = models.ForeignKey('auth.Permission', on_delete=models.CASCADE)
    deny = models.BooleanField(
        default=False,
        help_text='Blocks inheritance of this permission when set to True'
    )
    inherited = models.BooleanField(default=False)
    object_id = models.PositiveIntegerField()
    # We can't do something like GenericForeignKey('permission__content_type'),
    # so duplicate the content_type field here.
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    content_object = GenericForeignKey('content_type', 'object_id')
    uid = KpiUidField(uid_prefix='p')
    objects = ObjectPermissionManager()

    @property
    def kind(self):
        return 'objectpermission'

    @property
    def label(self):
        return self.content_object.get_label_for_permission(self.permission)

    class Meta:
        unique_together = (
            'user', 'permission', 'deny', 'inherited',
            'object_id', 'content_type')

    @void_cache_for_request(keys=('__get_all_object_permissions',
                                  '__get_all_user_permissions',))
    def save(self, *args, **kwargs):
        if self.permission.content_type_id is not self.content_type_id:
            raise ValidationError('The content type of the permission does '
                                  'not match that of the object.')
        super().save(*args, **kwargs)

    @void_cache_for_request(keys=('__get_all_object_permissions',
                                  '__get_all_user_permissions',))
    def delete(self, *args, **kwargs):
        super().delete(*args, **kwargs)

    def __unicode__(self):
        for required_field in ('user', 'permission'):
            if not hasattr(self, required_field):
                return 'incomplete ObjectPermission'
        return '{}{} {} {}'.format(
            'inherited ' if self.inherited else '',
            str(self.permission.codename),  # TODO Test if cast is still needed
            'denied from' if self.deny else 'granted to',
            str(self.user)  # TODO Test if cast is still needed
        )


class ObjectPermissionMixin:
    """
    A mixin class that adds the methods necessary for object-level
    permissions to a model (either models.Model or MPTTModel). The model must
    define parent, ASSIGNABLE_PERMISSIONS, CALCULATED_PERMISSIONS, and, if
    parent references a different model, MAPPED_PARENT_PERMISSIONS. A
    post_delete signal receiver should also clean up any ObjectPermission
    records associated with the model instance.  The MRO is important, so be
    sure to include this mixin before the base class in your model definition,
    e.g.
        class MyAwesomeModel(ObjectPermissionMixin, models.Model)
    """

    CONTRADICTORY_PERMISSIONS = {}

    @classmethod
    def get_assignable_permissions(cls, with_partial=True):
        """
        The "versioned app registry" used during migrations apparently does
        not store non-database attributes, so this awful workaround is needed

        Returns assignable permissions including permissions prefixed by
        `PREFIX_PARTIAL_PERMS` if `with_partial` is True.

        It can be useful to remove the partial permissions when assigning
        permissions to owner of the object.

        :param with_partial: bool.
        :return: tuple
        """
        try:
            assignable_permissions = cls.ASSIGNABLE_PERMISSIONS
        except AttributeError:
            assignable_permissions = apps.get_model(
                cls._meta.app_label, cls._meta.model_name
            ).ASSIGNABLE_PERMISSIONS

        if with_partial is False:
            assignable_permissions = tuple(ap for ap in assignable_permissions
                                           if not ap.startswith(
                                               PREFIX_PARTIAL_PERMS)
                                           )

        return assignable_permissions

    @transaction.atomic
    def copy_permissions_from(self, source_object):
        """
        Copies permissions from `source_object` to `self` object.
        Both objects must have the same type.

        :param source_object: mixed (Asset, Collection)
        :return: Boolean
        """

        # We can only copy permissions between objects from the same type.
        if type(source_object) is type(self):
            # First delete all permissions of the target asset (except owner's).
            self.permissions.exclude(user_id=self.owner_id).delete()
            # Then copy all permissions from source to target asset
            source_permissions = list(source_object.permissions.all())
            for source_permission in source_permissions:
                # Only need to reassign permissions if user is not the owner
                if source_permission.user_id != self.owner_id:
                    kwargs = {
                        'user_obj': source_permission.user,
                        'perm': source_permission.permission.codename,
                        'deny': source_permission.deny
                    }
                    if source_permission.permission.codename.startswith(PREFIX_PARTIAL_PERMS):
                        kwargs.update({
                            'partial_perms': source_object.get_partial_perms(
                                source_permission.user_id, with_filters=True)
                        })
                    self.assign_perm(**kwargs)
            self._recalculate_inherited_perms()
            return True
        else:
            return False

    @transaction.atomic
    def save(self, *args, **kwargs):
        # Make sure we exist in the database before proceeding
        super().save(*args, **kwargs)
        # Recalculate self and all descendants, re-fetching ourself first to
        # guard against stale MPTT values
        fresh_self = type(self).objects.get(pk=self.pk)
        # TODO: Don't do this when the modification is trivial, e.g. a
        # collection was renamed
        fresh_self._recalculate_inherited_perms()
        fresh_self.recalculate_descendants_perms()

    def _filter_anonymous_perms(self, unfiltered_set):
        """
        Restrict a set of tuples in the format (user_id, permission_id) to
        only those permissions that apply to the content_type of this object
        and are listed in settings.ALLOWED_ANONYMOUS_PERMISSIONS.
        """
        content_type = ContentType.objects.get_for_model(self)
        # Translate settings.ALLOWED_ANONYMOUS_PERMISSIONS to primary keys
        codenames = set()
        for perm in settings.ALLOWED_ANONYMOUS_PERMISSIONS:
            app_label, codename = perm_parse(perm)
            if app_label == content_type.app_label:
                codenames.add(codename)
        allowed_permission_ids = Permission.objects.filter(
            content_type_id=content_type.pk, codename__in=codenames
        ).values_list('pk', flat=True)
        filtered_set = copy.copy(unfiltered_set)
        for user_id, permission_id in unfiltered_set:
            if user_id == settings.ANONYMOUS_USER_ID:
                if permission_id not in allowed_permission_ids:
                    filtered_set.remove((user_id, permission_id))
        return filtered_set

    def _get_effective_perms(
        self, user=None, codename=None, include_calculated=True
    ):
        """ Reconcile all grant and deny permissions, and return an
        authoritative set of grant permissions (i.e. deny=False) for the
        current object. """
        # Including calculated permissions means we can't just pass kwargs
        # through to filter(), but we'll map the ones we understand.
        kwargs = {}
        if user is not None:
            kwargs['user'] = user
        if codename is not None:
            # share_ requires loading change_ from the database
            if codename.startswith('share_'):
                kwargs['codename'] = re.sub(
                    '^share_', 'change_', codename, 1)
            else:
                kwargs['codename'] = codename

        grant_perms = self.__get_object_permissions(deny=False, **kwargs)
        deny_perms = self.__get_object_permissions(deny=True, **kwargs)

        effective_perms = grant_perms.difference(deny_perms)
        # Sometimes only the explicitly assigned permissions are wanted,
        # e.g. when calculating inherited permissions
        if not include_calculated:
            # Double-check that the list includes only permissions for
            # anonymous users that are allowed by the settings. Other
            # permissions would be denied by has_perm() anyway.
            if user is None or user.pk == settings.ANONYMOUS_USER_ID:
                return self._filter_anonymous_perms(effective_perms)
            else:
                # Anonymous users weren't considered; no filtering is necessary
                return effective_perms

        # Add on the calculated permissions
        content_type = ContentType.objects.get_for_model(self)
        if codename in self.CALCULATED_PERMISSIONS:
            # A specific query for a calculated permission should not return
            # any explicitly assigned permissions, e.g. share_ should not
            # include change_
            effective_perms_copy = effective_perms
            effective_perms = set()
        else:
            effective_perms_copy = copy.copy(effective_perms)
        if self.editors_can_change_permissions and (
                codename is None or codename.startswith('share_')
        ):
            # Everyone with change_ should also get share_
            change_permissions = self.__get_permissions_for_content_type(
                content_type.pk, codename__startswith='change_')

            for change_perm_pk, change_perm_codename in change_permissions:
                share_permission_codename = re.sub(
                    '^change_', 'share_', change_perm_codename, 1)
                if (codename is not None and
                        share_permission_codename != codename
                ):
                    # If the caller specified `codename`, skip anything that
                    # doesn't match exactly. Necessary because `Asset` has
                    # `*_submissions` in addition to `*_asset`
                    continue
                share_perm_pk, _ = self.__get_permissions_for_content_type(
                    content_type.pk,
                    codename=share_permission_codename)[0]
                for user_id, permission_id in effective_perms_copy:
                    if permission_id == change_perm_pk:
                        effective_perms.add((user_id, share_perm_pk))
        # The owner has the delete_ permission
        if self.owner is not None and (
                user is None or user.pk == self.owner.pk) and (
                codename is None or codename.startswith('delete_')
        ):
            delete_permissions = self.__get_permissions_for_content_type(
                content_type.pk, codename__startswith='delete_')
            for delete_perm_pk, delete_perm_codename in delete_permissions:
                if (codename is not None and
                        delete_perm_codename != codename
                ):
                    # If the caller specified `codename`, skip anything that
                    # doesn't match exactly. Necessary because `Asset` has
                    # `delete_submissions` in addition to `delete_asset`
                    continue
                effective_perms.add((self.owner.pk, delete_perm_pk))
        # We may have calculated more permissions for anonymous users
        # than they are allowed to have. Remove them.
        if user is None or user.pk == settings.ANONYMOUS_USER_ID:
            return self._filter_anonymous_perms(effective_perms)
        else:
            # Anonymous users weren't considered; no filtering is necessary
            return effective_perms

    def recalculate_descendants_perms(self):
        """ Recalculate the inherited permissions of all descendants. Expects
        either self.get_mixed_children() or self.get_children() to exist. The
        former will be used preferentially if it exists. """

        GET_CHILDREN_METHODS = ('get_mixed_children', 'get_children')
        can_have_children = False
        for method in GET_CHILDREN_METHODS:
            if hasattr(self, method):
                can_have_children = True
                break
        if not can_have_children:
            # It's impossible for us to have descendants. Move along...
            return

        # Any potential parents found will be appended to this list
        parents = [self]
        while True:
            try:
                parent = parents.pop()
            except IndexError:
                # No parents left; we're done!
                break
            # Get the effective permissions once per parent so that each child
            # does not have to query the database for the same information
            parent_effective_perms = parent._get_effective_perms(
                include_calculated=False)
            # Get all children, retrieving only the necessary fields from the
            # database. NB: `content` is particularly heavy
            for method in GET_CHILDREN_METHODS:
                if hasattr(parent, method):
                    break
            children = getattr(parent, method)().only(
                'pk', 'owner', 'parent')
            # Delete stale permissions once per parent, instead of per-child
            # TODO: Um, don't have two loops?
            delete_pks_by_content_type = {}
            for child in children:
                content_type = ContentType.objects.get_for_model(child).pk
                pk_list = delete_pks_by_content_type.get(content_type, [])
                pk_list.append(child.pk)
                delete_pks_by_content_type[content_type] = pk_list
            delete_query = models.Q()
            for content_type, pks in delete_pks_by_content_type.items():
                delete_query |= models.Q(
                    content_type=content_type,
                    object_id__in=pks
                )
            # filter(Q()) is like all(); make sure we don't delete with a query
            # like that just because there are no children!
            if len(delete_pks_by_content_type):
                # This doesn't run as a single DELETE query. For once, MySQL
                # wins? https://code.djangoproject.com/ticket/23576#comment:3
                # TODO: Verify this is faster than having children delete
                ObjectPermission.objects.filter(
                    delete_query, inherited=True).delete()
            # Process each child individually, but only write to the database
            # once per parent
            objects_to_create = []
            for child in children:
                for method in GET_CHILDREN_METHODS:
                    if hasattr(child, method):
                        # This child could have its own children; make sure we
                        # check it later
                        parents.append(child)
                        break
                # Recalculate the child's permissions
                new_permissions = child._recalculate_inherited_perms(
                    parent_effective_perms=parent_effective_perms,
                    stale_already_deleted=True,
                    return_instead_of_creating=True
                )
                objects_to_create += new_permissions
            ObjectPermission.objects.bulk_create(objects_to_create)

    def _recalculate_inherited_perms(
            self,
            parent_effective_perms=None,
            stale_already_deleted=False,
            return_instead_of_creating=False,
            translate_perm={}  # mutable default parameter serves as cache
    ):
        """
        Copy all of our parent's effective permissions to ourself,
        marking the copies as inherited permissions. The owner's rights are
        also made explicit as "inherited" permissions.
        """
        # Start with a clean slate
        if not stale_already_deleted:
            ObjectPermission.objects.filter_for_object(
                self,
                inherited=True
            ).delete()
        content_type = ContentType.objects.get_for_model(self)
        if return_instead_of_creating:
            # Conditionally create this so that Python will raise an exception
            # if we use it when we're not supposed to
            objects_to_return = []
        # The owner gets every assignable permission
        if self.owner is not None:
            for perm in Permission.objects.filter(
                content_type=content_type,
                codename__in=self.get_assignable_permissions(with_partial=False)
            ):
                new_permission = ObjectPermission()
                new_permission.content_object = self
                # `user_id` instead of `user` is another workaround for
                # migrations
                new_permission.user_id = self.owner_id
                new_permission.permission = perm
                new_permission.inherited = True
                new_permission.uid = new_permission._meta.get_field(
                    'uid').generate_uid()
                if return_instead_of_creating:
                    objects_to_return.append(new_permission)
                else:
                    new_permission.save()
        # Is there anything to inherit?
        if self.parent is not None:
            # Get our parent's effective permissions from the database if they
            # were not passed in as an argument
            if parent_effective_perms is None:
                parent_effective_perms = self.parent._get_effective_perms(
                    include_calculated=False)
            # All our parent's effective permissions become our inherited
            # permissions. Store translations in the translate_perm dictionary
            # to minimize invocations of the Django machinery
            for user_id, permission_id in parent_effective_perms:
                if user_id == self.owner_id:
                    # The owner already has every assignable permission
                    continue
                if hasattr(self, 'MAPPED_PARENT_PERMISSIONS'):
                    try:
                        translated_id = translate_perm[permission_id]
                    except KeyError:
                        parent_perm = Permission.objects.get(pk=permission_id)
                        try:
                            translated_codename = \
                                self.MAPPED_PARENT_PERMISSIONS[
                                    parent_perm.codename]
                        except KeyError:
                            # We haven't been configured to inherit this
                            # permission from our parent, so skip it
                            continue
                        translated_id = Permission.objects.get(
                            content_type__app_label=\
                                parent_perm.content_type.app_label,
                            codename=translated_codename
                        ).pk
                        translate_perm[permission_id] = translated_id
                    permission_id = translated_id
                elif content_type != ContentType.objects.get_for_model(
                        self.parent
                ):
                    raise ImproperlyConfigured(
                        'Parent of {} is a {}, but the child has not defined '
                        'MAPPED_PARENT_PERMISSIONS.'.format(
                            type(self), type(self.parent))
                    )
                new_permission = ObjectPermission()
                new_permission.content_object = self
                new_permission.user_id = user_id
                new_permission.permission_id = permission_id
                new_permission.inherited = True
                new_permission.uid = new_permission._meta.get_field(
                    'uid').generate_uid()
                if return_instead_of_creating:
                    objects_to_return.append(new_permission)
                else:
                    new_permission.save()
        if return_instead_of_creating:
            return objects_to_return

    @classmethod
    def get_implied_perms(cls, explicit_perm, reverse=False):
        """
        Determine which permissions are implied by `explicit_perm` based on
        the `IMPLIED_PERMISSIONS` attribute.
        :param explicit_perm: str. The `codename` of the explicitly-assigned
            permission.
        :param reverse: bool When `True`, exchange the keys and values of
            `IMPLIED_PERMISSIONS`. Useful for working with `deny=True`
            permissions. Defaults to `False`.
        :rtype: set of `codename`s
        """
        implied_perms_dict = getattr(cls, 'IMPLIED_PERMISSIONS', {})
        if reverse:
            reverse_perms_dict = defaultdict(list)
            for src_perm, dest_perms in implied_perms_dict.items():
                for dest_perm in dest_perms:
                    reverse_perms_dict[dest_perm].append(src_perm)
            implied_perms_dict = reverse_perms_dict

        perms_to_process = [explicit_perm]
        result = set()
        while perms_to_process:
            this_explicit_perm = perms_to_process.pop()
            try:
                implied_perms = implied_perms_dict[this_explicit_perm]
            except KeyError:
                continue
            if result.intersection(implied_perms):
                raise ImproperlyConfigured(
                    'Loop in IMPLIED_PERMISSIONS for {}'.format(cls))
            perms_to_process.extend(implied_perms)
            result.update(implied_perms)
        return result

    @classmethod
    def get_all_implied_perms(cls):
        """
        Return a dictionary with permission codenames as keys and a complete
        list of implied permissions as each value. For example, given a model
        with:
        ```
        IMPLIED_PERMISSIONS = {
            'view_submissions': ('view_asset'),
            'change_submissions': ('view_submissions'),
        }
        ```
        this method will return
        ```
        {
            'view_submissions': ['view_asset'],
            'change_submissions': ['view_asset', 'view_submission']
        }
        ```
        instead of
        ```
        {
            'view_submissions': ['view_asset'],
            'change_submissions': ['view_submissions']
        }
        ```
        """
        return {
            codename: list(cls.get_implied_perms(codename))
            for codename in cls.IMPLIED_PERMISSIONS.keys()
        }

    @transaction.atomic
    def assign_perm(self, user_obj, perm, deny=False, defer_recalc=False,
                    skip_kc=False, partial_perms=None):
        r"""
            Assign `user_obj` the given `perm` on this object, or break
            inheritance from a parent object. By default, recalculate
            descendant objects' permissions and apply any applicable KC
            permissions.
            :type user_obj: :py:class:`User` or :py:class:`AnonymousUser`
            :param perm: str. The `codename` of the `Permission`
            :param deny: bool. When `True`, break inheritance from parent object
            :param defer_recalc: bool. When `True`, skip recalculating
                descendants
            :param skip_kc: bool. When `True`, skip assignment of applicable KC
                permissions
            :param partial_perms: dict. Filters used to narrow down query for
              partial permissions
        """
        app_label, codename = perm_parse(perm, self)
        if codename not in self.get_assignable_permissions():
            # Some permissions are calculated and not stored in the database
            raise ValidationError(
                '{} cannot be assigned explicitly to {} objects.'.format(
                    codename, self._meta.model_name)
            )
        if isinstance(user_obj, AnonymousUser) or (
            user_obj.pk == settings.ANONYMOUS_USER_ID
        ):
            # Is an anonymous user allowed to have this permission?
            fq_permission = f'{app_label}.{codename}'
            if (
                not deny
                and fq_permission not in settings.ALLOWED_ANONYMOUS_PERMISSIONS
            ):
                raise ValidationError(
                    'Anonymous users cannot be granted the permission {}.'.format(
                        codename
                    )
                )
            # Get the User database representation for AnonymousUser
            user_obj = get_anonymous_user()
        perm_model = Permission.objects.get(
            content_type__app_label=app_label,
            codename=codename
        )
        existing_perms = ObjectPermission.objects.filter_for_object(
            self,
            user=user_obj,
        )
        identical_existing_perm = existing_perms.filter(
            inherited=False,
            permission_id=perm_model.pk,
            deny=deny,
        )
        if identical_existing_perm.exists():
            # We need to always update partial permissions because
            # they may have changed even if `perm` is the same.
            self._update_partial_permissions(user_obj.pk, perm,
                                             partial_perms=partial_perms)
            # The user already has this permission directly applied
            return identical_existing_perm.first()

        # Remove any explicitly-defined contradictory grants or denials
        contradictory_filters = models.Q(
            user=user_obj,
            permission_id=perm_model.pk,
            deny=not deny,
            inherited=False
        )
        if not deny and perm in self.CONTRADICTORY_PERMISSIONS.keys():
            contradictory_filters |= models.Q(
                user=user_obj,
                permission__codename__in=self.CONTRADICTORY_PERMISSIONS.get(perm),
            )
        contradictory_perms = existing_perms.filter(contradictory_filters)
        contradictory_codenames = list(contradictory_perms.values_list(
            'permission__codename', flat=True))

        contradictory_perms.delete()
        # Check if any KC permissions should be removed as well
        if deny and not skip_kc:
            remove_applicable_kc_permissions(
                self, user_obj, contradictory_codenames)
        # Create the new permission
        new_permission = ObjectPermission.objects.create(
            content_object=self,
            user=user_obj,
            permission_id=perm_model.pk,
            deny=deny,
            inherited=False
        )
        # Assign any applicable KC permissions
        if not deny and not skip_kc:
            assign_applicable_kc_permissions(self, user_obj, codename)
        # Resolve implied permissions, e.g. granting change implies granting
        # view
        implied_perms = self.get_implied_perms(codename, reverse=deny)
        for implied_perm in implied_perms:
            self.assign_perm(
                user_obj, implied_perm, deny=deny, defer_recalc=True)
        # We might have been called by ourself to assign a related
        # permission. In that case, don't recalculate here.
        if defer_recalc:
            return new_permission

        self._update_partial_permissions(user_obj.pk, perm,
                                         partial_perms=partial_perms)

        # Recalculate all descendants, re-fetching ourself first to guard
        # against stale MPTT values
        fresh_self = type(self).objects.get(pk=self.pk)
        fresh_self.recalculate_descendants_perms()
        return new_permission

    def get_perms(self, user_obj):
        """ Return a list of codenames of all effective grant permissions that
        user_obj has on this object. """
        user_perm_ids = self._get_effective_perms(user=user_obj)
        perm_ids = [x[1] for x in user_perm_ids]
        return Permission.objects.filter(pk__in=perm_ids).values_list(
            'codename', flat=True)

    def get_partial_perms(self, user_id, with_filters=False):
        """
        Returns the list of partial permissions related to the user.

        Should implemented on classes that inherit from this mixin
        """
        return []

    def get_filters_for_partial_perm(self, user_id, perm=None):
        """
        Returns the list of (Mongo) filters for a specific permission `perm`
        and this specific object.

        Should implemented on classes that inherit from this mixin
        """
        return None

    def get_users_with_perms(self, attach_perms=False):
        """ Return a QuerySet of all users with any effective grant permission
        on this object. If attach_perms=True, then return a dict with
        users as the keys and lists of their permissions as the values. """
        user_perm_ids = self._get_effective_perms()
        if attach_perms:
            user_perm_dict = {}
            for user_id, perm_id in user_perm_ids:
                perm_list = user_perm_dict.get(user_id, [])
                perm_list.append(Permission.objects.get(pk=perm_id).codename)
                user_perm_dict[user_id] = sorted(perm_list)
            # Resolve user ids into actual user objects
            user_perm_dict = {User.objects.get(pk=key): value for key, value
                              in user_perm_dict.items()}
            return user_perm_dict
        else:
            # Use a set to avoid duplicate users
            user_ids = {x[0] for x in user_perm_ids}
            return User.objects.filter(pk__in=user_ids)

    def has_perm(self, user_obj, perm):
        """ Does user_obj have perm on this object? (True/False) """
        app_label, codename = perm_parse(perm, self)
        is_anonymous = False
        if isinstance(user_obj, AnonymousUser):
            # Get the User database representation for AnonymousUser
            user_obj = get_anonymous_user()
        if user_obj.pk == settings.ANONYMOUS_USER_ID:
            is_anonymous = True
        # Treat superusers the way django.contrib.auth does
        if user_obj.is_active and user_obj.is_superuser:
            return True
        # Look for matching permissions
        result = len(self._get_effective_perms(
            user=user_obj,
            codename=codename
        )) == 1
        if not result and not is_anonymous:
            # The user-specific test failed, but does the public have access?
            result = self.has_perm(AnonymousUser(), perm)
        if result and is_anonymous:
            # Is an anonymous user allowed to have this permission?
            fq_permission = '{}.{}'.format(app_label, codename)
            if fq_permission not in settings.ALLOWED_ANONYMOUS_PERMISSIONS:
                return False
        return result

    @transaction.atomic
    def remove_perm(self, user_obj, perm, defer_recalc=False, skip_kc=False):
        r"""
            Revoke the given `perm` on this object from `user_obj`. By default,
            recalculate descendant objects' permissions and remove any
            applicable KC permissions.  May delete granted permissions or add
            deny permissions as appropriate:
            Current access      Action
            ==============      ======
            None                None
            Direct              Remove direct permission
            Inherited           Add deny permission
            Direct & Inherited  Remove direct permission; add deny permission
            :type user_obj: :py:class:`User` or :py:class:`AnonymousUser`
            :param perm str: The `codename` of the `Permission`
            :param defer_recalc bool: When `True`, skip recalculating
                descendants
            :param skip_kc bool: When `True`, skip assignment of applicable KC
                permissions
        """
        if isinstance(user_obj, AnonymousUser):
            # Get the User database representation for AnonymousUser
            user_obj = get_anonymous_user()
        app_label, codename = perm_parse(perm, self)
        if codename not in self.get_assignable_permissions():
            # Some permissions are calculated and not stored in the database
            raise ValidationError('{} cannot be removed explicitly.'.format(
                codename)
            )
        all_permissions = ObjectPermission.objects.filter_for_object(
            self,
            user=user_obj,
            permission__codename=codename,
            deny=False
        )
        direct_permissions = all_permissions.filter(inherited=False)
        inherited_permissions = all_permissions.filter(inherited=True)
        # Resolve implied permissions, e.g. revoking view implies revoking
        # change
        implied_perms = self.get_implied_perms(codename, reverse=True)
        for implied_perm in implied_perms:
            self.remove_perm(
                user_obj, implied_perm, defer_recalc=True)
        # Delete directly assigned permissions, if any
        direct_permissions.delete()
        if inherited_permissions.exists():
            # Delete inherited permissions
            inherited_permissions.delete()
            # Add a deny permission to block future inheritance
            self.assign_perm(user_obj, perm, deny=True, defer_recalc=True)
        # Remove any applicable KC permissions
        if not skip_kc:
            remove_applicable_kc_permissions(self, user_obj, codename)

        # We might have been called by ourself to assign a related
        # permission. In that case, don't recalculate here.
        if defer_recalc:
            return

        self._update_partial_permissions(user_obj.pk, perm, remove=True)
        # Recalculate all descendants, re-fetching ourself first to guard
        # against stale MPTT values
        fresh_self = type(self).objects.get(pk=self.pk)
        fresh_self.recalculate_descendants_perms()

    def _update_partial_permissions(self, user_id, perm, remove=False,
                                    partial_perms=None):
        # Class is not an abstract class. Just pass.
        # Let the dev implement within the classes that inherit from this mixin
        pass

    @staticmethod
    @cache_for_request
    def __get_all_object_permissions(content_type_id, object_id):
        """
        Retrieves all object permissions and builds an dict with user ids as keys.
        Useful to retrieve permissions for several users in a row without
        hitting DB again & again (thanks to `@cache_for_request`)

        Because `django_cache_request` creates its keys based on method's arguments,
        it's important to minimize its number to hit the cache as much as possible.
        This method should be called when object permissions for a specific object
        are needed several times in a row (within the same request).

        It will hit the DB once for this object. If object permissions are needed
        for an another user, in subsequent calls, they can be easily retrieved
        by the returned dict keys.

        Args:
            content_type_id (int): ContentType's pk
            object_id (int): Object's pk

        Returns:
            dict: {
                '<user_id>': [
                    (permission_id, permission_codename, deny),
                    (permission_id, permission_codename, deny),
                    ...
                ],
                '<user_id>': [
                    (permission_id, permission_codename, deny),
                    (permission_id, permission_codename, deny),
                    ...
                ]
            }
        """
        records = ObjectPermission.objects. \
            filter(content_type_id=content_type_id, object_id=object_id). \
            values('user_id',
                   'permission_id',
                   'permission__codename',
                   'deny')
        object_permissions_per_user = defaultdict(list)
        for record in records:
            object_permissions_per_user[record['user_id']].append((
                record['permission_id'],
                record['permission__codename'],
                record['deny'],
            ))

        return object_permissions_per_user

    @staticmethod
    @cache_for_request
    def __get_all_user_permissions(content_type_id, user_id):
        """
        Retrieves all object permissions and builds an dict with object ids as keys.
        Useful to retrieve permissions (thanks to `@cache_for_request`)
        for several objects in a row without fetching data from data again & again

        Because `django_cache_request` creates its keys based on method's arguments,
        it's important to minimize their number to hit the cache as much as possible.
        This method should be called when object permissions for a specific user
        are needed several times in a row (within the same request).

        It will hit the DB once for this user. If object permissions are needed
        for an another object (i.e. `Asset`, `Collection`), in subsequent calls,
        they can be easily retrieved by the returned dict keys.

        Args:
            content_type_id (int): ContentType's pk
            user_id (int): User's pk

        Returns:
            dict: {
                '<object_id>': [
                    (permission_id, permission_codename, deny),
                    (permission_id, permission_codename, deny),
                    ...
                ],
                '<object_id>': [
                    (permission_id, permission_codename, deny),
                    (permission_id, permission_codename, deny),
                    ...
                ]
            }
        """
        records = ObjectPermission.objects. \
            filter(content_type_id=content_type_id, user=user_id). \
            values('object_id',
                   'permission_id',
                   'permission__codename',
                   'deny')

        object_permissions_per_object = defaultdict(list)
        for record in records:
            object_permissions_per_object[record['object_id']].append((
                record['permission_id'],
                record['permission__codename'],
                record['deny'],
            ))

        return object_permissions_per_object

    def __get_object_permissions(self, deny, user=None, codename=None):
        """
        Returns a set of user ids and object permission ids related to
        object `self`.

        Args:
            deny (bool): If `True`, returns denied permissions
            user (User)
            codename (str)

        Returns:
            set: [(User's pk, Permission's pk)]
        """

        def build_dict(user_id_, object_permissions_):
            perms_ = []
            if object_permissions_:
                for permission_id, codename_, deny_ in object_permissions_:
                    if (deny_ is not deny or
                            codename is not None and
                            codename != codename_):
                        continue
                    perms_.append((user_id_, permission_id))
            return perms_

        perms = []
        object_content_type_id = ContentType.objects.get_for_model(self).pk
        # If User is not none, retrieve all permissions for this user
        # grouped by object ids, otherwise, retrieve all permissions for this object
        # grouped by user ids.
        if user is not None:
            user_id = user.pk if not user.is_anonymous() \
                else settings.ANONYMOUS_USER_ID
            all_object_permissions = self.__get_all_user_permissions(
                content_type_id=object_content_type_id,
                user_id=user_id)
            perms = build_dict(user_id, all_object_permissions.get(self.pk))

            if not perms:
                # Try AnonymousUser's permissions in case user does not have any.
                all_object_permissions = self.__get_all_user_permissions(
                    content_type_id=object_content_type_id,
                    user_id=settings.ANONYMOUS_USER_ID)
                perms = build_dict(user_id, all_object_permissions.get(self.pk))
        else:
            all_object_permissions = self.__get_all_object_permissions(
                content_type_id=object_content_type_id,
                object_id=self.pk)
            for user_id, object_permissions in all_object_permissions.items():
                perms += build_dict(user_id, object_permissions)

        return set(perms)

    @staticmethod
    @cache_for_request
    def __get_permissions_for_content_type(content_type_id,
                                           codename=None,
                                           codename__startswith=None):
        """
        Gets permissions for specific content type and permission's codename
        This method is cached per request because it can be called several times
        in a row in the same request.

        Args:
            content_type_id (int): ContentType primary key
            codename (str)
            codename__startswith (str)

        Returns:
            mixed: If `first` is `True` returns a tuple.
                   Otherwise a list of tuples
                   The tuple consists of permission's pk and its codename.
        """
        filters = {'content_type_id': content_type_id}
        if codename is not None:
            filters['codename'] = codename

        if codename__startswith is not None:
            filters['codename__startswith'] = codename__startswith

        permissions = Permission.objects.filter(**filters). \
            values_list('pk', 'codename')

        return permissions
