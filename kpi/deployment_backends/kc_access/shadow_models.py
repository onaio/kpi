# coding: utf-8
from __future__ import (unicode_literals, print_function,
                        absolute_import, division)

from hashlib import md5

from django.conf import settings
from django.contrib.auth.models import User
try:
    from django.contrib.contenttypes.fields import GenericForeignKey
except ImportError:
    from django.contrib.contenttypes.generic import GenericForeignKey
from django.core.exceptions import ValidationError
from django.db import ProgrammingError
from django.db import models
from django.utils import timezone
from django.utils.six import text_type
from django.utils.translation import ugettext_lazy as _
from django.utils.encoding import python_2_unicode_compatible
from jsonfield import JSONField

from kpi.constants import SHADOW_MODEL_APP_LABEL
from kpi.utils.future import hashable_str


class ReadOnlyModelError(ValueError):
    pass


class ShadowModel(models.Model):
    """
    Allows identification of writeable and read-only shadow models
    """
    class Meta:
        managed = False
        abstract = True
        # TODO find out why it raises a warning when user logs in.
        # ```
        #   RuntimeWarning: Model '...' was already registered.
        #   Reloading models is not advised as it can lead to inconsistencies,
        #   most notably with related models
        # ```
        # Maybe because `SHADOW_MODEL_APP_LABEL` is not declared in `INSTALLED_APP`
        # It's just used for `DefaultDatabaseRouter` conditions.
        app_label = SHADOW_MODEL_APP_LABEL

    @staticmethod
    def get_content_type_for_model(model):
        model_name_mapping = {
            'readonlykobocatxform': ('logger', 'xform'),
            'readonlykobocatinstance': ('logger', 'instance'),
            'kobocatuserprofile': ('main', 'userprofile'),
            'kobocatuserobjectpermission': ('guardian', 'userobjectpermission'),
        }
        try:
            app_label, model_name = model_name_mapping[model._meta.model_name]
        except KeyError:
            raise NotImplementedError
        return KobocatContentType.objects.get(
            app_label=app_label, model=model_name)


class ReadOnlyModel(ShadowModel):

    class Meta(ShadowModel.Meta):
        abstract = True

    def save(self, *args, **kwargs):
        raise ReadOnlyModelError('Cannot save read-only-model')

    def delete(self, *args, **kwargs):
        raise ReadOnlyModelError('Cannot delete read-only-model')


class ReadOnlyKobocatXForm(ReadOnlyModel):

    class Meta(ReadOnlyModel.Meta):
        db_table = 'logger_xform'
        verbose_name = 'xform'
        verbose_name_plural = 'xforms'

    XFORM_TITLE_LENGTH = 255
    xls = models.FileField(null=True)
    xml = models.TextField()
    user = models.ForeignKey(User, related_name='xforms', null=True)
    shared = models.BooleanField(default=False)
    shared_data = models.BooleanField(default=False)
    downloadable = models.BooleanField(default=True)
    id_string = models.SlugField()
    title = models.CharField(max_length=XFORM_TITLE_LENGTH)
    date_created = models.DateTimeField()
    date_modified = models.DateTimeField()
    uuid = models.CharField(max_length=32, default='')
    last_submission_time = models.DateTimeField(blank=True, null=True)
    num_of_submissions = models.IntegerField(default=0)

    @property
    def hash(self):
        return '%s' % md5(hashable_str(self.xml)).hexdigest()

    @property
    def prefixed_hash(self):
        """
        Matches what's returned by the KC API
        """

        return "md5:%s" % self.hash


class ReadOnlyKobocatInstance(ReadOnlyModel):

    class Meta(ReadOnlyModel.Meta):
        db_table = 'logger_instance'
        verbose_name = 'instance'
        verbose_name_plural = 'instances'

    xml = models.TextField()
    user = models.ForeignKey(User, null=True)
    xform = models.ForeignKey(ReadOnlyKobocatXForm, related_name='instances')
    date_created = models.DateTimeField()
    date_modified = models.DateTimeField()
    deleted_at = models.DateTimeField(null=True, default=None)
    status = models.CharField(max_length=20,
                              default='submitted_via_web')
    uuid = models.CharField(max_length=249, default='')


class KobocatContentType(ShadowModel):
    """
    Minimal representation of Django 1.8's
    contrib.contenttypes.models.ContentType
    """
    app_label = models.CharField(max_length=100)
    model = models.CharField(_('python model class name'), max_length=100)

    class Meta(ShadowModel.Meta):
        db_table = 'django_content_type'
        unique_together = (('app_label', 'model'),)

    def __str__(self):
        # Not as nice as the original, which returns a human-readable name
        # complete with whitespace. That requires access to the Python model
        # class, though
        return self.model


@python_2_unicode_compatible
class KobocatPermission(ShadowModel):
    """
    Minimal representation of Django 1.8's contrib.auth.models.Permission
    """
    name = models.CharField(_('name'), max_length=255)
    content_type = models.ForeignKey(KobocatContentType)
    codename = models.CharField(_('codename'), max_length=100)

    class Meta(ShadowModel.Meta):
        db_table = 'auth_permission'
        unique_together = (('content_type', 'codename'),)
        ordering = ('content_type__app_label', 'content_type__model',
                    'codename')

    def __str__(self):
        return "%s | %s | %s" % (
            text_type(self.content_type.app_label),
            text_type(self.content_type),
            text_type(self.name))


class KobocatUser(ShadowModel):

    username = models.CharField(_("username"), max_length=30)
    password = models.CharField(_("password"), max_length=128)
    last_login = models.DateTimeField(_("last login"), blank=True, null=True)
    is_superuser = models.BooleanField(_('superuser status'), default=False)
    first_name = models.CharField(_('first name'), max_length=30, blank=True)
    last_name = models.CharField(_('last name'), max_length=150, blank=True)
    email = models.EmailField(_('email address'), blank=True)
    is_staff = models.BooleanField(_('staff status'), default=False)
    is_active = models.BooleanField(_('active'), default=True)
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)

    class Meta(ShadowModel.Meta):
        db_table = "auth_user"

    @classmethod
    def sync(cls, auth_user):
        # NB: `KobocatUserObjectPermission` (and probably other things) depend
        # upon PKs being synchronized between KPI and KoBoCAT
        try:
            kc_auth_user = cls.objects.get(pk=auth_user.pk)
            assert kc_auth_user.username == auth_user.username
        except KobocatUser.DoesNotExist:
            kc_auth_user = cls(pk=auth_user.pk, username=auth_user.username)

        kc_auth_user.password = auth_user.password
        kc_auth_user.last_login = auth_user.last_login
        kc_auth_user.is_superuser = auth_user.is_superuser
        kc_auth_user.first_name = auth_user.first_name
        kc_auth_user.last_name = auth_user.last_name
        kc_auth_user.email = auth_user.email
        kc_auth_user.is_staff = auth_user.is_staff
        kc_auth_user.is_active = auth_user.is_active
        kc_auth_user.date_joined = auth_user.date_joined

        kc_auth_user.save()


class KobocatUserObjectPermission(ShadowModel):
    """
    For the _sole purpose_ of letting us manipulate KoBoCAT
    permissions, this comprises the following django-guardian classes
    all condensed into one:

      * UserObjectPermission
      * UserObjectPermissionBase
      * BaseGenericObjectPermission
      * BaseObjectPermission

    CAVEAT LECTOR: The django-guardian custom manager,
    UserObjectPermissionManager, is NOT included!
    """
    permission = models.ForeignKey(KobocatPermission)
    content_type = models.ForeignKey(KobocatContentType)
    object_pk = models.CharField(_('object ID'), max_length=255)
    content_object = GenericForeignKey(fk_field='object_pk')
    # It's okay not to use `KobocatUser` as long as PKs are synchronized
    user = models.ForeignKey(
        getattr(settings, 'AUTH_USER_MODEL', 'auth.User'))

    class Meta(ShadowModel.Meta):
        db_table = 'guardian_userobjectpermission'
        unique_together = ['user', 'permission', 'object_pk']

    def __str__(self):
        # `unicode(self.content_object)` fails when the object's model
        # isn't known to this Django project. Let's use something more
        # benign instead.
        content_object_str = '{app_label}_{model} ({pk})'.format(
            app_label=self.content_type.app_label,
            model=self.content_type.model,
            pk=self.object_pk)
        return '%s | %s | %s' % (
            # unicode(self.content_object),
            content_object_str,
            text_type(getattr(self, 'user', False) or self.group),
            text_type(self.permission.codename))

    def save(self, *args, **kwargs):
        content_type = KobocatContentType.objects.get_for_model(
            self.content_object)
        if content_type != self.permission.content_type:
            raise ValidationError(
                "Cannot persist permission not designed for this "
                "class (permission's type is %r and object's type is "
                "%r)"
                % (self.permission.content_type, content_type)
            )
        return super(KobocatUserObjectPermission, self).save(*args, **kwargs)


class KobocatUserPermission(ShadowModel):
    """ Needed to assign model-level KoBoCAT permissions """
    user = models.ForeignKey('KobocatUser', db_column='user_id')
    permission = models.ForeignKey('KobocatPermission', db_column='permission_id')

    class Meta(ShadowModel.Meta):
        db_table = 'auth_user_user_permissions'


class KobocatUserProfile(ShadowModel):
    """
    From onadata/apps/main/models/user_profile.py
    Not read-only because we need write access to `require_auth`
    """
    class Meta(ShadowModel.Meta):
        db_table = 'main_userprofile'
        verbose_name = 'user profile'
        verbose_name_plural = 'user profiles'

    # This field is required.
    user = models.OneToOneField(KobocatUser, related_name='profile')

    # Other fields here
    name = models.CharField(max_length=255, blank=True)
    city = models.CharField(max_length=255, blank=True)
    country = models.CharField(max_length=2, blank=True)
    organization = models.CharField(max_length=255, blank=True)
    home_page = models.CharField(max_length=255, blank=True)
    twitter = models.CharField(max_length=255, blank=True)
    description = models.CharField(max_length=255, blank=True)
    require_auth = models.BooleanField(
        default=False,
        verbose_name=_(
            "Require authentication to see forms and submit data"
        )
    )
    address = models.CharField(max_length=255, blank=True)
    phonenumber = models.CharField(max_length=30, blank=True)
    created_by = models.ForeignKey(User, null=True, blank=True)
    num_of_submissions = models.IntegerField(default=0)
    metadata = JSONField(default={}, blank=True)


class KobocatToken(ShadowModel):

    key = models.CharField(_("Key"), max_length=40, primary_key=True)
    user = models.OneToOneField(KobocatUser,
                                related_name='auth_token',
                                on_delete=models.CASCADE, verbose_name=_("User"))
    created = models.DateTimeField(_("Created"), auto_now_add=True)

    class Meta(ShadowModel.Meta):
        db_table = "authtoken_token"

    @classmethod
    def sync(cls, auth_token):
        try:
            # Token use a One-to-One relationship on User.
            # Thus, we can retrieve tokens from users' id. 
            kc_auth_token = cls.objects.get(user_id=auth_token.user_id)
        except KobocatToken.DoesNotExist:
            kc_auth_token = cls(pk=auth_token.pk, user_id=auth_token.user_id)

        kc_auth_token.save()


class KobocatDigestPartial(ShadowModel):

    user = models.ForeignKey(KobocatUser, on_delete=models.CASCADE)
    login = models.CharField(max_length=128, db_index=True)
    partial_digest = models.CharField(max_length=100)
    confirmed = models.BooleanField(default=True)

    class Meta(ShadowModel.Meta):
        db_table = "django_digest_partialdigest"

    @classmethod
    def sync(cls, digest_partial, validate_user=True):
        """`
        Sync `django_digest_partialdigest` table between `kpi` and `kc``

        A race condition occurs when users are created.
        `DigestPartial` post-signal is (often) triggered before `User`
        post-signal.  Because of that, user doesn't exist in `kc` database
        when `KobocatDigestPartial` is saved.

        `validate_user` is useful to verify whether foreign key exists to avoid
        getting an `IntegrityError` on save.

        Args:
            digest_partial (DigestPartial)
            validate_user (bool)
        """
        try:
            if validate_user:
                # Race condition. `User` post signal can be triggered after
                # `DigestPartial` post signal.
                KobocatUser.objects.get(pk=digest_partial.user_id)

            try:
                kc_digest_partial = cls.objects.get(pk=digest_partial.pk)
                assert kc_digest_partial.user_id == digest_partial.user_id
            except KobocatDigestPartial.DoesNotExist:
                kc_digest_partial = cls(pk=digest_partial.pk,
                                        user_id=digest_partial.user_id)

            kc_digest_partial.login = digest_partial.login
            kc_digest_partial.partial_digest = digest_partial.partial_digest
            kc_digest_partial.confirmed = kc_digest_partial.confirmed
            kc_digest_partial.save()

        except KobocatUser.DoesNotExist:
            pass


def safe_kc_read(func):
    def _wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ProgrammingError as e:
            raise ProgrammingError('kc_access error accessing kobocat '
                                   'tables: {}'.format(e.message))
    return _wrapper
