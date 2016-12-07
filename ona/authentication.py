import jwt
from django.conf import settings
from django.contrib.auth.models import User
from django.core.signing import BadSignature
from django.utils.translation import ugettext as _
from django.utils import timezone
from django.shortcuts import get_object_or_404
from rest_framework import exceptions
from rest_framework.authentication import (
    TokenAuthentication, get_authorization_header
)
from rest_framework.authtoken.models import Token
from ona.models import TempToken


JWT_SECRET_KEY = getattr(settings, 'JWT_SECRET_KEY', 'jwt')
JWT_ALGORITHM = getattr(settings, 'JWT_ALGORITHM', 'HS256')


def encode_payload(payload):
    encoded_payload = jwt.encode(
        payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM
    )

    return encoded_payload


def decode_payload(payload):
    decoded_payload = jwt.decode(
        payload, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM]
    )

    return decoded_payload


def expired(time_token_created):
    """Checks if the time between when time_token_created and current time
    is greater than the token expiry time.

    :params time_token_created: The time the token we are checking was created.
    :returns: Boolean True if not passed expired time, otherwise False.
    """
    temp_token_expiry_time = 21600  # 6 hours
    time_diff = (timezone.now() - time_token_created).total_seconds()
    token_expiry_time = temp_token_expiry_time

    return True if time_diff > token_expiry_time else False


def get_api_token(json_web_token):
    """Get API Token from JSON Web Token"""
    # having the JWT variables here allows the values to be mocked easily as
    # oppossed to being on the global scope. At the moment they are set
    # globally mainly because there isn't a test for it
    try:
        jwt_payload = decode_payload(json_web_token)
        api_token = get_object_or_404(Token, key=jwt_payload.get('api-token'))

        return api_token
    except BadSignature as e:
        raise exceptions.AuthenticationFailed(_(u'Bad Signature: %s' % e))
    except jwt.DecodeError as e:
        raise exceptions.AuthenticationFailed(_(u'JWT DecodeError: %s' % e))


class JWTAuthentication(TokenAuthentication):
    model = Token

    def authenticate(self, request):
        try:
            cookie_jwt = request.get_signed_cookie(
                '__enketo', salt=getattr(settings, 'ENKETO_API_SALT')
            )
            api_token = get_api_token(cookie_jwt)

            if getattr(api_token, 'user'):
                return api_token.user, api_token
        except self.model.DoesNotExist:
            raise exceptions.AuthenticationFailed(_(u'Invalid token'))
        except KeyError:
            pass
        except BadSignature:
            # if the cookie wasn't signed it means zebra might have
            # generated it
            cookie_jwt = request.COOKIES.get('__enketo')
            if cookie_jwt:
                api_token = get_api_token(cookie_jwt)
                if getattr(api_token, 'user'):
                    return api_token.user, api_token

                raise exceptions.ParseError(
                    _('Malformed cookie. Clear your cookies then try again'))

            raise exceptions.ParseError(_('Expected cookie not found'))

        return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None


class TempTokenAuthentication(TokenAuthentication):
    model = TempToken

    def authenticate(self, request):
        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != b'temptoken':
            return None

        if len(auth) == 1:
            m = _(u'Invalid token header. No credentials provided.')
            raise exceptions.AuthenticationFailed(m)
        elif len(auth) > 2:
            m = _(u'Invalid token header. '
                  'Token string should not contain spaces.')
            raise exceptions.AuthenticationFailed(m)

        return self.authenticate_credentials(auth[1])

    def authenticate_credentials(self, key):
        try:
            token = self.model.objects.get(key=key)
        except self.model.DoesNotExist:
            raise exceptions.AuthenticationFailed(_(u'Invalid token'))

        if not token.user.is_active:
            raise exceptions.AuthenticationFailed(
                _(u'User inactive or deleted'))

        if expired(token.created):
            raise exceptions.AuthenticationFailed(_(u'Token expired'))

        return (token.user, token)

    def authenticate_header(self, request):
        return 'TempToken'
