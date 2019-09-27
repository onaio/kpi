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
        cookie_jwt = request.COOKIES.get(settings.KPI_COOKIE_NAME)
        if cookie_jwt:
            api_token = get_api_token(cookie_jwt)
            if getattr(api_token, 'user'):
                return api_token.user, api_token

            raise exceptions.ParseError(
                _('Malformed cookie. Clear your cookies then try again'))

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None