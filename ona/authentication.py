import jwt
from django.conf import settings
from django.contrib.auth.models import User
from django.core.signing import BadSignature
from django.utils.translation import ugettext as _
from rest_framework import exceptions
from rest_framework.authentication import (
    BaseAuthentication
)
from rest_framework.authtoken.models import Token
from kpi.utils.permissions import grant_default_model_level_perms


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
        try:
            api_token = Token.objects.using(
                "kobocat").select_related('user').get(
                    key=jwt_payload.get('api-token'))
        except Token.DoesNotExist:
            raise exceptions.AuthenticationFailed(
                f'No Token retrieved.')

        return api_token
    except BadSignature as e:
        raise exceptions.AuthenticationFailed(_(f'Bad Signature: {e}'))
    except jwt.DecodeError as e:
        raise exceptions.AuthenticationFailed(_(f'JWT DecodeError: {e}'))


class JWTAuthentication(BaseAuthentication):
    model = Token

    def authenticate(self, request):
        cookie_jwt = request.COOKIES.get(settings.KPI_COOKIE_NAME)

        if not cookie_jwt:
            return None

        api_token = get_api_token(cookie_jwt)

        # Create KPI User from Onadata user username and email
        user, created = User.objects.using('default').get_or_create(
            username=api_token.user.username,
            email=api_token.user.email
            )
        if created:
            grant_default_model_level_perms(user)
        return (user, None)
