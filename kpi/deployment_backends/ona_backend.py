import requests

from rest_framework import status

from .kobocat_backend import KobocatDeploymentBackend
from ..exceptions import KobocatDeploymentException


class OnaDeploymentBackend(KobocatDeploymentBackend):
    """
    Ona deployment backend that extends KobocatDeploymentBackend.
    This class is used to interact with Ona's deployment system.
    """

    def _kobocat_request(self, method, url, **kwargs):
        """
        Make a POST or PATCH request and return parsed JSON. Keyword arguments,
        e.g. `data` and `files`, are passed through to `requests.request()`.
        """

        expected_status_codes = {
            "POST": 201,
            "PATCH": 200,
            "DELETE": 204,
        }
        try:
            expected_status_code = expected_status_codes[method]
        except KeyError:
            raise NotImplementedError(
                "This backend does not implement the {} method".format(method)
            )

        # Make the request to KC
        try:
            kc_request = requests.Request(method=method, url=url, **kwargs)
            response = self.__kobocat_proxy_request(kc_request, user=self.asset.owner)

        except requests.exceptions.RequestException as e:
            # Failed to access the KC API
            # TODO: clarify that the user cannot correct this
            raise KobocatDeploymentException(detail=str(e))

        # If it's a no-content success, return immediately
        if response.status_code == expected_status_code == 204:
            return {}

        # Parse the response
        try:
            json_response = response.json()
        except ValueError as e:
            # Unparseable KC API output
            # TODO: clarify that the user cannot correct this
            raise KobocatDeploymentException(detail=str(e), response=response)

        # Check for failure
        if response.status_code != expected_status_code:
            if "detail" in json_response:
                # KC API refused us for a specified reason, likely invalid
                # input Raise a 400 error that includes the reason
                e = KobocatDeploymentException(detail=json_response["detail"])
                e.status_code = status.HTTP_400_BAD_REQUEST
                raise e
            else:
                # Unspecified failure; raise 500
                raise KobocatDeploymentException(
                    detail="Unexpected KoBoCAT error {}: {}".format(
                        response.status_code, response.content
                    ),
                    response=response,
                )

        return json_response
