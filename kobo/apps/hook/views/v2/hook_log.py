<<<<<<< HEAD
# coding: utf-8
from django.utils.translation import ugettext as _
from rest_framework import viewsets, mixins, status
from rest_framework.decorators import action
=======
# -*- coding: utf-8 -*-
from __future__ import absolute_import

from django.utils.translation import ugettext as _
from rest_framework import viewsets, mixins, status
from rest_framework.decorators import detail_route
>>>>>>> Make Hook app work with v1 & v2
from rest_framework.response import Response
from rest_framework_extensions.mixins import NestedViewSetMixin

from kobo.apps.hook.constants import KOBO_INTERNAL_ERROR_STATUS_CODE
from kobo.apps.hook.models.hook_log import HookLog
from kobo.apps.hook.serializers.v2.hook_log import HookLogSerializer
<<<<<<< HEAD
from kpi.paginators import TinyPaginated
from kpi.permissions import AssetEditorSubmissionViewerPermission
from kpi.utils.viewset_mixins import AssetNestedObjectViewsetMixin


class HookLogViewSet(AssetNestedObjectViewsetMixin,
                     NestedViewSetMixin,
=======
from kpi.filters import AssetOwnerFilterBackend
from kpi.paginators import TinyPaginated
from kpi.permissions import AssetOwnerNestedObjectPermission


class HookLogViewSet(NestedViewSetMixin,
>>>>>>> Make Hook app work with v1 & v2
                     mixins.RetrieveModelMixin,
                     mixins.ListModelMixin,
                     viewsets.GenericViewSet):
    """
    ## Logs of an external service

    ** Users can't add, update or delete logs with the API. They can only retry failed attempts (see below)**

    #### Lists logs of an external services endpoints accessible to requesting user
    <pre class="prettyprint">
<<<<<<< HEAD
    <b>GET</b> /api/v2/assets/{asset_uid}/hooks/{hook_uid}/logs/
=======
    <b>GET</b> /assets/{asset_uid}/hooks/{hook_uid}/logs/
>>>>>>> Make Hook app work with v1 & v2
    </pre>

    > Example
    >
<<<<<<< HEAD
    >       curl -X GET https://[kpi-url]/api/v2/assets/a9PkXcgVgaDXuwayVeAuY5/hooks/hSBxsiVNa5UxkVAjwu6dFB/logs/
=======
    >       curl -X GET https://[kpi-url]/assets/a9PkXcgVgaDXuwayVeAuY5/hooks/hSBxsiVNa5UxkVAjwu6dFB/logs/
>>>>>>> Make Hook app work with v1 & v2



    * `asset_uid` - is the unique identifier of a specific asset
    * `hook_uid` - is the unique identifier of a specific external service
    * `uid` - is the unique identifier of a specific log

    #### Retrieves a log
    <pre class="prettyprint">
<<<<<<< HEAD
    <b>GET</b> /api/v2/assets/<code>{asset_uid}</code>/hooks/<code>{hook_uid}</code>/logs/<code>{uid}</code>/
=======
    <b>GET</b> /assets/<code>{asset_uid}</code>/hooks/<code>{hook_uid}</code>/logs/<code>{uid}</code>/
>>>>>>> Make Hook app work with v1 & v2
    </pre>


    > Example
    >
<<<<<<< HEAD
    >       curl -X GET https://[kpi-url]/api/v2/assets/a9PkXcgVgaDXuwayVeAuY5/hooks/hfgha2nxBdoTVcwohdYNzb/logs/3005940a-6e30-4699-813a-0ee5b2b07395/
=======
    >       curl -X GET https://[kpi-url]/assets/a9PkXcgVgaDXuwayVeAuY5/hooks/hfgha2nxBdoTVcwohdYNzb/logs/3005940a-6e30-4699-813a-0ee5b2b07395/
>>>>>>> Make Hook app work with v1 & v2


    #### Retries a failed attempt
    <pre class="prettyprint">
<<<<<<< HEAD
    <b>PATCH</b> /api/v2/assets/<code>{asset_uid}</code>/hooks/<code>{hook_uid}</code>/logs/<code>{uid}</code>/retry/
=======
    <b>PATCH</b> /assets/<code>{asset_uid}</code>/hooks/<code>{hook_uid}</code>/logs/<code>{uid}</code>/retry/
>>>>>>> Make Hook app work with v1 & v2
    </pre>

    > Example
    >
<<<<<<< HEAD
    >       curl -X GET https://[kpi-url]/api/v2/assets/a9PkXcgVgaDXuwayVeAuY5/hooks/hfgha2nxBdoTVcwohdYNzb/logs/3005940a-6e30-4699-813a-0ee5b2b07395/retry/
=======
    >       curl -X GET https://[kpi-url]/assets/a9PkXcgVgaDXuwayVeAuY5/hooks/hfgha2nxBdoTVcwohdYNzb/logs/3005940a-6e30-4699-813a-0ee5b2b07395/retry/
>>>>>>> Make Hook app work with v1 & v2


    ### CURRENT ENDPOINT
    """

    URL_NAMESPACE = 'api_v2'

    model = HookLog

    lookup_field = "uid"
    serializer_class = HookLogSerializer
    permission_classes = (AssetEditorSubmissionViewerPermission,)
    pagination_class = TinyPaginated

    def get_queryset(self):
        hook_uid = self.get_parents_query_dict().get("hook")
        queryset = self.model.objects.filter(hook__uid=hook_uid,
                                             hook__asset__uid=self.asset_uid)
        queryset = queryset.select_related("hook__asset__uid")

        return queryset

    @action(detail=True, methods=["PATCH"])
    def retry(self, request, uid=None, *args, **kwargs):
        """
        Retries to send data to external service.
        :param request: rest_framework.request.Request
        :param uid: str
        :return: Response
        """
        response = {"detail": "",
                    "status_code": KOBO_INTERNAL_ERROR_STATUS_CODE}
        status_code = status.HTTP_200_OK
        hook_log = self.get_object()

        if hook_log.can_retry():
            hook_log.change_status()
            success = hook_log.retry()
            if success:
                # Return status_code of remote server too.
                # `response["status_code"]` is not the same as `status_code`
                response["detail"] = hook_log.message
                response["status_code"] = hook_log.status_code
            else:
                response["detail"] = _("An error has occurred when sending the data. Please try again later.")
                status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        else:
            response["detail"] = _("Data is being or has already been processed")
            status_code = status.HTTP_400_BAD_REQUEST

        return Response(response, status=status_code)
