# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import

from rest_framework import status, exceptions
from rest_framework.response import Response
from rest_framework.reverse import reverse

from kpi.models import ExportTask
from kpi.models.import_export_task import _resolve_url_to_asset_or_collection
from kpi.model_utils import remove_string_prefix
from kpi.serializers import ExportTaskSerializer
from kpi.tasks import export_in_background
from kpi.views.no_update_model import NoUpdateModelViewSet


class ExportTaskViewSet(NoUpdateModelViewSet):
    queryset = ExportTask.objects.all()
    serializer_class = ExportTaskSerializer
    lookup_field = 'uid'

    def get_queryset(self, *args, **kwargs):
        if self.request.user.is_anonymous():
            return ExportTask.objects.none()

        queryset = ExportTask.objects.filter(
            user=self.request.user).order_by('date_created')

        # Ultra-basic filtering by:
        # * source URL or UID if `q=source:[URL|UID]` was provided;
        # * comma-separated list of `ExportTask` UIDs if
        #   `q=uid__in:[UID],[UID],...` was provided
        q = self.request.query_params.get('q', False)
        if not q:
            # No filter requested
            return queryset
        if q.startswith('source:'):
            q = remove_string_prefix(q, 'source:')
            # This is exceedingly crude... but support for querying inside
            # JSONField not available until Django 1.9
            queryset = queryset.filter(data__contains=q)
        elif q.startswith('uid__in:'):
            q = remove_string_prefix(q, 'uid__in:')
            uids = [uid.strip() for uid in q.split(',')]
            queryset = queryset.filter(uid__in=uids)
        else:
            # Filter requested that we don't understand; make it obvious by
            # returning nothing
            return ExportTask.objects.none()
        return queryset

    def create(self, request, *args, **kwargs):
        if self.request.user.is_anonymous():
            raise exceptions.NotAuthenticated()

        # Read valid options from POST data
        valid_options = (
            'type',
            'source',
            'group_sep',
            'lang',
            'hierarchy_in_labels',
            'fields_from_all_versions',
        )
        task_data = {}
        for opt in valid_options:
            opt_val = request.POST.get(opt, None)
            if opt_val is not None:
                task_data[opt] = opt_val
        # Complain if no source was specified
        if not task_data.get('source', False):
            raise exceptions.ValidationError(
                {'source': 'This field is required.'})
        # Get the source object
        source_type, source = _resolve_url_to_asset_or_collection(
            task_data['source'])
        # Complain if it's not an Asset
        if source_type != 'asset':
            raise exceptions.ValidationError(
                {'source': 'This field must specify an asset.'})
        # Complain if it's not deployed
        if not source.has_deployment:
            raise exceptions.ValidationError(
                {'source': 'The specified asset must be deployed.'})
        # Create a new export task
        export_task = ExportTask.objects.create(user=request.user,
                                                data=task_data)
        # Have Celery run the export in the background
        export_in_background.delay(export_task_uid=export_task.uid)
        return Response({
            'uid': export_task.uid,
            'url': reverse(
                'exporttask-detail',
                kwargs={'uid': export_task.uid},
                request=request),
            'status': ExportTask.PROCESSING
        }, status.HTTP_201_CREATED)
