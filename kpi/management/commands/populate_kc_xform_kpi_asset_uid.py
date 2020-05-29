# -*- coding: utf-8 -*-
import sys

from django.core.management.base import BaseCommand

from kpi.exceptions import KobocatDeploymentException
from kpi.models.asset import Asset


class Command(BaseCommand):

    help = 'Link KoBoCAT `XForm`s back to their corresponding KPI `Asset`s ' \
           'by populating the `kpi_asset_uid` field'

    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument(
            '--rest-service-only',
            action='store_true',
            default=False,
            help='Modify only `XForm`s whose corresponding `Asset`s have ' \
                 '`Hook`s (REST Services) enabled'
        )

        parser.add_argument(
            '--force',
            action='store_true',
            default=False,
            help='Rewrite `XForm.kpi_asset_uid` even if it already has a value'
        )

        parser.add_argument(
            '--username',
            action='store',
            dest='username',
            default=False,
            help='Only modify `XForm`s whose corresponding `Asset`s belong ' \
                 'to a specific user'
        )

        parser.add_argument(
            "--chunks",
            default=1000,
            type=int,
            help="Update records by batch of `chunks`.",
        )

    def handle(self, *args, **options):

        force = options['force']
        chunks = options["chunks"]
        verbosity = options['verbosity']
        rest_service_only = options['rest_service_only']
        username = options['username']

        # Counters
        cpt = 0
        cpt_already_populated = 0
        cpt_failed = 0
        cpt_patched = 0
        cpt_no_deployments = 0

        # Filter query
        query = Asset.objects
        if rest_service_only:
            query = query.exclude(hooks=None)
        if username:
            query = query.filter(owner__username=username)

        total = query.count()

        # Use only fields we need.
        assets = query.only('id', 'uid', '_deployment_data', 'name',
                            'parent_id', 'owner_id')

        for asset in assets.iterator(chunk_size=chunks):
            if asset.has_deployment:
                try:
                    if asset.deployment.set_asset_uid(force=force):
                        if verbosity >= 2:
                            self.stdout.write('\nAsset #{}: Patching XForm'.format(asset.id))
                        # Avoid `Asset.save()` logic. Do not touch `modified_date`
                        Asset.objects.filter(pk=asset.id).update(
                            _deployment_data=asset._deployment_data)
                        cpt_patched += 1
                    else:
                        if verbosity >= 2:
                            self.stdout.write('\nAsset #{}: Already populated'.format(asset.id))
                        cpt_already_populated += 1
                except KobocatDeploymentException as e:
                    if verbosity >= 2:
                        self.stdout.write('\nERROR: Asset #{}: {}'.format(asset.id,
                                                                          str(e)))
                    cpt_failed += 1
            else:
                if verbosity >= 3:
                    self.stdout.write('\nAsset #{}: No deployments found'.format(asset.id))
                cpt_no_deployments += 1

            cpt += 1
            if verbosity >= 1:
                progress = '\rUpdated {cpt}/{total} records...'.format(
                    cpt=cpt,
                    total=total
                )
                self.stdout.write(progress)
                self.stdout.flush()

        self.stdout.write('\nSummary:')
        self.stdout.write(f'Successfully populated: {cpt_patched}')
        self.stdout.write(f'Failures: {cpt_failed}')
        self.stdout.write(f'No deployments found: {cpt_no_deployments}')
        if not force:
            self.stdout.write(f'Already populated: {cpt_already_populated}')
