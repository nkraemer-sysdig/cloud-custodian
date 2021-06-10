# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
import logging

from c7n.actions import Action, BaseAction
from c7n.exceptions import PolicyValidationError
from c7n.filters import ValueFilter, Filter
from c7n.manager import resources
from c7n.tags import universal_augment
from c7n.query import ConfigSource, DescribeSource, QueryResourceManager, TypeInfo
from c7n.utils import local_session, type_schema

from .aws import shape_validate, Arn

log = logging.getLogger('c7n.resources.cloudtrail')


class DescribeTrail(DescribeSource):

    def augment(self, resources):
        return universal_augment(self.manager, resources)


class RegionClientMixin:
    """Mixin to group an array of trails by region, returning
       a map from region -> (client, set(trails))"""
    def __init__(self):
        pass

    def group_by_region(self, trails):
        grouped_trails = {}
        for t in trails:
            region = Arn.parse(t['TrailARN']).region

            if grouped_trails[region] is None:
                grouped_trails[region] = {}
                grouped_trails[region]["client"] = local_session(self.manager.session_factory).client('cloudtrail', region_name=region)
                grouped_trails[region]["trails"] = set()

            grouped_trails[region]["trails"].add(t)

        return grouped_trails


@resources.register('cloudtrail')
class CloudTrail(QueryResourceManager):

    class resource_type(TypeInfo):
        service = 'cloudtrail'
        enum_spec = ('describe_trails', 'trailList', None)
        filter_name = 'trailNameList'
        filter_type = 'list'
        arn_type = 'trail'
        arn = id = 'TrailARN'
        name = 'Name'
        cfn_type = config_type = "AWS::CloudTrail::Trail"
        universal_taggable = object()

    source_mapping = {
        'describe': DescribeTrail,
        'config': ConfigSource
    }


@CloudTrail.filter_registry.register('is-shadow')
class IsShadow(Filter):
    """Identify shadow trails (secondary copies), shadow trails
    can't be modified directly, the origin trail needs to be modified.

    Shadow trails are created for multi-region trails as well for
    organizational trails.
    """
    schema = type_schema('is-shadow', state={'type': 'boolean'})
    permissions = ('cloudtrail:DescribeTrails',)
    embedded = False

    def process(self, resources, event=None):
        rcount = len(resources)
        trails = [t for t in resources if (self.is_shadow(t) == self.data.get('state', True))]
        if len(trails) != rcount and self.embedded:
            self.log.info("implicitly filtering shadow trails %d -> %d",
                     rcount, len(trails))
        return trails

    def is_shadow(self, t):
        if t.get('IsOrganizationTrail') and self.manager.config.account_id not in t['TrailARN']:
            return True
        if t.get('IsMultiRegionTrail') and t['HomeRegion'] != self.manager.config.region:
            return True
        return False


@CloudTrail.filter_registry.register('status')
class Status(ValueFilter, RegionClientMixin):
    """Filter a cloudtrail by its status.

    :Example:

    .. code-block:: yaml

        policies:
          - name: cloudtrail-check-status
            resource: aws.cloudtrail
            filters:
            - type: status
              key: IsLogging
              value: False
    """

    schema = type_schema('status', rinherit=ValueFilter.schema)
    schema_alias = False
    permissions = ('cloudtrail:GetTrailStatus',)
    annotation_key = 'c7n:TrailStatus'

    def process(self, resources, event=None):
        grouped_trails = self.group_by_region(resources)
        non_account_trails = set()
        account_trails = set()

        for region in grouped_trails.items():
            client = region["client"]
            for t in region["trails"]:
                trail_arn = Arn.parse(t['TrailARN'])
                if (t.get('IsOrganizationTrail') and
                        self.manager.config.account_id != trail_arn.account_id):
                    non_account_trails.add(t['TrailARN'])
                    continue
                if self.annotation_key in t:
                    continue
                status = client.get_trail_status(Name=t['Name'])
                status.pop('ResponseMetadata')
                t[self.annotation_key] = status
                account_trails.add(t)

        if non_account_trails:
            self.log.warning(
                'found %d org cloud trail from different account that cant be processed',
                len(non_account_trails))
        return super(Status, self).process(account_trails)

    def __call__(self, r):
        return self.match(r['c7n:TrailStatus'])


@CloudTrail.filter_registry.register('event-selectors')
class EventSelectors(ValueFilter, RegionClientMixin):
    """Filter a cloudtrail by its related Event Selectors.

    :example:

    .. code-block:: yaml

      policies:
        - name: cloudtrail-event-selectors
          resource: aws.cloudtrail
          filters:
          - type: event-selectors
            key: EventSelectors[].IncludeManagementEvents
            op: contains
            value: True
    """

    schema = type_schema('event-selectors', rinherit=ValueFilter.schema)
    schema_alias = False
    permissions = ('cloudtrail:GetEventSelectors',)
    annotation_key = 'c7n:TrailEventSelectors'

    def process(self, resources, event=None):
        grouped_trails = self.group_by_region(resources)
        trails = set()

        for region in grouped_trails.items():
            client = region["client"]
            for t in region["trails"]:
                selectors = client.get_event_selectors(TrailName=t['TrailARN'])
                selectors.pop('ResponseMetadata')
                t[self.annotation_key] = selectors
                trails.add(t)

        return super(EventSelectors, self).process(trails)

    def __call__(self, r):
        return self.match(r['c7n:TrailEventSelectors'])


@CloudTrail.action_registry.register('update-trail')
class UpdateTrail(Action):
    """Update trail attributes.

    :Example:

    .. code-block:: yaml

       policies:
         - name: cloudtrail-set-log
           resource: aws.cloudtrail
           filters:
            - or:
              - KmsKeyId: empty
              - LogFileValidationEnabled: false
           actions:
            - type: update-trail
              attributes:
                KmsKeyId: arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef
                EnableLogFileValidation: true
    """
    schema = type_schema(
        'update-trail',
        attributes={'type': 'object'},
        required=('attributes',))
    shape = 'UpdateTrailRequest'
    permissions = ('cloudtrail:UpdateTrail',)

    def validate(self):
        attrs = dict(self.data['attributes'])
        if 'Name' in attrs:
            raise PolicyValidationError(
                "Can't include Name in update-trail action")
        attrs['Name'] = 'PolicyValidation'
        return shape_validate(
            attrs,
            self.shape,
            self.manager.resource_type.service)

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('cloudtrail')
        shadow_check = IsShadow({'state': False}, self.manager)
        shadow_check.embedded = True
        resources = shadow_check.process(resources)

        for r in resources:
            client.update_trail(
                Name=r['Name'],
                **self.data['attributes'])


@CloudTrail.action_registry.register('set-logging')
class SetLogging(Action):
    """Set the logging state of a trail

    :Example:

    .. code-block:: yaml

      policies:
        - name: cloudtrail-set-active
          resource: aws.cloudtrail
          filters:
           - type: status
             key: IsLogging
             value: False
          actions:
           - type: set-logging
             enabled: True
    """
    schema = type_schema(
        'set-logging', enabled={'type': 'boolean'})

    def get_permissions(self):
        enable = self.data.get('enabled', True)
        if enable is True:
            return ('cloudtrail:StartLogging',)
        else:
            return ('cloudtrail:StopLogging',)

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('cloudtrail')
        shadow_check = IsShadow({'state': False}, self.manager)
        shadow_check.embedded = True
        resources = shadow_check.process(resources)
        enable = self.data.get('enabled', True)

        for r in resources:
            if enable:
                client.start_logging(Name=r['Name'])
            else:
                client.stop_logging(Name=r['Name'])


@CloudTrail.action_registry.register('delete')
class DeleteTrail(BaseAction):
    """ Delete a cloud trail

    :example:

    .. code-block:: yaml

      policies:
        - name: delete-cloudtrail
          resource: aws.cloudtrail
          filters:
           - type: value
             key: Name
             value: delete-me
             op: eq
          actions:
           - type: delete
    """

    schema = type_schema('delete')
    permissions = ('cloudtrail:DeleteTrail',)

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('cloudtrail')
        shadow_check = IsShadow({'state': False}, self.manager)
        shadow_check.embedded = True
        resources = shadow_check.process(resources)
        for r in resources:
            try:
                client.delete_trail(Name=r['Name'])
            except client.exceptions.TrailNotFoundException:
                continue
