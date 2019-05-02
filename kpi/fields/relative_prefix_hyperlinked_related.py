<<<<<<< HEAD
# coding: utf-8
from urllib.parse import urlparse

from django.urls import get_script_prefix
from rest_framework.serializers import HyperlinkedRelatedField


class RelativePrefixHyperlinkedRelatedField(HyperlinkedRelatedField):

=======
# -*- coding: utf-8 -*-
from django.core.urlresolvers import get_script_prefix
from django.utils.six.moves.urllib import parse as urlparse
from rest_framework import serializers


class RelativePrefixHyperlinkedRelatedField(serializers.HyperlinkedRelatedField):
>>>>>>> WIP - refactored structure of serializers Fields
    def to_internal_value(self, data):
        try:
            http_prefix = data.startswith(('http:', 'https:'))
        except AttributeError:
            self.fail('incorrect_type', data_type=type(data).__name__)

        # The script prefix must be removed even if the URL is relative.
        # TODO: Figure out why DRF only strips absolute URLs, or file bug
        if True or http_prefix:
            # If needed convert absolute URLs to relative path
<<<<<<< HEAD
            data = urlparse(data).path
=======
            data = urlparse.urlparse(data).path
>>>>>>> WIP - refactored structure of serializers Fields
            prefix = get_script_prefix()
            if data.startswith(prefix):
                data = '/' + data[len(prefix):]

<<<<<<< HEAD
        return super().to_internal_value(data)
=======
        return super(
            RelativePrefixHyperlinkedRelatedField, self
        ).to_internal_value(data)
>>>>>>> WIP - refactored structure of serializers Fields
