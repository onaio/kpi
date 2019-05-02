<<<<<<< HEAD
# coding: utf-8
=======
# -*- coding: utf-8 -*-
>>>>>>> WIP - refactored structure of serializers Fields
import json

from rest_framework import serializers


class WritableJSONField(serializers.Field):
    """
    Serializer for JSONField -- required to make field writable
    """

    def __init__(self, **kwargs):
        self.allow_blank = kwargs.pop('allow_blank', False)
<<<<<<< HEAD
        super().__init__(**kwargs)
=======
        super(WritableJSONField, self).__init__(**kwargs)
>>>>>>> WIP - refactored structure of serializers Fields

    def to_internal_value(self, data):
        if (not data) and (not self.required):
            return None
        else:
            try:
                return json.loads(data)
            except Exception as e:
                raise serializers.ValidationError(
<<<<<<< HEAD
                    'Unable to parse JSON: {}'.format(e))
=======
                    u'Unable to parse JSON: {}'.format(e))
>>>>>>> WIP - refactored structure of serializers Fields

    def to_representation(self, value):
        return value
