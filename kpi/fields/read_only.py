<<<<<<< HEAD
# coding: utf-8
=======
# -*- coding: utf-8 -*-

>>>>>>> WIP - refactored structure of serializers Fields
from rest_framework import serializers


class ReadOnlyJSONField(serializers.ReadOnlyField):
    def to_representation(self, value):
        return value
