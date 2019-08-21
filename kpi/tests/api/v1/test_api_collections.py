# coding: utf-8
<<<<<<< HEAD
=======
from __future__ import (unicode_literals, print_function,
                        absolute_import, division)

>>>>>>> Added __future__ imports to all files
# importing module instead of the class, avoid running the tests twice
from kpi.tests.api.v2 import test_api_collections


class CollectionsTests(test_api_collections.CollectionsTests):

    URL_NAMESPACE = None
