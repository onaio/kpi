# coding: utf-8
import hashlib
from urllib.parse import urlencode

from kpi.utils.strings import hashable_str


from kpi.utils.future import hashable_str


def gravatar_url(email, https=True):
    return "%s://www.gravatar.com/avatar/%s?%s" % (
        'https' if https else 'http',
        hashlib.md5(hashable_str(email.lower())).hexdigest(),
<<<<<<< HEAD
        urlencode({'s': '40'}),
=======
        urllib.urlencode({'s': '40'}),
>>>>>>> - Updated PIP dependencies to use latest Formpack commit for Python 3
        )
