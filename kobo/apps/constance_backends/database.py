import logging

from django_redis.exceptions import ConnectionInterrupted
from constance.backends.database import DatabaseBackend as BaseDatabaseBackend

logger = logging.getLogger(__name__)


class DatabaseBackend(BaseDatabaseBackend):
    """
    Fix for https://github.com/jazzband/django-constance/issues/348
    Overrides the `get` method to remove silencing of database failures.
    Such errors would otherwise result in unwanted resetting of parameters
    to default values.

    Cache connection errors (e.g. Redis going away) are caught separately
    so that the backend can fall back to the database rather than crashing
    the request.  Database errors still propagate as before.
    """

    def _safe_cache_get(self, key):
        """
        Attempt to read from cache.  Return `None` on connection failure
        so the caller falls through to the database.
        """
        try:
            return self._cache.get(key)
        except ConnectionInterrupted:
            logger.warning(
                'constance cache read failed for key %s, '
                'falling back to database',
                key,
            )
            return None

    def get(self, key):
        key = self.add_prefix(key)
        if self._cache:
            value = self._safe_cache_get(key)
            if value is None:
                self.autofill()
                value = self._safe_cache_get(key)
        else:
            value = None
        if value is None:
            try:
                value = self._model._default_manager.get(key=key).value
            except self._model.DoesNotExist:
                pass
            else:
                if self._cache:
                    try:
                        self._cache.add(key, value)
                    except ConnectionInterrupted:
                        logger.warning(
                            'constance cache write failed for key %s',
                            key,
                        )
        return value
