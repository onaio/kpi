# coding: utf-8
from .mock_backend import MockDeploymentBackend
from .ona_backend import OnaDeploymentBackend

DEPLOYMENT_BACKENDS = {
    "mock": MockDeploymentBackend,
    "kobocat": OnaDeploymentBackend,
}
