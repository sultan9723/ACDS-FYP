"""
API Routes Package
==================
Contains all API route modules for the ACDS backend.
"""

from . import auth
from . import threats
from . import dashboard
from . import feedback
from . import reports
from . import testing
from . import demo

__all__ = ['auth', 'threats', 'dashboard', 'feedback', 'reports', 'testing', 'demo']
