"""
WSGI config for secure_dock project.
"""

import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'secure_dock.settings')
application = get_wsgi_application()
