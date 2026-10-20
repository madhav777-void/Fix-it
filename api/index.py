"""
Vercel serverless entry point for the Flask application.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is in sys.path
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from app import app


class VercelPathMiddleware:
    """
    WSGI middleware that normalizes incoming PATH_INFO on Vercel.
    When Vercel rewrites / or /(.*) to /api/index, PATH_INFO can arrive as
    '/api/index' or '/api/index/...'. This strips the prefix so Flask routes match.
    """

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        path_info = environ.get("PATH_INFO", "")
        if path_info.startswith("/api/index"):
            rest = path_info[len("/api/index"):]
            environ["PATH_INFO"] = rest if rest.startswith("/") else ("/" + rest if rest else "/")
        elif path_info.startswith("/api"):
            rest = path_info[len("/api"):]
            environ["PATH_INFO"] = rest if rest.startswith("/") else ("/" + rest if rest else "/")

        return self.wsgi_app(environ, start_response)


# Apply middleware to app.wsgi_app
app.wsgi_app = VercelPathMiddleware(app.wsgi_app)
