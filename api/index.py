"""
Vercel serverless entry point for the Flask application.
"""

from app import app

# Vercel's Python runtime exposes 'app' as the WSGI application
