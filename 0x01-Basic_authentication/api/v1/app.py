#!/usr/bin/env python3
"""
Route module for the API
"""
import os
from os import getenv
from flask import Flask, jsonify, abort, request
from flask_cors import (CORS, cross_origin)
from api.v1.auth.auth import Auth
from api.v1.views import app_views
from api.v1.auth.basic_auth import BasicAuth

app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})

auth = None
auth_type = getenv('AUTH_TYPE', 'auth')

if auth_type == 'auth':
    auth = Auth()

if auth_type == 'basic_auth':
    auth = BasicAuth()


@app.before_request
def before_request():
    """
    Handle user authentication before resource access
    """
    if auth:
        paths = ['/api/v1/status/',
                 '/api/v1/unauthorized/',
                 '/api/v1/forbidden/']

        if auth.require_auth(request.path, paths):
            auth_header = auth.authorization_header(request)
            user = auth.current_user(request)
            if auth_header is None:
                abort(401)
            if user is None:
                abort(403)


@app.errorhandler(401)
def unauthorized(error) -> str:
    """
    Handle a case of unautorized access
    """
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(403)
def forbidden(error) -> str:
    """
    Handle forbidden
    """
    return jsonify({"error": "Forbidden"}), 403


@app.errorhandler(404)
def not_found(error) -> str:
    """
    Handle not found
    """
    return jsonify({"error": "Not found"}), 404


if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port)
