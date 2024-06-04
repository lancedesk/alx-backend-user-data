#!/usr/bin/env python3
"""
Route module for the API
"""
import os
from os import getenv

from api.v1.views import app_views
from flask_cors import CORS, cross_origin
from flask import Flask, abort, jsonify, request


app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})

auth = None

"""
Check AUTH_TYPE
"""
if getenv('AUTH_TYPE') == 'auth':
    from api.v1.auth.auth import Auth
    auth = Auth()
elif getenv('AUTH_TYPE') == 'basic_auth':
    from api.v1.auth.basic_auth import BasicAuth
    auth = BasicAuth()


@app.errorhandler(404)
def not_found(error) -> str:
    """
    Handle not found
    """
    return jsonify({"error": "Not found"}), 404


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


@app.before_request
def before_request():
    """
    Handle user authentication before resource access
    """
    if auth is None:
        return
    if auth.require_auth(
            path=request.path,
            exclude_paths=[
                '/api/v1/status/',
                '/api/v1/unauthorized/',
                '/api/v1/forbidden/',
            ],
    ):
        if auth.authorization_header(request) is None:
            abort(401)
        if auth.current_user(request) is None:
            abort(403)


if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port)
