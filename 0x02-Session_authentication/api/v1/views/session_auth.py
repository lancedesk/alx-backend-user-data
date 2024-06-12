#!/usr/bin/env python3
"""
Session Authentication
"""
from os import getenv
from api.v1.views import app_views
from flask import abort, jsonify, request
from models.user import User


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login() -> str:
    """
    Sets user cookie
    """
    email = request.form.get('email')
    password = request.form.get('password')

    if email is None or email == '':
        return jsonify({"error": "email missing"}), 400

    if password is None or password == '':
        return jsonify({"error": "password missing"}), 400

    user = User.search({'email': email})
    if len(user) == 0:
        return jsonify({"error": "no user found for this email"}), 404

    user = user[0]
    if not user.is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401

    from api.v1.app import auth
    session_id = auth.create_session(user.id)
    session_name = getenv('SESSION_NAME')

    response = jsonify(user.to_json())
    response.set_cookie(session_name, session_id)
    return response


@app_views.route('/auth_session/logout',
                 methods=['DELETE'],
                 strict_slashes=False)
def logout() -> str:
    """
    Deletes user session
    """
    from api.v1.app import auth

    if auth.destroy_session(request) is False:
        abort(404)

    return jsonify({}), 200
