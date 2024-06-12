#!/usr/bin/env python3
"""
User session Authentication
"""
from uuid import uuid4

from api.v1.auth.auth import Auth
from models.user import User


class SessionAuth(Auth):
    """
    Authentication API
    """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """
        Create Session
        """
        if user_id is None or type(user_id) != str:
            return None

        session_id = str(uuid4())
        self.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        User ID
        """
        if session_id is None or type(session_id) != str:
            return None

        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        """
        Current user
        """
        session_cookie = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_cookie)
        return User.get(user_id)

    def destroy_session(self, request=None):
        """
        Deletes the user session
        """
        if request is None:
            return False

        session_cookie = self.session_cookie(request)
        if not session_cookie:
            return False

        user_id = self.user_id_for_session_id(session_cookie)
        if not user_id:
            return False

        del self.user_id_by_session_id[session_cookie]
        return True
