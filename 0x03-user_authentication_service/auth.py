#!/usr/bin/env python3
"""
User Authentication Module
"""
from uuid import uuid4

import bcrypt
from db import DB
from sqlalchemy.orm.exc import NoResultFound
from user import User


def _hash_password(password: str) -> bytes:
    """Hash a password with a salt using bcrypt.

    Args:
        password (str): The password to hash.

    Returns:
        bytes: The salted hash of the password.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def _generate_uuid() -> str:
    """
    Generate an UUID
    """
    return str(uuid4())


class Auth:
    """
    Auth class to interact with the database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Register a new user.

        Args:
            email (str): The user's email address.
            password (str): The user's password.

        Returns:
            User: The registered user.

        Raises:
            ValueError: If the user already exists.
        """
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))

    def valid_login(self, email: str, password: str) -> bool:
        """Check if a login is valid.

        Args:
            email (str): The user's email address.
            password (str): The user's password.

        Returns:
            bool: True if the login is valid, False otherwise.
        """
        try:
            user = self._db.find_user_by(email=email)
            return bcrypt.checkpw(password.encode('utf-8'),
                                  user.hashed_password)
        except Exception:
            return False

    def create_session(self, email: str) -> str:
        """Create a session for the user.

        Args:
            email (str): The user's email address.

        Returns:
            str: The session ID.
        """
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except Exception:
            return None

    def get_user_from_session_id(self, session_id: str) -> User:
        """Get the user corresponding to the session ID.

        Args:
            session_id (str): The session ID.

        Returns:
            User or None: The corresponding user, or None if not found.
        """
        try:
            if session_id is None:
                return None
            return self._db.find_user_by(session_id=session_id)
        except Exception:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Destroy the session for the user.

        Args:
            user_id (int): The ID of the user.
        """
        try:
            self._db.update_user(user_id, session_id=None)
        except Exception:
            pass
        return None

    def get_reset_password_token(self, email: str) -> str:
        """Get a reset password token for the user.

        Args:
            email (str): The user's email address.

        Returns:
            str: The reset password token.
        """
        try:
            user = self._db.find_user_by(email=email)
            token = _generate_uuid()
            self._db.update_user(user.id, reset_token=token)
            return token
        except Exception:
            raise ValueError()

    def update_password(self, reset_token: str, password: str) -> None:
        """Update the user's password using a reset token.

        Args:
            reset_token (str): The reset token.
            new_password (str): The new password.
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            hashed_password = _hash_password(password)
            self._db.update_user(user.id,
                                 hashed_password=hashed_password,
                                 reset_token=None)
            return None
        except Exception:
            raise ValueError()
