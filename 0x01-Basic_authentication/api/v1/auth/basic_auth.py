#!/usr/bin/env python3
"""
Basic auth
"""
from base64 import b64decode
from models.user import User
from typing import Tuple, TypeVar
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """
    Basic auth
    """

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """
        Basic - Base64 part
        """

        if authorization_header is None or type(
                authorization_header
        ) is not str or authorization_header[:6] != 'Basic ':
            return None

        return authorization_header[6:]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """
        Basic - Base64 decode
        """

        if base64_authorization_header is None or type(
                base64_authorization_header) is not str:
            return None

        try:
            b64_bytes = b64decode(base64_authorization_header)
            return b64_bytes.decode('utf-8')

        except Exception:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> Tuple[str, str]:
        """
        Basic - User credentials
        """

        if decoded_base64_authorization_header is None or type(
                decoded_base64_authorization_header
        ) is not str or ':' not in decoded_base64_authorization_header:
            return (None, None)

        return tuple(decoded_base64_authorization_header.split(':', 1))

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """
        Basic - User object
        """
        if user_email is None or type(user_email) is not str:
            return None

        if user_pwd is None or type(user_pwd) is not str:
            return None

        try:
            match = User.search({'email': user_email})
            if len(match) == 0:
                return None
            user = match[0]

            if user.is_valid_password(user_pwd):
                return user
        except Exception:
            pass

        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Basic - Overload current_user
        """

        header = self.authorization_header(request)
        base64_header = self.extract_base64_authorization_header(header)
        decoded_header = self.decode_base64_authorization_header(base64_header)
        user_credentials = self.extract_user_credentials(decoded_header)
        return self.user_object_from_credentials(user_credentials[0],
                                                 user_credentials[1])
