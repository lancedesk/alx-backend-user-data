#!/usr/bin/env python3
"""
Encrypt password module
"""

import bcrypt
from typing import Union


def hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt.

    Args:
        password: A string representing the password.

    Returns:
        A byte string representing the hashed password.
    """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validates a password against its hashed version using bcrypt.

    Args:
        hashed_password: A byte string representing the hashed password.
        password: A string representing the password to validate.

    Returns:
        A boolean indicating whether the password matches its hashed version.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)


if __name__ == "__main__":
    password = "MyAmazingPassw0rd"
    encrypted_password = hash_password(password)
    print(encrypted_password)
    print(is_valid(encrypted_password, password))
