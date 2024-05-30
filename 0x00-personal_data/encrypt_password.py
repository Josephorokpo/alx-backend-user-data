#!/usr/bin/env python3
"""
This module defines functions for hashing passwords and
verifying hashed passwords using the bcrypt algorithm.
"""

import bcrypt
from bcrypt import hashpw


def hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt.

    Args:
        password (str): The password to be hashed.

    Returns:
        bytes: The hashed password.
    """
    b = password.encode()
    hashed = hashpw(b, bcrypt.gensalt())
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Verifies whether a given password matches the hashed password.

    Args:
        hashed_password (bytes): The hashed password.
        password (str): The plain text password to verify.

    Returns:
        bool: True if the password matches the hashed password,
        False otherwise.
    """
    return bcrypt.checkpw(password.encode(), hashed_password)
