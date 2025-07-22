import uuid
from typing import Optional

from authlib.jose import JsonWebEncryption, JsonWebKey

from .keys import Keys

JWE = JsonWebEncryption()


DEFAULT_SESSION_VERSION = 1
DEFAULT_SESSION_EXPIRES = 120


class Session:
    def __init__(self, keys: Keys, app: uuid.UUID = None, audience: list = None, header: dict = None,
                 version: int = DEFAULT_SESSION_VERSION, expires: int = DEFAULT_SESSION_EXPIRES,
                 key: Optional[bytes, JsonWebKey] = None):
        """
        :param keys: The "Keys" class containing public keys
        :param app: Application UUID for iss encoding JWT
        :param audience: Allowed audience list for this session. None == All Allowed
        :param header: Headers for JWT encoding
        :param version: JWT versions
        :param expires: JWT lifetime (ttl)
        :param key: The private key for the JWE decoding or JWT encoding operation
        """
        pass
