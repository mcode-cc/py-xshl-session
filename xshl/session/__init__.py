import logging
import os
import time
import uuid
from uuid import NAMESPACE_OID
from copy import deepcopy
from typing import Optional, Type, Union

from authlib.jose import JsonWebEncryption, JsonWebKey, Key, JWTClaims, jwt
from authlib.jose.errors import InvalidClaimError

from .claims import SessionClaims
from .keys import Keys
from .utilites import datetime_as_8601, dict_merge

log = logging.getLogger(__name__)
log.setLevel(logging.WARNING if os.getenv("DEBUG", "0") == "0" else logging.DEBUG)
JWE = JsonWebEncryption()

NAME_ENCRYPT = "{}a"
NAME_KEY = "{}k"
NAME_TOKEN = "{}t"

DEFAULT_SESSION_VERSION = 1
DEFAULT_SESSION_EXPIRES = 120
DEFAULT_UID = "00000000-0000-0000-0000-000000000000"
DEFAULT_STR = "undef"


class Trace:
    def __init__(self, *args):
        self._items = args

    def get(self, value: str):
        """:returns: UUIDv5 string from trace args with spacename jti"""
        return str(uuid.uuid5(uuid.UUID(value), str(self)))

    def validate(self, claims: JWTClaims, value: str):
        return self.get(claims.get("jti")) == value

    def __str__(self):
        return ":".join(map(str, self._items))


class ConfigSession:
    def __init__(self, keys: Keys, app: uuid.UUID = None, audience: list = None, header: dict = None,
                 version: int = DEFAULT_SESSION_VERSION, expires: int = DEFAULT_SESSION_EXPIRES,
                 key: Optional[bytes, Key] = None):
        """
        :param keys: The "Keys" class containing public keys
        :param app: Application UUID for iss encoding JWT
        :param audience: Allowed audience list for this session. None == All allowed
        :param header: Headers for JWT encoding or JWE serialize. Example: {"alg": "RS256", "kid": "7Hx9cC0eQ3...."}
        :param version: JWT versions
        :param expires: JWT lifetime (ttl)
        :param key: The private key for the JWE decoding or JWT encoding operation
        """
        self.keys = keys
        self.audience = audience
        self.header = header
        self.version = int(version)
        self.expires = int(expires)
        self.private = key if isinstance(key, Key) else JsonWebKey.import_key(key)

        if isinstance(app, uuid.UUID):
            self.app = str(app)
        else:
            raise TypeError("app must be 'UUID' (not '{}') to str".format(type(app).__name__))

        if isinstance(header, dict):
            if "kid" in header:
                self.kid = header["kid"]
            else:
                raise ValueError("'header' must be a dictionary with 'kid' key when provided")


class Session:
    claims_cls: Type[JWTClaims] = SessionClaims
    trace_cls: Type[Trace] = Trace

    def __init__(self, config: ConfigSession, *args):
        self._config = config
        self._trace = self.trace_cls(*args)
        self._claims = self.claims_cls(
            payload={
                "iss": self._config.app,
                "sub": DEFAULT_UID,
                "aud": DEFAULT_STR,
                "sid": str(uuid.uuid5(uuid.uuid5(NAMESPACE_OID, self.name), str(self._trace))),
                "version": self._config.version
            },
            header=config.header
        )

    def __add__(self, other: Union['Session', str]):
        """
        Combines attributes ("aud", "sub", "_payloads", "scope", "_scope") the current and transmitted session or JWT.
        """
        if isinstance(other, str):
            try:
                _claims = jwt.decode(
                    other, key=self._config.keys(), claims_options=self.options, claims_cls=self.claims_cls
                )
                _claims.validate()
            except InvalidClaimError as claim:
                log.debug(claim)
            except Exception as e:
                log.warning(e)
            else:
                for attribute in ["aud", "sub", "_payloads", "_meta", "scope", "_scope"]:
                    if attribute in _claims:
                        if isinstance(_claims[attribute], dict) and isinstance(self._claims.get(attribute), dict):
                            setattr(self._claims, attribute, dict_merge(self._claims[attribute], _claims[attribute]))
                        # summing lists without duplicate and maintaining order
                        elif isinstance(_claims[attribute], list) and isinstance(self._claims.get(attribute), list):
                            setattr(
                                self._claims, attribute, list(set(self._claims.get([attribute]) + _claims[attribute]))
                            )
                        else:
                            setattr(self._claims, attribute, _claims[attribute])
        else:
            raise TypeError(
                "can only concatenate 'str' (not '{}')".format(type(other).__name__)
            )

    def update(self, **kwargs):
        for k, v in kwargs.items():
            if hasattr(self, k):
                # If the current and new values are a dictionary, use dictionary merging.
                if isinstance(getattr(self, k), dict) and isinstance(v, dict):
                    setattr(self, k, dict_merge(getattr(self, k), v))
                else:
                    setattr(self, k, v)

    # Default JWT claims:
    @property
    def iss(self) -> str:
        return self._claims.iss

    @property
    def sub(self) -> str:
        return self._claims.sub

    @sub.setter
    def sub(self, value):
        self._claims.sub = value

    @property
    def aud(self) -> str:
        return self._claims.aud

    @aud.setter
    def aud(self, value):
        self._claims.aud = value

    # ------
    @property
    def sid(self):
        return self._claims.sid

    # Service JWT claims
    @property
    def scope(self) -> list:
        return self._claims.get("scope", None)

    @scope.setter
    def scope(self, value: list):
        if isinstance(value, list):
            self._claims.scope = value
        else:
            raise TypeError("scope must be 'list' (not '{}')".format(type(value).__name__))

    @property
    def path(self) -> str:
        """JWT location"""
        return self._claims.get("location", DEFAULT_STR)

    @path.setter
    def path(self, value: str):
        self._claims.location = value

    @path.deleter
    def path(self):
        del self._claims["location"]

    @property
    def response_type(self):
        return self._claims.get("type", DEFAULT_STR)

    @response_type.setter
    def response_type(self, value: str):
        self._claims.type = value

    @response_type.deleter
    def response_type(self):
        del self._claims.type

    @property
    def trace(self) -> str:
        return self._claims.get("trace", DEFAULT_STR)

    @property
    def request_scope(self):
        return self._claims["_scope"] if "_scope" in self._claims else ""

    @request_scope.setter
    def request_scope(self, value: str):
        """if setter None or null value, deleting "_scope"""""
        if value:
            self._claims["_scope"] = value
        else:
            del self.request_scope

    @request_scope.deleter
    def request_scope(self):
        del self._claims["_scope"]

    # ------

    # Data JWT claims
    @property
    def payloads(self) -> dict:
        return deepcopy(self._claims.get("_payloads", {}))

    @payloads.setter
    def payloads(self, value: dict):
        """if setter None or null value, deleting "_payloads"""""
        if value:
            setattr(self._claims, "_payloads", value)
        else:
            del self.payloads

    @payloads.deleter
    def payloads(self):
        del self._claims["_payloads"]

    @property
    def meta(self) -> dict:
        return deepcopy(self._claims.get("_meta", {}))

    @meta.setter
    def meta(self, value: dict):
        """if setter None or null value, deleting "_meta"""""
        if value:
            setattr(self._claims, "_meta", value)
        else:
            del self.meta

    @meta.deleter
    def meta(self):
        del self._claims["_meta"]

    # ------

    # NAMES
    @property
    def encrypt(self) -> str:
        return NAME_ENCRYPT.format(self.name)

    @property
    def key(self) -> str:
        return NAME_KEY.format(self.name)

    @property
    def token(self) -> str:
        return NAME_TOKEN.format(self.name)

    # ------

    # JWE
    def serialize(self, value: Union[str, int, bytes], header: dict) -> str:
        """
        :param value: Payload (bytes or a value convertible to bytes)
        :param header: A dict of protected header
        :return:
        """
        key = self._config.keys(kid=self._config.kid)
        if key is not None:
            try:
                return JWE.serialize_compact(protected=header, payload=value, key=key).decode()
            except Exception as e:
                log.error(e)
        else:
            raise ValueError("Cannot serialize: No public key for serialize.")

    def deserialize(self, value=None) -> str:
        if self._config.private:
            result = None
            if value is not None:
                result = JWE.deserialize_compact(value, key=self._config.private)["payload"].decode()
            return result
        raise ValueError("Cannot deserialize: 'key' (private key) is not initialized.")

    # ------

    # Token
    @property
    def jwt(self) -> Optional[str]:
        if self._config.private:
            try:
                _t = int(time.time())
                self._claims.jti = str(uuid.uuid4())
                self._claims.iat = _t
                self._claims.exp = _t + self._config.expires
                self._claims.nbf = _t
                self._claims.trace = self._trace.get(self._claims.jti)
                result = jwt.encode(
                    header=self._config.header,
                    payload=datetime_as_8601(self.value),
                    key=self._config.private
                ).decode()
            except Exception as e:
                result = None
                log.warning(e)
            return result
        raise ValueError("Cannot return JWT: 'key' (private key) is not initialized.")

    # ------

    @property
    def value(self) -> dict:
        """
        :returns: Isolated dictionary of JWT data.
        """
        return deepcopy(dict(self._claims))

    @property
    def options(self):
        result = {
            "version": {"value": self._config.version},
            "trace": {"validate": self._trace.validate},
            "sid": {"value": self.sid}
        }
        if isinstance(self._config.audience, list):
            result = {"values": self._config.audience}
        return result

    @property
    def name(self):
        return self._config.keys.name
