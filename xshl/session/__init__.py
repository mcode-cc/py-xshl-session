import logging
import os
import time
import uuid
from copy import deepcopy
from uuid import NAMESPACE_OID
from typing import Optional, Type, Union, KeysView
from datetime import datetime

import json
from authlib.jose import JsonWebEncryption, JsonWebKey, Key, JWTClaims, jwt
from authlib.jose.errors import InvalidClaimError
from xshl.target import Target

from .claims import SessionClaims
from .keys import Keys

log = logging.getLogger(__name__)
log.setLevel(logging.WARNING if os.getenv("DEBUG", "0") == "0" else logging.DEBUG)

JWE = JsonWebEncryption()
DEFAULT_SESSION_VERSION = 1
DEFAULT_SESSION_EXPIRES = 120
DEFAULT_UID = "00000000-0000-0000-0000-000000000000"
DEFAULT_STR = "undef"


def dict_merge(first: dict, second: dict) -> dict:
    """
    Recursively combines two dicts. Values that are not a dict are replaced from second.
    Args:
        first: Basic dict
        second: The dict that will be combined with the base one.

    Returns:
        New combined dict (original dict are not changed)
    """
    result = deepcopy(first)
    for key, value in second.items():
        if key in result:
            if isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = dict_merge(result[key], value)
            else:
                result[key] = value
        else:
            result[key] = value
    return result


class JsonDumps:
    def __init__(self, df=None):
        """
        :param df: default function for dumps
        """
        self.original_dumps = json.dumps

        if df is None:
            def jdf(value):
                try:
                    if isinstance(value, datetime):
                        return value.isoformat()
                    elif isinstance(value, Target):
                        return str(value)
                    else:
                        return vars(value)
                except Exception as e:
                    raise type(e)("JSON serialization failed: {}".format(e)) from e

            df = jdf

        def dumps(*args, default=None, **kwargs):
            if default is None:
                default = df
            return self.original_dumps(*args, default=default, **kwargs)

        self.dumps = dumps

    def __enter__(self):
        json.dumps = self.dumps
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        json.dumps = self.original_dumps


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
                 key: Union[bytes, Key] = None):
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
        self.private = None if key is None else key if isinstance(key, Key) else JsonWebKey.import_key(key)
        self.app = str(app) if isinstance(app, uuid.UUID) else DEFAULT_UID

        if isinstance(header, dict):
            if "kid" not in header:
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

    def __add__(self, other: str):
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
                for attribute in ["aud", "sub", "_payloads", "scope", "_scope"]:
                    if attribute in _claims:
                        if isinstance(_claims[attribute], dict) and isinstance(self._claims.get(attribute), dict):
                            setattr(self._claims, attribute, dict_merge(self._claims[attribute], _claims[attribute]))
                        # summing lists without duplicate and maintaining order
                        elif isinstance(_claims[attribute], list) and isinstance(self._claims.get(attribute), list):
                            setattr(
                                self._claims, attribute, list(set(self._claims.get(attribute) + _claims[attribute]))
                            )
                        else:
                            setattr(self._claims, attribute, _claims[attribute])
        return self

    def __len__(self) -> int:
        return len(self._claims)

    def __contains__(self, item):
        return item in self._claims

    def __getitem__(self, item):
        return self._claims.get(item, None)

    def __iter__(self):
        for k, v in self._claims.items():
            if v is None:
                continue
            yield k, v

    def keys(self) -> KeysView[str]:
        """
        To unpack: **session
        """
        return self._claims.keys()

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
    def sub(self, value: str):
        self._claims.sub = value

    @property
    def aud(self) -> str:
        return self._claims.aud

    @aud.setter
    def aud(self, value: str):
        if self._config.audience is None or value in self._config.audience:
            self._claims.aud = value

    # ------
    @property
    def sid(self):
        return self._claims.sid

    # Service JWT claims
    @property
    def scope(self) -> Optional[list]:
        return self._claims.scope

    @scope.setter
    def scope(self, value: list):
        if isinstance(value, list):
            self._claims.scope = list(map(str, value))
        else:
            raise ValueError("'scope' must be a list")

    @property
    def path(self) -> Optional[str]:
        """JWT location"""
        return self._claims.location

    @path.setter
    def path(self, value: str):
        if value:
            self._claims.location = value
        else:
            del self.path

    @path.deleter
    def path(self):
        if "location" in self._claims:
            del self._claims["location"]

    @property
    def response_type(self) -> Optional[str]:
        return self._claims.type

    @response_type.setter
    def response_type(self, value: str):
        if value:
            self._claims.type = value
        else:
            del self.response_type

    @response_type.deleter
    def response_type(self):
        del self._claims["type"]

    @property
    def request_scope(self) -> Optional[str]:
        return self._claims.get("_scope", None)

    @request_scope.setter
    def request_scope(self, value: str):
        """if setter None or null value, deleting "_scope"""""
        if value:
            self._claims["_scope"] = value
        else:
            del self.request_scope

    @request_scope.deleter
    def request_scope(self):
        if "_scope" in self._claims:
            del self._claims["_scope"]

    # ------

    # Data JWT claims
    @property
    def payloads(self) -> Optional[dict]:
        return self._claims.get("_payloads", None)

    @payloads.setter
    def payloads(self, value: dict):
        """if setter None or null value, deleting "_payloads"""""
        if not value:
            del self.payloads
        elif isinstance(value, dict):
            self._claims["_payloads"] = value
        else:
            raise ValueError("'payloads' must be a dict")

    @payloads.deleter
    def payloads(self):
        if "_payloads" in self._claims:
            del self._claims["_payloads"]

    # ------

    # JWE
    def serialize(self, value: Union[str, int, bytes], header: dict) -> str:
        """
        :param value: Payload (bytes or a value convertible to bytes)
        :param header: A dict of protected header
        :return:
        """
        key = self._config.keys(kid=header.get("kid", DEFAULT_STR))
        if key is not None:
            try:
                return JWE.serialize_compact(protected=header, payload=value, key=key).decode()
            except Exception as e:
                log.error(e)
        else:
            raise ValueError("Cannot serialize: No public key for serialize.")

    def deserialize(self, value=None) -> str:
        result = None
        if value is not None:
            result = JWE.deserialize_compact(value, key=self._config.private)["payload"].decode()
        return result

    # ------

    # Token
    @property
    def jwt(self) -> Optional[str]:
        try:
            _t = int(time.time())
            self._claims.jti = str(uuid.uuid4())
            self._claims.iat = _t
            self._claims.exp = _t + self._config.expires
            self._claims.nbf = _t
            self._claims.trace = self._trace.get(self._claims.jti)
            with JsonDumps():
                result = jwt.encode(
                    header=self._config.header, payload=dict(self._claims), key=self._config.private
                ).decode()
        except Exception as e:
            result = None
            log.warning(e)
        return result

    # ------

    @property
    def options(self):
        result = {
            "version": {"value": self._config.version},
            "trace": {"validate": self._trace.validate},
            "sid": {"value": self.sid}
        }
        if isinstance(self._config.audience, list):
            result["aud"] = {"values": self._config.audience}
        return result

    @property
    def name(self):
        return self._config.keys.name
