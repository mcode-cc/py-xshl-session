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

    def __init__(self, config: ConfigSession, trace: list):
        self._config = config
        self._trace = trace
        self._claims = self.claims_cls(payload={}, header=config.header)

    def __add__(self, other: Union['Session', str]):
        """
        Combines attributes ("_payloads", "_meta", "scope", "_scope") the current and transmitted session or JWT.
        """
        _claims = None
        if isinstance(other, Session):
            _claims = other._claims
        elif isinstance(other, str):
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
            raise TypeError(
                "can only concatenate '{}' or 'str' (not '{}') to str".format(self.__name__, type(other).__name__)
            )

        if _claims is not None:
            for attribute in ["_payloads", "_meta", "scope", "_scope"]:
                if attribute in _claims:
                    if isinstance(_claims[attribute], dict) and isinstance(self._claims.get(attribute), dict):
                        setattr(self._claims, attribute, dict_merge(self._claims[attribute], _claims[attribute]))
                    # We add up the scope if at least one of them is a list.
                    elif isinstance(_claims[attribute], list) or isinstance(self._claims.get(attribute), list):
                        if isinstance(_claims[attribute], list):
                            new = _claims[attribute]
                            addend = self._claims.get(attribute)
                        else:
                            new = self._claims.get(attribute)
                            addend = _claims[attribute]
                        new += addend if isinstance(addend, list) else [addend] if isinstance(addend, str) else []
                        setattr(self._claims, attribute, list(set(new)))
                    else:
                        setattr(self._claims, attribute, _claims[attribute])

    def update(self, path: str = None, scope: list = None, **kwargs):
        if path is not None:
            self.path = path
        if scope is not None:
            if self.scope is None:
                self.scope = scope
            else:
                self.scope = list(set(self.scope + scope)) if isinstance(self.scope, list) \
                    else list(set([self.scope] + scope))
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
    def scope(self) -> Union[list, str]:
        return self._claims.get("scope", None)

    @scope.setter
    def scope(self, value: Union[list, str]):
        if isinstance(value, list) and len(value) == 1:
            # Строка - если список состоит из 1 значения
            self._claims.scope = value[0]
        else:
            self._claims.scope = value

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
    def future_scope(self):
        return self._claims["_scope"] if "_scope" in self._claims else ""

    @future_scope.setter
    def future_scope(self, value: str):
        """if setter None or null value, deleting "_scope"""""
        if value:
            self._claims["_scope"] = value
        else:
            del self.future_scope

    @future_scope.deleter
    def future_scope(self):
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
                self._claims.iss = self._config.app
                self._claims.trace = self.get_trace(self._trace)
                self._claims.sid = self._sid
                self._claims.version = self._config.version
                self._claims.validate()
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

    @jwt.setter
    def jwt(self, value: str):
        try:
            _claims = jwt.decode(
                value, key=self._config.keys(), claims_options=self.options, claims_cls=self.claims_cls
            )
            _claims.validate()
        except InvalidClaimError as claim:
            log.debug(claim)
        except Exception as e:
            log.warning(e)
        else:
            self._claims = _claims

    # ------

    @property
    def _sid(self) -> str:
        return str(uuid.uuid5(uuid.uuid5(NAMESPACE_OID, self.name), ":".join(self._trace)))

    @property
    def value(self) -> dict:
        """
        :returns: Isolated dictionary of JWT data.
        """
        return deepcopy(dict(self._claims))

    def expire(self, _format="%a, %d %b %Y %H:%M:%S GMT") -> str:
        return time.strftime(_format, time.gmtime(self._claims.exp))

    def get_trace(self, *args):
        """:returns: UUIDv5 string from trace args with spacename jti"""
        return str(uuid.uuid5(uuid.UUID(self._claims.jti), ":".join(map(str, args))))

    def _trace_validate(self, _: JWTClaims, value: str):
        return self.get_trace(*self._trace) == value

    @property
    def options(self):
        result = {
            "version": {"value": self._config.version},
            "sid": {"value": self._sid},
            "trace": {"validate": self._trace_validate}
        }
        if isinstance(self._config.audience, list):
            result = {"values": self._config.audience}
        return result

    @property
    def name(self):
        return self._config.keys.name
