import logging
import os
import time
import uuid
from copy import deepcopy
from typing import Optional, Type, Union

from authlib.jose import JsonWebEncryption, JsonWebKey, Key, JWTClaims, jwt
from authlib.jose.errors import InvalidClaimError

from .claims import SessionClaims
from .keys import Keys
from .utilites import datetime_as_8601, dict_merge

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING if os.getenv("DEBUG", "0") == "0" else logging.DEBUG)
JWE = JsonWebEncryption()

NAME_ENCRYPT = "{}a"
NAME_KEY = "{}k"
NAME_TOKEN = "{}t"

DEFAULT_SESSION_VERSION = 1
DEFAULT_SESSION_EXPIRES = 120
DEFAULT_UID = "00000000-0000-0000-0000-000000000000"
DEFAULT_STR = "undef"


class Session:
    def __init__(self, keys: Keys, app: uuid.UUID = None, audience: list = None, header: dict = None,
                 version: int = DEFAULT_SESSION_VERSION, expires: int = DEFAULT_SESSION_EXPIRES,
                 key: Optional[bytes, Key] = None, claims_cls: Type[JWTClaims] = SessionClaims):
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
        self.name = keys.name
        self.app = app
        self.header = header
        self.expires = int(expires)

        self._version = int(version)
        self._options = {"version": {"value": self._version}}
        if isinstance(audience, list):
            self._options["aud"] = {"values": audience}
        self._claims = None
        self._claims_cls = claims_cls
        self._private = key if isinstance(key, Key) else JsonWebKey.import_key(key)

    def __add__(self, other: 'Session'):
        """
        Combines attributes ("_payloads", "_meta", "scope", "_scope") the current and transmitted session.
        """
        if isinstance(other, Session):
            for attribute in ["_payloads", "_meta", "scope", "_scope"]:
                value = other.value
                if attribute in value:
                    if isinstance(value[attribute], dict) and isinstance(self._claims.get(attribute), dict):
                        setattr(self._claims, attribute, dict_merge(self._claims[attribute], value[attribute]))
                    # We add up the scope if at least one of them is a list.
                    elif isinstance(value[attribute], list) or isinstance(self._claims.get(attribute), list):
                        if isinstance(value[attribute], list):
                            new = value[attribute]
                            addend = self._claims.get(attribute)
                        else:
                            new = self._claims.get(attribute)
                            addend = value[attribute]
                        new += addend if isinstance(addend, list) else [addend] if isinstance(addend, str) else []
                        setattr(self._claims, attribute, list(set(new)))
                    else:
                        setattr(self._claims, attribute, value[attribute])
        else:
            raise TypeError("can only concatenate '{}' (not '{}') to str".format(self.__name__, type(other).__name__))

    def new(self, audience: str = DEFAULT_STR, subject: str = DEFAULT_UID,
            expires: int = None, path: str = None, trace: list = None):
        """
        Creates new jwt data for the current object (session)
        """
        _t = int(time.time())
        self._claims = self._claims_cls(
            {
                "iss": self.app,
                "aud": audience,
                "sub": subject,
                "exp": _t + int(expires or self.expires),
                "nbf": _t,
                "jti": str(uuid.uuid4()),
                "iat": _t,
                "version": self._version,
                "sid": str(uuid.uuid4())
            },
            header=self.header
        )
        if path is not None:
            self.path = path
        if trace is not None:
            self.trace = trace

    def update(self, trace: list = None, path: str = None, scope: list = None, **kwargs):
        _t = int(time.time())
        self._claims.jti = str(uuid.uuid4())
        self._claims.exp = _t + self.expires
        self._claims.nbf = _t
        self.iss = self.app
        if trace is not None:
            self.trace = trace
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

    def copy(self, token: str = None) -> "Session":
        """
        :return: Copies an instance of the class, sets the data if there is a token.
        """
        session = self.__class__(
            keys=self.keys,
            app=self.app,
            audience=None if "aud" not in self._options else self._options["aud"]["values"],
            header=self.header,
            version=self._version,
            expires=self.expires,
            key=self._private,
            claims_cls=self._claims_cls
        )
        if token:
            session.jwt = token
        return session

    # Default JWT claims:
    @property
    def iss(self) -> str:
        return self._claims.iss

    @iss.setter
    def iss(self, value: str):
        """
        @param value: Must be uuid
        """
        try:
            self._claims.iss = str(uuid.UUID(value))
        except ValueError:
            self._claims.iss = DEFAULT_UID
            logger.warning("Incorrect iss: {}".format(value))

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

    # Service JWT claims
    @property
    def sid(self) -> str:
        return self._claims.sid

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

    @trace.setter
    def trace(self, value: list):
        value = value if isinstance(value, list) else []
        self._claims.trace = self.get_trace(*value)

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
        if self.header and "kid" in self.header:
            key = self.keys(kid=self.header["kid"])
            if key is not None:
                try:
                    return JWE.serialize_compact(protected=header, payload=value, key=key).decode()
                except Exception as e:
                    logger.error(e)
            else:
                raise ValueError("Cannot serialize: No public key for serialize.")
        else:
            raise ValueError("Cannot serialize: 'header' must be a dictionary containing at 'kid'.")

    def deserialize(self, value=None) -> str:
        if self._private:
            result = None
            if value is not None:
                result = JWE.deserialize_compact(value, key=self._private)["payload"].decode()
            return result
        raise ValueError("Cannot deserialize: 'key' (private key) is not initialized.")

    # ------

    # Token
    @property
    def jwt(self) -> Optional[str]:
        if self._private:
            try:
                result = jwt.encode(
                    header=self.header,
                    payload=datetime_as_8601(self.value),
                    key=self._private
                ).decode()
            except Exception as e:
                result = None
                logger.warning(e)
            return result
        raise ValueError("Cannot return JWT: 'key' (private key) is not initialized.")

    @jwt.setter
    def jwt(self, value: str):
        try:
            self._claims = jwt.decode(
                value, key=self.keys(), claims_options=self._options, claims_cls=self._claims_cls
            )
            self._claims.validate()
        except InvalidClaimError as claim:
            self._claims = None
            logger.debug(claim)
        except Exception as e:
            logger.warning(e)

    # ------

    @property
    def value(self) -> dict:
        """
        :returns: Isolated dictionary of JWT data.
        """
        return deepcopy(dict(self._claims))

    def validate(self, sid: str, *args, trace=True, audience: str = None) -> bool:
        result = False
        if self._claims is not None:
            try:
                self._claims.validate(audience=audience)
                if int(self._claims.get("version", DEFAULT_SESSION_VERSION)) == self._version:
                    if self.sid == sid:
                        if not trace or self.trace == self.get_trace(*args):
                            result = True
            except InvalidClaimError as e:
                logger.debug(e)
            except Exception as ex:
                logger.error(ex)
        return result

    def get_trace(self, *args):
        """:returns: UUIDv5 string from trace args with spacename jti"""
        return str(uuid.uuid5(uuid.UUID(self._claims.jti), ":".join(map(str, args))))

    def expire(self, _format="%a, %d %b %Y %H:%M:%S GMT") -> str:
        return time.strftime(_format, time.gmtime(self._claims.exp))
