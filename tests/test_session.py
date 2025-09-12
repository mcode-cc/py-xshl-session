import time
import unittest
from unittest.mock import Mock, patch
import uuid

from authlib.jose import JsonWebKey, KeySet
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

import xshl.session
from xshl.session import Session, SessionClaims, Trace, dict_merge, ConfigSession, DEFAULT_STR, DEFAULT_UID
from xshl.session.keys import Keys, DEFAULT_KEYS_TTL

NAMESPACE_OID = uuid.NAMESPACE_OID


class KeysStub(Keys):
    def __init__(self, name: str, url: str, ttl: int = DEFAULT_KEYS_TTL, fake=None):
        super().__init__(name, url, ttl)
        self.__data = fake

    @property
    def _data(self) -> KeySet:
        return self.__data

    def load(self, background: bool = False):
        pass


class TestSession(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        cls.kid = kid = JsonWebKey.import_key(public_key).thumbprint()

        mock_config = Mock(spec=ConfigSession)
        mock_config.app = str(uuid.uuid4())
        mock_config.version = 1
        mock_config.expires = 3600
        mock_config.audience = None
        mock_config.header = {"alg": "RS256", "kid": kid}
        mock_config.keys = KeysStub(
            "session_name",
            "url",
            fake=JsonWebKey.import_key_set(
                {"keys": [JsonWebKey.import_key(raw=public_key, options={"kid": kid}).as_dict()]}
            )
        )
        mock_config.private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        cls.mock_config = mock_config

    def setUp(self):
        self.app = self.mock_config.app
        self.name = self.mock_config.keys.name
        self.trace = ["trace_arg1", "trace_arg2"]
        _time = time.time()
        self.session = Session(self.mock_config, *self.trace)
        _jti = str(uuid.uuid4())
        self.raw_claims = {
            "sid": self.session.sid,
            "iss": str(uuid.uuid4()),
            "jti": _jti,
            "exp": _time + 100,
            "iat": _time - 1,
            "nbf": _time - 1,
            "version": self.mock_config.version,
            "trace": self.session._trace.get(_jti)
        }

    def test_initialization(self):
        trace = Trace(*self.trace)
        sid = str(uuid.uuid5(uuid.uuid5(NAMESPACE_OID, self.name), str(trace)))

        self.assertEqual(self.session.iss, self.mock_config.app)
        self.assertEqual(self.session.sub, DEFAULT_UID)
        self.assertEqual(self.session.aud, DEFAULT_STR)
        self.assertEqual(str(trace), str(self.session._trace))
        self.assertEqual(self.session.sid, sid)
        self.assertEqual(self.session["version"], self.mock_config.version)
        self.assertEqual(self.session._claims.header, self.mock_config.header)

    def test_setter_properties(self):
        new_sub = "new_sub"
        self.session.sub = new_sub
        self.assertEqual(self.session.sub, new_sub)

        new_aud = "new_aud"
        self.session.aud = new_aud
        self.assertEqual(self.session.aud, new_aud)

        self.assertIsNone(self.session.scope)
        new_scope = ["scope1", "scope2"]
        self.session.scope = new_scope
        self.assertEqual(self.session.scope, new_scope)

        self.assertIsNone(self.session.request_scope)
        new_request_scope = "foo_scope"
        self.session.request_scope = new_request_scope
        self.assertEqual(self.session.request_scope, new_request_scope)
        self.session.request_scope = ""
        self.assertIsNone(self.session.request_scope)
        self.session.request_scope = new_request_scope
        del self.session.request_scope
        self.assertIsNone(self.session.request_scope)

        self.assertIsNone(self.session.path)
        new_path = "/test/path"
        self.session.path = new_path
        self.assertEqual(self.session.path, new_path)
        self.session.path = ""
        self.assertIsNone(self.session.path)
        self.session.path = new_path
        del self.session.path
        self.assertIsNone(self.session.path)

        self.assertIsNone(self.session.payloads)
        new_payloads = {"key": "value"}
        self.session.payloads = new_payloads
        self.assertEqual(self.session.payloads, new_payloads)
        self.session.payloads = {}
        self.assertIsNone(self.session.payloads)
        self.session.payloads = new_payloads
        del self.session.payloads
        self.assertIsNone(self.session.payloads)

        prev_iss = self.session.iss
        prev_sid = self.session.sid
        with self.assertRaises(AttributeError):
            self.session.iss = "changed"
        with self.assertRaises(AttributeError):
            self.session.sid = "changed"
        self.assertEqual(self.session.iss, prev_iss)
        self.assertEqual(self.session.sid, prev_sid)

    def test_jwt_property(self):
        token = self.session.jwt
        result = xshl.session.jwt.decode(
            token,
            key=self.session._config.keys(),
            claims_options=self.session.options,
            claims_cls=self.session.claims_cls
        )
        self.assertDictEqual(dict(self.session), result)

        level = "WARNING"

        class TestEncodeError(Exception):
            pass

        # Test jwt property when encode fails
        with self.assertLogs("xshl.session", level=level) as captured:
            with patch("xshl.session.jwt.encode", side_effect=TestEncodeError("Test Encode error")):
                self.assertIsNone(self.session.jwt)

            self.assertTrue(len(captured.records) > 0)
            self.assertEqual(captured.records[0].levelname, level)
            self.assertIsInstance(captured.records[0].msg, TestEncodeError)

    def test_add_operation(self):
        _payloads = {"new_key": "value", "foo": "bar"}
        add_payloads = {"new_key": {"baz": "foo"}}
        new_payloads = dict_merge(_payloads, add_payloads)
        self.raw_claims.update({
            "aud": "new_aud",
            "sub": "new_sub",
            "_payloads": add_payloads,
            "scope": ["foo", "new_key"],
            "_scope": "new_request_scope"
        })
        mock_claims = self.session.claims_cls(self.raw_claims, header=None, options=self.session.options)

        self.session.payloads = _payloads
        self.session.scope = ["foo"]
        self.session.request_scope = ["baz"]
        with patch("xshl.session.jwt.decode", return_value=mock_claims):
            result = self.session + "jwt_string"

        # Verify the claims were merged
        self.assertEqual(self.session.aud, mock_claims["aud"])
        self.assertEqual(self.session.sub, mock_claims["sub"])
        self.assertDictEqual(self.session.payloads, new_payloads)
        self.assertEqual(self.session.request_scope, mock_claims["_scope"])
        self.assertTrue(len(self.session.scope) == 2)
        self.assertTrue(mock_claims["scope"][0] in self.session.scope and mock_claims["scope"][1] in self.session.scope)
        self.assertIs(result, self.session)

    def test_add_operation_audience_validation(self):
        _audience = self.mock_config.audience
        allowed_aud = "allowed_aud"
        self.mock_config.audience = [allowed_aud]
        session = Session(self.mock_config, *self.trace)
        mock_jwt_str = "mock_jwt_string"
        sub = uuid.uuid4()
        self.raw_claims.update({"aud": "denied_aud", "sub": sub})

        with patch(
                "xshl.session.jwt.decode",
                return_value=SessionClaims(self.raw_claims, header=None, options=session.options),
        ):
            _ = session + mock_jwt_str

        self.assertEqual(session.aud, DEFAULT_STR)
        self.assertEqual(session.sub, DEFAULT_UID)

        self.raw_claims["aud"] = allowed_aud
        with patch(
                "xshl.session.jwt.decode",
                return_value=SessionClaims(self.raw_claims, header=None, options=session.options),
        ):
            _ = session + mock_jwt_str
        self.assertEqual(session.aud, allowed_aud)
        self.assertEqual(session.sub, sub)

        self.mock_config.audience = _audience

    def test_contains_and_getitem(self):
        self.assertTrue("iss" in self.session)
        self.assertEqual(self.session["iss"], self.app)
        self.assertIsNone(self.session["non_existent_key"])

    def test_properties_items(self):
        self.assertTrue(self.session["iss"] == self.session.iss == self.mock_config.app)
        self.assertTrue(self.session["sid"] == self.session.sid)

        self.assertEqual(self.session["aud"], DEFAULT_STR)
        self.assertEqual(self.session.aud, DEFAULT_STR)
        self.assertEqual(self.session["sub"], DEFAULT_UID)
        self.assertEqual(self.session.sub, DEFAULT_UID)
        self.assertIsNone(self.session["scope"])
        self.assertIsNone(self.session.scope)
        self.assertIsNone(self.session["location"])
        self.assertIsNone(self.session.path)
        self.assertIsNone(self.session["type"])
        self.assertIsNone(self.session.response_type)
        self.assertIsNone(self.session["_scope"])
        self.assertIsNone(self.session.request_scope)
        self.assertIsNone(self.session["_payloads"])
        self.assertIsNone(self.session.payloads)

        aud = "test-aud"
        sub = "test-sub"
        scope = ["s1", "s2"]
        location = "/loc"
        resp_type = "json"
        req_scope = "req"
        payloads = {"p": 1}

        self.session.aud = aud
        self.session.sub = sub
        self.session.scope = scope
        self.session.path = location
        self.session.response_type = resp_type
        self.session.request_scope = req_scope
        self.session.payloads = payloads

        self.assertEqual(self.session["aud"], self.session.aud)
        self.assertEqual(self.session["sub"], self.session.sub)
        self.assertEqual(self.session["scope"], self.session.scope)
        self.assertEqual(self.session["location"], self.session.path)
        self.assertEqual(self.session["type"], self.session.response_type)
        self.assertEqual(self.session["_scope"], self.session.request_scope)
        self.assertDictEqual(self.session["_payloads"], self.session.payloads)

        del self.session.payloads
        del self.session.request_scope
        del self.session.path
        self.assertIsNone(self.session.payloads)
        self.assertNotIn("_payloads", self.session._claims)
        self.assertIsNone(self.session.request_scope)
        self.assertNotIn("_scope", self.session._claims)
        self.assertIsNone(self.session.path)
        self.assertNotIn("location", self.session._claims)

        self.assertDictEqual(self.session._claims, dict(self.session))
        self.assertDictEqual(self.session._claims, {**self.session})

    def test_len_and_iter(self):
        self.assertEqual(len(self.session), len(self.session._claims))
        for key, value in self.session:
            self.assertIsNotNone(value)

    def test_update_method(self):
        self.session.payloads = {
            "a": 1,
            "nested": {"x": 1, "keep": True}
        }
        self.session.scope = ["old"]
        self.session.sub = "old_sub"
        self.session.aud = DEFAULT_STR
        self.session.path = None

        updates = {
            "sub": "updated_sub",
            "aud": "updated_aud",
            "scope": ["s1", "s2"],
            "payloads": {"b": 2, "nested": {"y": 2}},
            "response_type": "json",
            "request_scope": "req",
            "path": "/new/path",
            "unknown_property": "ignored"
        }
        self.session.update(**updates)

        self.assertEqual(self.session.sub, updates["sub"])
        self.assertEqual(self.session.aud, updates["aud"])
        self.assertEqual(self.session.scope, updates["scope"])
        self.assertEqual(self.session.response_type, updates["response_type"])
        self.assertEqual(self.session.request_scope, updates["request_scope"])
        self.assertEqual(self.session.path, updates["path"])

        self.assertDictEqual(
            self.session.payloads,
            {"a": 1, "b": 2, "nested": {"x": 1, "keep": True, "y": 2}}
        )
        self.assertIsNone(self.session.__dict__.get("unknown_property"))

        second_updates = {
            "payloads": {"nested": {"x": 3}},
            "scope": ["s3"]
        }
        self.session.update(**second_updates)
        self.assertEqual(self.session.scope, ["s3"])
        self.assertDictEqual(
            self.session.payloads,
            {"a": 1, "b": 2, "nested": {"x": 3, "keep": True, "y": 2}}
        )

    def test_serialize_and_deserialize(self):
        headers = {"alg": "RSA-OAEP-256", "enc": "A128GCM", "kid": self.kid}
        payloads = "test_encrypt_str"
        result = self.session.deserialize(self.session.serialize(payloads, headers))
        self.assertEqual(result, payloads)


if __name__ == "__main__":
    unittest.main()
