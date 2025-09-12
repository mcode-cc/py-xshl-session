import time
import unittest
import uuid

from authlib.jose import JWTClaims

from xshl.session import Trace


class TestClaims(unittest.TestCase):
    def setUp(self):
        self.ua = "CustomUA/1.0"
        self.ip = "127.0.0.1"
        self.salt = uuid.uuid4()
        self.name_space = uuid.uuid4()
        self._join = ":".join([self.ua, str(self.salt), self.ip])
        self._trace = str(uuid.uuid5(self.name_space, self._join))

    def test_trace_str(self):
        trace = Trace(self.ua, self.salt, self.ip)
        self.assertEqual(str(trace), self._join)

    def test_trace_get(self):
        trace = Trace(self.ua, self.salt, self.ip)
        self.assertEqual(self._trace, trace.get(str(self.name_space)))

    def test_trace_validate(self):
        now = time.time()
        trace = Trace(self.ua, self.salt, self.ip)
        claims = JWTClaims(
            {"exp": now + 100, "iat": now - 1, "nbf": now - 1, "jti": str(self.name_space), "trace": self._trace},
            header=None,
            options={"trace": {"validate": trace.validate}}
        )
        claims.validate()

    def test_trace_empty_args(self):
        trace = Trace()
        self.assertEqual(str(trace), "")
        # UUIDv5 от пустой строки должен быть детерминирован
        name_space = uuid.uuid4()
        self.assertEqual(trace.get(str(name_space)), str(uuid.uuid5(name_space, "")))
