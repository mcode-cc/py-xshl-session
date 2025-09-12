import time
import unittest
from copy import deepcopy

from authlib.jose import JWTClaims
from authlib.jose.errors import MissingClaimError, InvalidTokenError, ExpiredTokenError, InvalidClaimError

from xshl.session.claims import SessionClaims


class TestClaims(unittest.TestCase):
    def setUp(self):
        now = time.time()
        self.claims = {
            "_payloads": {
                "login": {
                    "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
                },
            },
            "aud": "session",
            "exp": now + 100,
            "iat": now - 1,
            "iss": "613659bc-4e13-40d9-9422-5ca356725f9b",
            "jti": "e4ed0beb-4535-4138-b459-2100441bb7b0",
            "location": "https://example.ru/",
            "nbf": now - 1,
            "scope": [
                "payloads:login"
            ],
            "sid": "1bd3d2f8-5358-4722-a536-ca7afae02c8b",
            "sub": "84a276c1-82f0-496e-9c06-91e3b07df389",
            "trace": "4247d744-293a-5de3-b8ce-d2678eff9385",
            "type": "set",
            "version": 1,
            "_scope": "payloads:profile"
        }

    def test_required_claims(self):
        required = SessionClaims.REQUIRED_CLAIMS

        for claim in required:
            bad_data = deepcopy(self.claims)
            bad_data.pop(claim)
            claims = SessionClaims(bad_data)
            with self.assertRaises(MissingClaimError, msg="Claim: '{}' has problem.".format(claim)):
                claims.validate()

    def test_registered_claims(self):
        registered = SessionClaims.REGISTERED_CLAIMS
        session = SessionClaims(self.claims)

        for claim in registered:
            self.assertTrue(
                getattr(session, claim) == session[claim] == self.claims[claim],
                msg="Claim: '{}' has problem.".format(claim)
            )

    def test_unregistered_claims(self):
        unregistered = "unregistered"
        self.claims[unregistered] = unregistered
        session = SessionClaims(self.claims)

        with self.assertRaises(AttributeError):
            getattr(session, unregistered)

    def test_advanced_validate_value(self):
        registered = set(SessionClaims.REGISTERED_CLAIMS)
        not_support = {"exp", "nbf", "iat"}
        registered -= not_support

        for claim in registered:
            session = SessionClaims(self.claims, options={claim: {"value": self.claims[claim]}})
            session.validate()
            session[claim] = "invalid_value"
            with self.assertRaises(InvalidClaimError, msg="Claim: '{}' has problem.".format(claim)):
                session.validate()

    def test_advanced_validate_values(self):
        registered = set(SessionClaims.REGISTERED_CLAIMS)
        not_support = {"exp", "nbf", "iat"}
        registered -= not_support
        values = ["value", "value2"]

        for claim in registered:
            session = SessionClaims(self.claims, options={claim: {"values": values}})
            for el in values:
                session[claim] = el
                session.validate()
            session[claim] = "invalid_value"
            with self.assertRaises(InvalidClaimError, msg="Claim: '{}' has problem.".format(claim)):
                session.validate()

    def test_advanced_validate_func(self):
        registered = set(SessionClaims.REGISTERED_CLAIMS)
        not_support = {"aud", "exp", "nbf", "iat"}
        registered -= not_support

        for claim in registered:

            def validate(claims: JWTClaims, value: str) -> bool:
                return self.claims[claim] == value

            session = SessionClaims(self.claims, options={claim: {"validate": validate}})
            session.validate()
            session[claim] = "invalid_value"
            with self.assertRaises(InvalidClaimError, msg="Claim: '{}' has problem.".format(claim)):
                session.validate()

    def test_nbf(self):
        self.claims["nbf"] = self.claims["nbf"] + 10
        session = SessionClaims(self.claims)
        with self.assertRaises(InvalidTokenError):
            session.validate()

    def test_exp(self):
        self.claims["exp"] = time.time()-1
        session = SessionClaims(self.claims)
        with self.assertRaises(ExpiredTokenError):
            session.validate()

    def test_iat(self):
        self.claims["iat"] = time.time() + 10
        session = SessionClaims(self.claims)
        with self.assertRaises(InvalidTokenError):
            session.validate()


if __name__ == "__main__":
    unittest.main()
