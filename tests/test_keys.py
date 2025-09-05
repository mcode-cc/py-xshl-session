import asyncio
import os
import unittest
from unittest.mock import patch, MagicMock, AsyncMock, Mock
import time
import requests
from aiohttp import ClientConnectorDNSError
from authlib.jose import JsonWebKey

from xshl.session.keys import Keys, KeySet, Key

URL = os.getenv("TEST_URL", "http://valid.url/keys")


class TestKeys(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.test_name = "test"
        self.valid_url = URL
        self.invalid_url = "http://invalid.url/keys"
        self.keys_data_new = {
            "keys": [
                {
                    "alg": "RS256",
                    "e": "AQAB",
                    "kid": "new",
                    "kty": "RSA",
                    "n": "QzwNbH4Umb9G-k-D3I4VztN13gQwoHNU0sadaflv3SvKndw9SgCiAOa_",
                    "use": "enc"
                }
            ]
        }
        self.keys_data = {
            "keys": [
                {
                    "alg": "RS256",
                    "e": "AQAB",
                    "kid": "1",
                    "kty": "RSA",
                    "n": "soh7mpn1Uzt7P-k-D3I4VztN13gQwoHNU0qTxglv3SvKndw9SgCiAOa_",
                    "use": "sig"
                },
                {
                    "alg": "RS256",
                    "e": "AQAB",
                    "kid": "2",
                    "kty": "RSA",
                    "n": "QzwNbH4Umb9G-k-D3I4VztN13gQwoHNU0qTxglv3SvKndw9SgCiAOa_",
                    "use": "enc"
                }
            ]
        }
        self.key_set = JsonWebKey.import_key_set(self.keys_data)

    @staticmethod
    def _create_mock_response(status_code, json_data):
        mock = MagicMock()
        mock.status_code = status_code
        mock.json.return_value = json_data
        mock.raise_for_status.side_effect = (
            requests.exceptions.HTTPError if status_code != 200 else None
        )
        return mock

    @patch("requests.get")
    def test_init_with_invalid_url_raises(self, mock_get):
        mock_get.return_value = self._create_mock_response(404, {})

        with self.assertRaises(requests.exceptions.HTTPError):
            Keys(name=self.test_name, url=self.invalid_url)

    @patch("requests.get")
    def test_init_with_valid_url(self, mock_get):
        mock_get.return_value = self._create_mock_response(200, self.keys_data)

        keys = Keys(name=self.test_name, url=self.valid_url)

        self.assertEqual(keys.name, self.test_name)
        self.assertEqual(keys.url, self.valid_url)
        self.assertIsNotNone(keys._keys)

    @patch("requests.get")
    def test_update_with_invalid_url(self, mock_get):
        mock_get.return_value = self._create_mock_response(200, self.keys_data)
        level = "WARNING"

        keys = Keys(name=self.test_name, url=self.valid_url)
        self.assertTrue(len(keys().keys) > 0)
        mock_get.return_value = self._create_mock_response(400, self.keys_data)
        with self.assertLogs("xshl.session.keys", level=level) as captured:
            keys.url = self.invalid_url
            keys._update = 0
            keys()
            time.sleep(0.1)
            self.assertTrue(len(captured.records) > 0)
            self.assertEqual(captured.records[0].levelname, level)
            self.assertIsInstance(captured.records[0].msg, ClientConnectorDNSError)

    @patch("requests.get")
    def test_get_data(self, mock_get):
        mock_get.return_value = self._create_mock_response(200, self.keys_data)

        keys = Keys(name="test", url=self.valid_url)

        self.assertIsInstance(keys(kid="1"), Key)
        self.assertIsInstance(keys(kid="2"), Key)
        self.assertIsInstance(keys(), KeySet)

    @patch("aiohttp.ClientSession")
    @patch("requests.get")
    def test_multiple_calls(self, mock_get, mock_client_session):
        # function for simulating a delayed response from the api
        async def delayed_response():
            await asyncio.sleep(0.5)
            return mock_asinc_response

        mock_get.return_value = self._create_mock_response(200, self.keys_data)
        mock_asinc_response = AsyncMock(name="MockAsincResponse")
        mock_asinc_response.status = 200
        mock_asinc_response.json.return_value = self.keys_data_new
        mock_asinc_response.raise_for_status = Mock(return_value=None)
        mock_asinc_get = AsyncMock(name="MockAsincGet")
        mock_asinc_get.__aenter__.side_effect = delayed_response
        mock_asinc_get.__aenter__.return_value = mock_asinc_response
        mock_asinc_session = AsyncMock(name="MockAsincSession")
        mock_asinc_session.get = Mock(name="MockSessionGet", return_value=mock_asinc_get)
        mock_client_session.return_value.__aenter__.return_value = mock_asinc_session

        keys = Keys(name=self.test_name, url=self.valid_url)

        self.assertIsNotNone(keys("1"))
        keys._update = 0  # imitation of the end of life
        keys()
        self.assertIsNotNone(keys("2"))
        time.sleep(0.6)
        self.assertIsNotNone(keys("new"))

    @patch("requests.get")
    def test_find_key_by_kid(self, mock_get):
        mock_get.return_value = self._create_mock_response(200, self.keys_data)

        keys = Keys(name=self.test_name, url=self.valid_url)
        result = keys(kid="1")

        self.assertIsInstance(result, Key)
        self.assertEqual(result.kid, "1")

    @patch("requests.get")
    def test_find_nonexistent_kid(self, mock_get):
        mock_get.return_value = self._create_mock_response(200, self.keys_data)

        keys = Keys(name=self.test_name, url=self.valid_url)
        result = keys(kid="nonexistent")

        self.assertIsNone(result)

    @patch("requests.get")
    def test_requests_verify_tls_flag(self, mock_get):
        mock_get.return_value = self._create_mock_response(200, self.keys_data)
        Keys(name=self.test_name, url=self.valid_url, verify_tls=True)
        mock_get.assert_called_with(self.valid_url, verify=True)

        mock_get.reset_mock()
        Keys(name=self.test_name, url=self.valid_url, verify_tls=False)
        mock_get.assert_called_with(self.valid_url, verify=False)

    @patch("aiohttp.ClientSession")
    @patch("requests.get")
    async def test_aiohttp_verify_tls_flag(self, mock_get, mock_client_session):
        mock_get.return_value = self._create_mock_response(200, self.keys_data)

        # Prepare async client session mocks
        mock_asinc_response = AsyncMock(name="MockAsincResponse")
        mock_asinc_response.status = 200
        mock_asinc_response.json.return_value = self.keys_data_new
        mock_asinc_response.raise_for_status = Mock(return_value=None)
        mock_asinc_get = AsyncMock(name="MockAsincGet")
        mock_asinc_get.__aenter__.return_value = mock_asinc_response
        mock_asinc_session = AsyncMock(name="MockAsincSession")
        mock_asinc_session.get = Mock(name="MockSessionGet", return_value=mock_asinc_get)
        mock_client_session.return_value.__aenter__.return_value = mock_asinc_session

        keys = Keys(name=self.test_name, url=self.valid_url, verify_tls=False)
        keys._update = 0
        keys()
        await asyncio.sleep(0)  # yield to event loop
        mock_asinc_session.get.assert_called_with(self.valid_url, ssl=False)

        # Now with verify_tls=True
        keys = Keys(name=self.test_name, url=self.valid_url, verify_tls=True)
        keys._update = 0
        keys()
        await asyncio.sleep(0)
        mock_asinc_session.get.assert_called_with(self.valid_url, ssl=True)


if __name__ == "__main__":
    unittest.main()
