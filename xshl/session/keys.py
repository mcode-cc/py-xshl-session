import time
from typing import Union

import requests
from xshl.target import Target
from authlib.jose import JsonWebKey, KeySet, Key

DEFAULT_KEYS_TTL = 60 * 60  # Default update after 1 hour


class Keys:
    def __init__(self, target: Target, url: str, ttl: int = DEFAULT_KEYS_TTL):
        """
        Keys from API, response must be formate JWK
        Args:
            target: An object of the class "Target" from xshl.target
                - Required: 'spot', 'base', 'entity'
                - Optional: '@context', '@id', '@type'
                Example:
                    {
                        "spot": "auth",
                        "base": "prod",
                        "entity": "service1",
                        "@type": "/reference",
                        "@context": {
                            "source": "text",
                            "path": "/keys",
                            "ext": ".json"
                        }
                    }

            url: API endpoint template with placeholders. Must include host.
                Example:
                    "https://api.example.com/v2/{@id}/{@type}/{path}{ext}?target={spot}:{entity}@{base}"

            ttl: Time-to-live in seconds for cached public keys (refresh frequency)
        """
        if not any(item in ["spot", "base", "entity"] for item in dict(target)):
            raise ValueError("The target is incorrect. Does not contain 1 or more required properties")
        self.target = target
        self.url = url
        self._ttl = ttl
        self.name = target.entity
        self._update = 0
        self._keys = KeySet([])

    @property
    def _data(self) -> KeySet:
        """
        Returns a **KeySet** and self updates keys every "self._ttl" seconds.
        """
        if self._update + self._ttl < time.time():
            contex = self.target["@context"] if "@context" in self.target else {}
            response = requests.get(self.url.format(**dict(self.target), **contex))
            if response.status_code == 200:
                self._keys = JsonWebKey.import_key_set(response.json())
                self._update = time.time()
        return self._keys

    def __call__(self, kid: str = None) -> Union[Key, KeySet]:
        """
        Returns
            - **KeySet** if no kid is specified
            - **Key** object if kid is found
            - **None** if kid is not found
        """
        if kid:
            try:
                result = self._data.find_by_kid(kid)
            except ValueError:
                result = None
        else:
            result = self._data
        return result
