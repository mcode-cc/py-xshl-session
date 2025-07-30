import time
from typing import Union
import asyncio
import aiohttp

import requests
from xshl.target import Target
from authlib.jose import JsonWebKey, KeySet, Key

DEFAULT_KEYS_TTL = 60  # Default update times a minute
API_REFERENCE = "/{version}/{source}/{path}{ext}?target={spot}:{entity}@{base}"


async def fetch(url, session):
    async with session.get(url) as response:
        return url, await response.text()


async def loader_reference(links):
    async with aiohttp.ClientSession() as session:
        results = []
        for link in links:
            results.append(fetch(link, session))
        return await asyncio.gather(*results)


class Keys:
    def __init__(self, name: str, url: str, ttl: int = DEFAULT_KEYS_TTL):
        self.name = name
        self.url = url
        self._ttl = ttl
        self._update = 0
        self._keys = KeySet([])
        self.load()

    def load(self, background: bool = False):
        if background:
            pass  # asyncio.run(loader_reference(urls))
        else:
            response = requests.get(self.url)
            if response.status_code == 200:
                self._keys = JsonWebKey.import_key_set(response.json())
                self._update = time.time()

    @property
    def update(self) -> bool:
        return self._update + self._ttl < time.time()

    @property
    def _data(self) -> KeySet:
        """
        Returns a **KeySet** and self updates keys every "self._ttl" seconds.
        """
        if self.update:
            self.load(background=True)
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


class ReferenceKeys(Keys):
    def __init__(self, target: Target, url: str, ttl: int = DEFAULT_KEYS_TTL):
        super(ReferenceKeys, self).__init__(target.entity, url + self.api_path(dict(target)), ttl)
        self.target = target

    def api_path(self, item: dict) -> str:
        return API_REFERENCE.format(
            version=item.get("@id", "latest"),
            ext=item.get("@context", {}).pop("ext", ".json"),
            **item, **item.get("@context", {})
        )
