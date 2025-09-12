import logging
import os
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from typing import Union, Optional
from copy import deepcopy

import requests
import aiohttp
from xshl.target import Target
from authlib.jose import JsonWebKey, KeySet, Key

log = logging.getLogger(__name__)
log.setLevel(logging.WARNING if os.getenv("DEBUG", "0") == "0" else logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setFormatter(
    logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
)
log.addHandler(console_handler)

DEFAULT_KEYS_TTL = 60  # Default update times a minute
API_REFERENCE = "/{version}/{source}/{path}{ext}?target={spot}:{entity}@{base}"


class Keys:
    def __init__(self, name: str, url: str, ttl: int = DEFAULT_KEYS_TTL, verify_tls: bool = True):
        self.name = name
        self.url = url
        self._ttl = ttl
        self._verify_tls = bool(verify_tls)
        self._update = 0
        self._task = False
        self._lock = Lock()
        self._executor = ThreadPoolExecutor(max_workers=1)
        self._keys: Optional[KeySet] = None

        self.load()

    async def _load(self):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.url, ssl=self._verify_tls) as response:
                    response.raise_for_status()  # checking API availability
                    json_data = await response.json()
                    with self._lock:
                        self._keys = JsonWebKey.import_key_set(json_data)
                        self._update = time.time()
        except Exception as e:
            log.warning(e)
        finally:
            self._task = False

    def load(self, background: bool = False):
        if background:
            if not self._task:
                self._task = True
                try:
                    asyncio.get_running_loop()
                    asyncio.create_task(self._load())
                except RuntimeError:  # if RuntimeError means the code is synchronous
                    self._executor.submit(asyncio.run, self._load())
        else:
            response = requests.get(self.url, verify=self._verify_tls)
            if response.status_code == 200:
                with self._lock:
                    self._keys = JsonWebKey.import_key_set(response.json())
                    self._update = time.time()
            else:
                response.raise_for_status()

    @property
    def updated(self) -> bool:
        return self._update + self._ttl > time.time()

    @property
    def _data(self) -> KeySet:
        """
        Returns a **KeySet** and self updates keys every "self._ttl" seconds.
        """
        if not self.updated:
            self.load(background=True)
        with self._lock:
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

    def __del__(self):
        try:
            self._executor.shutdown()
        except RuntimeError:
            pass


class ReferenceKeys(Keys):
    def __init__(self, target: Target, trust_url: str, ttl: int = DEFAULT_KEYS_TTL, verify_tls: bool = True):
        super(ReferenceKeys, self).__init__(
            target.entity, trust_url + self.api_path(dict(target)), ttl, verify_tls
        )
        self.target = target

    @staticmethod
    def api_path(item: dict) -> str:
        context = deepcopy(item.get("@context", {}))
        return API_REFERENCE.format(
            version=item.get("@id", "latest"),
            ext=context.pop("ext", ".json"),
            **item, **context
        )
