from abc import (
    ABC,
    abstractmethod,
)
from typing import (
    Any,
    Mapping,
)

from aiohttp import ClientResponse
from aiohttp.typedefs import LooseCookies
from yarl import URL


class RequestStrategyAbstract(ABC):
    @abstractmethod
    async def request(self, url: str, method: str, **kwargs: Any) -> ClientResponse:
        ...

    @abstractmethod
    def cookies(self, domain: str = "steamcommunity.com") -> Mapping[str, str]:
        ...

    @abstractmethod
    async def close(self) -> None:
        ...

    @abstractmethod
    def update_cookies(self, cookies: LooseCookies, response_url: URL = URL()) -> None:
        ...
