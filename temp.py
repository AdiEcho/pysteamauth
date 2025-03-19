import json
from pysteamauth.auth import Steam
from pysteamauth.errors import SteamError, custom_error_exception, check_steam_error
from typing import Any, Mapping, Optional, Dict
from pysteamauth.abstract import RequestStrategyAbstract, CookieStorageAbstract
from aiohttp import ClientResponse, ClientSession
from aiohttp.client_exceptions import ClientOSError


class LoginError(SteamError): ...


class RateLimitExceeded(SteamError): ...


custom_error_exception(
    {
        5: LoginError,
        84: RateLimitExceeded,
    }
)


class BaseCookieStorage(CookieStorageAbstract):
    def __init__(self):
        self.cookies: Dict[str, Mapping[str, Mapping[str, str]]] = {}
        with open("cookies.json", "r") as f:
            self.cookies = json.load(f)

    async def set(self, login: str, cookies: Mapping[str, Mapping[str, str]]) -> None:
        self.cookies[login] = cookies
        with open("cookies.json", "w") as f:
            json.dump(self.cookies, f)

    async def get(self, login: str, domain: str) -> Mapping[str, str]:
        cookies = self.cookies.get(login)
        if not cookies:
            return {}
        return cookies.get(domain, {})


class BaseRequestStrategy(RequestStrategyAbstract):
    def __init__(self, proxy: str = None, headers: Mapping[str, str] = None):
        self._session: Optional[ClientSession] = None
        self._proxy = proxy
        self._headers = headers

    def __del__(self):
        if self._session:
            self._session.connector.close()

    def _create_session(self) -> ClientSession:
        """
        Create aiohttp session.
        Aiohttp session saves and stores cookies.
        It writes cookies from responses after each request that specified
        in Set-Cookie header.

        :return: aiohttp.ClientSession object.
        """
        if self._headers:
            return ClientSession(
                # connector=aiohttp.TCPConnector(verify_ssl=False),
                headers=self._headers,
            )
        else:
            return ClientSession(
                # connector=aiohttp.TCPConnector(verify_ssl=False)
            )

    async def request(
        self, url: str, method: str, **kwargs: Any
    ) -> ClientResponse | None:
        err_time = 0
        while True:
            try:
                if self._session is None:
                    self._session = self._create_session()
                if self._proxy:
                    kwargs["proxy"] = self._proxy
                    response = await self._session.request(method, url, **kwargs)
                    if error := response.headers.get("X-eresult"):
                        check_steam_error(int(error))
                    return response
            except ClientOSError as e:
                err_time += 1
                print(f"{method} {url} failed {e}, retrying...")
                if err_time > 5:
                    return None

    def cookies(self, domain: str = "steamcommunity.com") -> Mapping[str, str]:
        if self._session is None:
            self._session = self._create_session()
        cookies = {}
        for cookie in self._session.cookie_jar:
            if cookie["domain"] == domain:
                cookies[cookie.key] = cookie.value
        return cookies

    async def text(self, url: str, method: str, **kwargs: Any) -> str:
        if self._proxy:
            kwargs["proxy"] = self._proxy
        if (res := await self.request(url, method, **kwargs)) is False:
            return ""
        else:
            return await res.text()

    async def bytes(self, url: str, method: str, **kwargs: Any) -> bytes:
        if self._proxy:
            kwargs["proxy"] = self._proxy
        if (res := await self.request(url, method, **kwargs)) is False:
            return b""
        else:
            return await res.read()


async def main():
    try:
        await Steam(
            login="sdxuqytuqe9",
            password="dil050696",
            shared_secret="+YtWh/0001SwdOHLSdhyFTPBlK8=",
            identity_secret="pmvmE3xGqVCojBHnE63c2EJDCEg=",
            device_id="android:4ae31cb7-360c-4215-806f-1b58b8025360",
            request_strategy=BaseRequestStrategy("http://127.0.0.1:7890"),
            cookie_storage=BaseCookieStorage(),
        ).login_to_steam()
    except LoginError as error:
        print(error)


def update_access_token(refresh_token):
    session = requests.Session()
    steam_id = refresh_token.split('%7C%7C')[0]
    refresh = refresh_token.split('%7C%7C')[1]
    post_url = 'https://api.steampowered.com/IAuthenticationService/GenerateAccessTokenForApp/v1/'
    post_data = {'steamid': steam_id, 'refresh_token': refresh}
    response = session.post(post_url, data=post_data, allow_redirects=False, timeout=20)
    while response.status_code == 302:
        response = session.post(response.headers['Location'], data=post_data, allow_redirects=False, timeout=20)
    res = response.json()
    access_token = res['response']['access_token']
    steam_login_secure = str(steam_id) + '%7C%7C' + str(access_token)
    session.cookies.set('steamLoginSecure', steam_login_secure, domain='steamcommunity.com')


if __name__ == "__main__":
    import asyncio
    import requests
    refresh_cookie = "76561199830930361%7C%7CeyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0.eyAiaXNzIjogInN0ZWFtIiwgInN1YiI6ICI3NjU2MTE5OTgzMDkzMDM2MSIsICJhdWQiOiBbICJ3ZWIiLCAicmVuZXciLCAiZGVyaXZlIiBdLCAiZXhwIjogMTc0MzQ2Mjc0MywgIm5iZiI6IDE3MzIyMTE0NzcsICJpYXQiOiAxNzQwODUxNDc3LCAianRpIjogIjAwMDlfMjVFN0Y4MkZfQUNEQzkiLCAib2F0IjogMTc0MDg1MTQ3NywgInBlciI6IDAsICJpcF9zdWJqZWN0IjogIjEwMy4xODkuMjM0LjEyNiIsICJpcF9jb25maXJtZXIiOiAiMTAzLjE4OS4yMzQuMTI2IiB9.4Wp86vDpgI8qA_TyJhCqn3SoshufbpotyaXICnkm3DkKzN8rErjkpoK8J8youeV696c7qFR3n73fgb8MSJknCA"
    update_access_token(refresh_cookie)
    # asyncio.run(main())

