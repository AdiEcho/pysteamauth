import base64
import binascii
import hashlib
import hmac
import json
import math
import time
from struct import pack
from typing import (
    Any,
    Mapping,
    Optional,
)
import rsa
from aiohttp import FormData
from bitstring import BitArray
from urllib3.util import parse_url

from pysteamauth.abstract import (
    CookieStorageAbstract,
    RequestStrategyAbstract,
)
from pysteamauth.base import (
    BaseCookieStorage,
    BaseRequestStrategy,
)
from pysteamauth.pb2.enums_pb2 import ESessionPersistence
from pysteamauth.pb2.steammessages_auth.steamclient_pb2 import (
    CAuthentication_AllowedConfirmation,
    CAuthentication_BeginAuthSessionViaCredentials_Request,
    CAuthentication_BeginAuthSessionViaCredentials_Response,
    CAuthentication_GetPasswordRSAPublicKey_Request,
    CAuthentication_GetPasswordRSAPublicKey_Response,
    CAuthentication_PollAuthSessionStatus_Request,
    CAuthentication_PollAuthSessionStatus_Response,
    CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request,
    EAuthSessionGuardType,
    EAuthTokenPlatformType,
)
from yarl import URL
from .schemas import FinalizeLoginStatus


def base64url_decode(base64_str):
    size = len(base64_str) % 4
    if size == 2:
        base64_str += "=="
    elif size == 3:
        base64_str += "="
    elif size != 0:
        raise ValueError("Invalid base64 string")
    return base64.urlsafe_b64decode(base64_str.encode("utf-8"))


def parse_jwt(jwt_token):
    jwt_token_list = jwt_token.split(".")
    header = base64url_decode(jwt_token_list[0]).decode()
    payload = base64url_decode(jwt_token_list[1]).decode()
    return {
        "header": json.loads(header),
        "payload": json.loads(payload),
        "signature": jwt_token_list[-1],
    }


class Steam:
    def __init__(
        self,
        login: str,
        password: str,
        steamid: Optional[int] = None,
        shared_secret: Optional[str] = None,
        identity_secret: Optional[str] = None,
        device_id: Optional[str] = None,
        cookie_storage: Optional[CookieStorageAbstract] = None,
        request_strategy: Optional[RequestStrategyAbstract] = None,
    ):
        self._login = login
        self._steamid = steamid
        self._password = password
        self._shared_secret = shared_secret
        self._identity_secret = identity_secret
        self._device_id = device_id
        self._requests = (
            request_strategy if request_strategy is not None else BaseRequestStrategy()
        )
        self._storage = (
            cookie_storage if cookie_storage is not None else BaseCookieStorage()
        )

    @property
    def steamid(self) -> int:
        if not self._steamid:
            raise ValueError("steamid is not specified")
        return self._steamid

    @property
    def shared_secret(self) -> str:
        if not self._shared_secret:
            raise ValueError("shared_secret is not specified")
        return self._shared_secret

    @property
    def identity_secret(self) -> str:
        if not self._identity_secret:
            raise ValueError("identity_secret is not specified")
        return self._identity_secret

    @property
    def device_id(self) -> str:
        if not self._device_id:
            raise ValueError("device_id is not specified")
        return self._device_id

    @property
    def login(self) -> str:
        return self._login

    @property
    def partner_id(self) -> int:
        return self.steamid - 76561197960265728

    async def cookies(self, domain: str = "steamcommunity.com") -> Mapping[str, str]:
        return await self._storage.get(
            login=self._login,
            domain=domain,
        )

    async def sessionid(self, domain: str = "steamcommunity.com") -> str:
        return (await self.cookies(domain))["sessionid"]

    async def get_refresh_token(self):
        login_steam_cookie = await self.cookies("login.steampowered.com")
        steam_refresh_steam = login_steam_cookie.get("steamRefresh_steam")
        if not steam_refresh_steam:
            return None, None
        sp = steam_refresh_steam.split("%7C%7C")
        steam_id, refresh_token = sp[0], sp[1]
        return steam_id, refresh_token

    async def request(self, url: str, method: str = "GET", **kwargs: Any) -> str:
        cookies = await self._storage.get(
            login=self._login,
            domain=parse_url(url).host,
        )
        return await self._requests.text(
            url=url,
            method=method,
            cookies={
                **cookies,
                **kwargs.pop("cookies", {}),
            },
            **kwargs,
        )

    async def is_authorized(self) -> bool:
        response: str = await self.request(
            url="https://steamcommunity.com/chat/clientjstoken",
        )
        data = json.loads(response)
        logged_in = data["logged_in"]
        if logged_in:
            if not self._steamid:
                try:
                    self._steamid = int(data["steamid"])
                except KeyError:
                    ...
        return logged_in

    async def _getrsakey(self) -> CAuthentication_GetPasswordRSAPublicKey_Response:
        message = CAuthentication_GetPasswordRSAPublicKey_Request(
            account_name=self._login,
        )
        response = await self._requests.bytes(
            method="GET",
            url="https://api.steampowered.com/IAuthenticationService/GetPasswordRSAPublicKey/v1",
            params={
                "input_protobuf_encoded": str(
                    base64.b64encode(message.SerializeToString()), "utf8"
                ),
            },
        )
        return CAuthentication_GetPasswordRSAPublicKey_Response.FromString(response)

    async def _begin_auth_session(
        self,
        encrypted_password: str,
        rsa_timestamp: int,
    ) -> CAuthentication_BeginAuthSessionViaCredentials_Response:
        message = CAuthentication_BeginAuthSessionViaCredentials_Request(
            account_name=self._login,
            encrypted_password=encrypted_password,
            encryption_timestamp=rsa_timestamp,
            remember_login=True,
            platform_type=EAuthTokenPlatformType.k_EAuthTokenPlatformType_MobileApp,
            website_id="Community",
            persistence=ESessionPersistence.k_ESessionPersistence_Persistent,
            device_friendly_name="Mozilla/5.0 (X11; Linux x86_64; rv:1.9.5.20) Gecko/2812-12-10 04:56:28 Firefox/3.8",
        )
        response = await self._requests.bytes(
            method="POST",
            url="https://api.steampowered.com/IAuthenticationService/BeginAuthSessionViaCredentials/v1",
            data=FormData(
                fields=[
                    (
                        "input_protobuf_encoded",
                        str(base64.b64encode(message.SerializeToString()), "utf8"),
                    ),
                ],
            ),
        )
        return CAuthentication_BeginAuthSessionViaCredentials_Response.FromString(
            response
        )

    async def get_server_time(self) -> int:
        response = await self._requests.text(
            method="POST",
            url="https://api.steampowered.com/ITwoFactorService/QueryTime/v0001",
        )
        data = json.loads(response)
        return int(data["response"]["server_time"])

    @classmethod
    async def get_steam_guard(cls, shared_secret: str, server_time: int) -> str:
        data = binascii.unhexlify(
            hmac.new(
                key=base64.b64decode(shared_secret),
                msg=pack("!L", 0) + pack("!L", math.floor(server_time // 30)),
                digestmod=hashlib.sha1,
            ).hexdigest(),
        )

        value = data[19] & 0xF
        full_code = (
            (data[value] & 0x7F) << 24  # noqa:W504
            | (data[value + 1] & 0xFF) << 16  # noqa:W504
            | (data[value + 2] & 0xFF) << 8  # noqa:W504
            | (data[value + 3] & 0xFF)
        )

        code = ""
        chars = "23456789BCDFGHJKMNPQRTVWXY"
        for _ in range(5):
            code += chars[full_code % len(chars)]
            full_code //= len(chars)

        return code

    def get_confirmation_hash(self, server_time: int, tag: str = "conf") -> str:
        identitysecret = base64.b64decode(
            self.identity_secret,
        )
        secret = BitArray(
            bytes=identitysecret,
            length=len(identitysecret) * 8,
        )
        tag_buffer = BitArray(
            bytes=tag.encode("utf8"),
            length=len(tag) * 8,
        )
        buffer = BitArray(4 * 8)
        buffer.append(BitArray(int=server_time, length=32))
        buffer.append(tag_buffer)
        confirmation = hmac.new(
            key=secret.tobytes(),
            msg=buffer.tobytes(),
            digestmod=hashlib.sha1,
        )
        return str(base64.b64encode(confirmation.digest()), "utf8")

    def _encrypt_password(
        self, keys: CAuthentication_GetPasswordRSAPublicKey_Response
    ) -> str:
        publickey_exp = int(keys.publickey_exp, 16)  # type:ignore
        publickey_mod = int(keys.publickey_mod, 16)  # type:ignore
        public_key = rsa.PublicKey(
            n=publickey_mod,
            e=publickey_exp,
        )
        encrypted_password = rsa.encrypt(
            message=self._password.encode("ascii"),
            pub_key=public_key,
        )
        return str(base64.b64encode(encrypted_password), "utf8")

    async def _update_auth_session(
        self,
        client_id: int,
        steamid: int,
        code: str,
        code_type: int,
    ) -> None:
        message = CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request(
            client_id=client_id,
            steamid=steamid,
            code=code,
            code_type=code_type,
        )
        await self._requests.request(
            method="POST",
            url="https://api.steampowered.com/IAuthenticationService/UpdateAuthSessionWithSteamGuardCode/v1",
            data=FormData(
                fields=[
                    (
                        "input_protobuf_encoded",
                        str(base64.b64encode(message.SerializeToString()), "utf8"),
                    ),
                ],
            ),
        )

    async def _poll_auth_session_status(
        self,
        client_id: int,
        request_id: bytes,
    ) -> CAuthentication_PollAuthSessionStatus_Response:
        message = CAuthentication_PollAuthSessionStatus_Request(
            client_id=client_id,
            request_id=request_id,
        )
        response = await self._requests.bytes(
            method="POST",
            url="https://api.steampowered.com/IAuthenticationService/PollAuthSessionStatus/v1",
            data=FormData(
                fields=[
                    (
                        "input_protobuf_encoded",
                        str(base64.b64encode(message.SerializeToString()), "utf8"),
                    ),
                ],
            ),
        )
        return CAuthentication_PollAuthSessionStatus_Response.FromString(response)

    async def _finalize_login(
        self, refresh_token: str, sessionid: str
    ) -> FinalizeLoginStatus:
        response = await self._requests.text(
            method="POST",
            url="https://login.steampowered.com/jwt/finalizelogin",
            data=FormData(
                fields=[
                    ("nonce", refresh_token),
                    ("sessionid", sessionid),
                    ("redir", "https://steamcommunity.com/login/home/?goto="),
                ],
            ),
            headers={"Origin": "https://steamcommunity.com"},
        )
        return FinalizeLoginStatus.model_validate_json(response)

    async def _set_token(self, url: str, nonce: str, auth: str, steamid: int) -> None:
        await self._requests.request(
            method="POST",
            url=url,
            data=FormData(
                fields=[
                    ("nonce", nonce),
                    ("auth", auth),
                    ("steamID", str(steamid)),
                ],
            ),
        )

    @staticmethod
    def _is_twofactor_required(
        confirmation: CAuthentication_AllowedConfirmation,
    ) -> bool:
        return (
            confirmation.confirmation_type
            == EAuthSessionGuardType.k_EAuthSessionGuardType_DeviceCode
        )

    async def login_to_steam(self, code: str) -> None:
        # 如果已经授权（已经登录），直接退出
        if await self.is_authorized():
            return
        steam_id, refresh_token = await self.get_refresh_token()
        if steam_id and refresh_token:
            try:
                decoded_token = parse_jwt(refresh_token)
                if time.time() > decoded_token["payload"]["exp"]:
                    raise Exception("Refresh token expired")
                url = "https://api.steampowered.com/IAuthenticationService/GenerateAccessTokenForApp/v1"
                headers = {
                    "Origin": "https://steamcommunity.com",
                    "Referer": "https://steamcommunity.com/",
                }
                res = await self._requests.request(
                    method="POST",
                    url=url,
                    data=FormData(
                        fields=[
                            ("steamid", steam_id),
                            ("refresh_token", refresh_token),
                        ],
                    ),
                    headers=headers,
                )
                resp_json = await res.json()
                if "response" in resp_json and "access_token" in resp_json["response"]:
                    access_token = resp_json["response"]["access_token"]
                    steam_login_secure = steam_id + "%7C%7C" + access_token
                    for domain_name in [
                        "steamcommunity.com",
                        "store.steampowered.com",
                        "help.steampowered.com",
                    ]:
                        self._requests._session.cookie_jar.update_cookies(
                            {
                                "sessionid": (
                                    await self._storage.get(
                                        login=self._login, domain=domain_name
                                    )
                                ).get("sessionid"),
                                "steamLoginSecure": steam_login_secure,
                            },
                            response_url=URL(f"https://{domain_name}/"),
                        )
                    self._steamid = int(steam_id)
                    await self._save_cookies()
                return
            except Exception as e:
                print(f"login with refresh token error: {e}")
                pass

        # 如果没有有效的 refresh_token，执行正常的登录流程
        if not self._requests.cookies().get("sessionid"):
            await self._requests.bytes(
                method="GET",
                url="https://steamcommunity.com",
            )
        keys = await self._getrsakey()
        encrypted_password = self._encrypt_password(keys)
        auth_session = await self._begin_auth_session(
            encrypted_password=encrypted_password,
            rsa_timestamp=keys.timestamp,
        )
        if auth_session.allowed_confirmations:
            if self._is_twofactor_required(auth_session.allowed_confirmations[0]):
                if not code:
                    server_time = await self.get_server_time()
                    code = await Steam.get_steam_guard(self.shared_secret, server_time)
                await self._update_auth_session(
                    client_id=auth_session.client_id,
                    steamid=auth_session.steamid,
                    code=code,
                    code_type=EAuthSessionGuardType.k_EAuthSessionGuardType_DeviceCode,
                )
        session = await self._poll_auth_session_status(
            client_id=auth_session.client_id,
            request_id=auth_session.request_id,
        )
        tokens = await self._finalize_login(
            refresh_token=session.refresh_token,
            sessionid=self._requests.cookies()["sessionid"],
        )
        for token in tokens.transfer_info:
            await self._set_token(
                url=token.url,
                nonce=token.params.nonce,
                auth=token.params.auth,
                steamid=auth_session.steamid,
            )
        if not self._steamid and tokens.steamID:
            self._steamid = int(tokens.steamID)
        await self._save_cookies()

    async def _save_cookies(self):
        cookies = self._storage.cookies.get(self._login, {})
        for url in ("https://store.steampowered.com", "https://help.steampowered.com"):
            await self._requests.bytes(url, "GET")

        for morsel in self._requests._session.cookie_jar:
            if morsel["domain"] in cookies:
                cookies[morsel["domain"]][morsel.key] = morsel.value
            else:
                cookies[morsel["domain"]] = {morsel.key: morsel.value}

        await self._storage.set(login=self._login, cookies=cookies)
