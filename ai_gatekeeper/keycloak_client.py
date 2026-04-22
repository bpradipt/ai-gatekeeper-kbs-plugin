import httpx


class KeycloakClient:
    def __init__(
        self,
        token_url: str,
        client_id: str,
        client_secret: str,
        timeout: int = 10,
    ) -> None:
        self._token_url = token_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._timeout = timeout

    @classmethod
    def from_config(
        cls,
        url: str,
        realm: str,
        client_id: str,
        client_secret: str,
        timeout: int = 10,
    ) -> "KeycloakClient":
        token_url = f"{url}/realms/{realm}/protocol/openid-connect/token"
        return cls(token_url, client_id, client_secret, timeout)

    async def get_token(self, scope: str) -> str:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            r = await client.post(
                self._token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "scope": scope,
                },
            )
            r.raise_for_status()
            return r.json()["access_token"]
