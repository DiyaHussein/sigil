"""Weather MCP server - one upstream, allow-listed, OAuth for user identity."""

import httpx
from urllib.parse import urlparse

ALLOWED_HOSTS = {"api.open-meteo.com"}
OAUTH_DISCOVERY = "/.well-known/oauth-authorization-server"


def validate_url(url: str) -> str:
    host = urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        raise ValueError(f"host not allowed: {host}")
    return url


@mcp.tool(scopes=["read"])
async def get_forecast(city: str) -> str:
    """Return the 5-day forecast for a named city."""
    url = validate_url(f"https://api.open-meteo.com/v1/forecast?name={city}")
    async with httpx.AsyncClient() as client:
        return (await client.get(url)).text
