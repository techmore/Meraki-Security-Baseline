import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

DEFAULT_API_BASE = "https://api.meraki.com/api/v1"
DEFAULT_REQUEST_TIMEOUT = 30
DEFAULT_MAX_RETRIES = 5


@dataclass(frozen=True)
class MerakiClientConfig:
    """Runtime settings for one Meraki API collection process."""

    api_base: str = DEFAULT_API_BASE
    request_timeout: int = DEFAULT_REQUEST_TIMEOUT
    max_retries: int = DEFAULT_MAX_RETRIES

    @classmethod
    def from_environment(cls) -> "MerakiClientConfig":
        def read_int(name: str, default: int) -> int:
            try:
                return int(os.getenv(name, str(default)))
            except (TypeError, ValueError):
                return default

        return cls(
            api_base=os.getenv("MERAKI_API_BASE", DEFAULT_API_BASE),
            request_timeout=read_int("MERAKI_REQUEST_TIMEOUT", DEFAULT_REQUEST_TIMEOUT),
            max_retries=read_int("MERAKI_MAX_RETRIES", DEFAULT_MAX_RETRIES),
        )


# Do not read environment configuration at import time. The backup entrypoint
# loads .env first, then calls configure_from_env() to freeze one run's policy.
_CONFIG: Optional[MerakiClientConfig] = None


def configure_from_env() -> MerakiClientConfig:
    """Load current environment values for the next API calls."""
    global _CONFIG
    _CONFIG = MerakiClientConfig.from_environment()
    return _CONFIG


def _active_config(config: Optional[MerakiClientConfig] = None) -> MerakiClientConfig:
    return config or _CONFIG or MerakiClientConfig.from_environment()


class MerakiRequestError(RuntimeError):
    """Structured request failure so callers can react to status and headers."""

    def __init__(
        self,
        message: str,
        status: Optional[int] = None,
        body: str = "",
        headers: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.body = body
        self.headers = headers or {}


def build_url(
    path: str,
    params: Optional[Dict[str, Any]] = None,
    config: Optional[MerakiClientConfig] = None,
) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        return path
    url = f"{_active_config(config).api_base}{path}"
    if params:
        url = f"{url}?{urllib.parse.urlencode(params, doseq=True)}"
    return url


def request(method: str, url: str, api_key: str) -> urllib.request.Request:
    return urllib.request.Request(
        url,
        method=method,
        headers={
            "X-Cisco-Meraki-API-Key": api_key,
            "Accept": "application/json",
        },
    )


def get_json(
    url: str,
    api_key: str,
    timeout: Optional[int] = None,
    config: Optional[MerakiClientConfig] = None,
) -> Dict[str, Any]:
    req = request("GET", url, api_key)
    client_config = _active_config(config)
    try:
        effective_timeout = timeout if timeout is not None else client_config.request_timeout
        with urllib.request.urlopen(req, timeout=effective_timeout) as resp:
            data = resp.read().decode("utf-8")
            return {
                "data": json.loads(data) if data else None,
                "headers": dict(resp.headers),
                "status": resp.status,
            }
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8") if e.fp else ""
        raise MerakiRequestError(
            f"HTTP {e.code} for {url}: {body}",
            status=e.code,
            body=body,
            headers=dict(e.headers),
        )
    except urllib.error.URLError as e:
        raise MerakiRequestError(f"Network error for {url}: {e}")


def parse_link_header(link: Optional[str]) -> Dict[str, str]:
    if not link:
        return {}
    links = {}
    for part in [p.strip() for p in link.split(",")]:
        if ";" not in part:
            continue
        url_part, rel_part = part.split(";", 1)
        url = url_part.strip()[1:-1]
        rel = rel_part.strip().split("=")[1].strip('"')
        links[rel] = url
    return links


def paged_get(
    path: str,
    api_key: str,
    params: Optional[Dict[str, Any]] = None,
    per_page_default: int = 500,
    max_retries: Optional[int] = None,
    courtesy_delay: float = 0.2,
    config: Optional[MerakiClientConfig] = None,
) -> List[Any]:
    client_config = _active_config(config)
    params = params or {}
    params.setdefault("perPage", per_page_default)
    url: Optional[str] = build_url(path, params, config=client_config)
    all_items: List[Any] = []
    retry_count = 0
    retry_limit = client_config.max_retries if max_retries is None else max_retries

    while url:
        try:
            if config is None:
                # Keep the normal call shape compatible with lightweight test
                # doubles and callers that wrap get_json().
                resp = get_json(url, api_key)
            else:
                resp = get_json(url, api_key, config=client_config)
            retry_count = 0
        except MerakiRequestError as e:
            if e.status == 429 and retry_count < retry_limit:
                retry_after_header = e.headers.get("Retry-After")
                try:
                    retry_after = int(str(retry_after_header))
                except (TypeError, ValueError):
                    retry_after = 2
                time.sleep(retry_after * (2 ** retry_count))
                retry_count += 1
                continue
            raise

        data = resp["data"]
        if isinstance(data, list):
            all_items.extend(data)
        elif data is not None:
            all_items.append(data)

        links = parse_link_header(resp["headers"].get("Link"))
        url = links.get("next")
        time.sleep(courtesy_delay)

    return all_items


def get_one(
    path: str,
    api_key: str,
    params: Optional[Dict[str, Any]] = None,
    config: Optional[MerakiClientConfig] = None,
) -> Any:
    client_config = _active_config(config)
    url = build_url(path, params, config=client_config)
    if config is None:
        return get_json(url, api_key)["data"]
    return get_json(url, api_key, config=client_config)["data"]
