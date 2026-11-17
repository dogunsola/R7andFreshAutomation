import json
import ssl
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen


class ApiError(RuntimeError):
    pass


MAX_RESPONSE_BYTES = 250 * 1024 * 1024


class HttpClient:
    def __init__(
        self,
        headers: dict[str, str] | None = None,
        retries: int = 5,
        allowed_hosts: set[str] | None = None,
    ) -> None:
        self.headers = headers or {}
        self.retries = retries
        self.allowed_hosts = allowed_hosts

        self.ssl_context = ssl.create_default_context()
        self.ssl_context.minimum_version = (
            ssl.TLSVersion.TLSv1_2
        )

    def request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout: int = 120,
        retryable: bool = True,
    ) -> Any:
        if params:
            url = (
                f"{url}?"
                f"{urlencode(params)}"
            )

        self._validate_url(
            url
        )

        request_headers = {
            **self.headers,
            **(
                headers
                or {}
            ),
        }

        if json_body is not None:
            body = json.dumps(
                json_body
            ).encode(
                "utf-8"
            )

            request_headers[
                "Content-Type"
            ] = "application/json"

        request = Request(
            url,
            data=body,
            headers=request_headers,
            method=method,
        )

        max_retries = (
            self.retries
            if retryable
            else 0
        )

        for attempt in range(
            max_retries + 1
        ):
            try:
                with urlopen(
                    request,
                    timeout=timeout,
                    context=self.ssl_context,
                ) as response:
                    raw = response.read(
                        MAX_RESPONSE_BYTES + 1
                    )

                if len(raw) > MAX_RESPONSE_BYTES:
                    raise ApiError(
                        f"{url} returned more than "
                        f"{MAX_RESPONSE_BYTES} bytes"
                    )

                try:
                    return json.loads(
                        raw
                    )

                except json.JSONDecodeError as exc:
                    raise ApiError(
                        f"{url} returned invalid JSON"
                    ) from exc

            except HTTPError as exc:
                response_body = (
                    exc.read()
                    .decode(
                        "utf-8",
                        errors="replace",
                    )[:1000]
                )

                if (
                    exc.code
                    not in {
                        429,
                        500,
                        502,
                        503,
                        504,
                    }
                    or attempt >= max_retries
                ):
                    raise ApiError(
                        f"{method} {url} returned "
                        f"{exc.code}: {response_body}"
                    ) from exc

                retry_after = (
                    exc.headers.get(
                        "Retry-After"
                    )
                )

                if retry_after:
                    try:
                        delay = min(
                            max(
                                float(
                                    retry_after
                                ),
                                0,
                            ),
                            60,
                        )
                    except ValueError:
                        delay = min(
                            2 ** attempt,
                            60,
                        )
                else:
                    delay = min(
                        2 ** attempt,
                        60,
                    )

            except TimeoutError as exc:
                if attempt >= max_retries:
                    raise ApiError(
                        f"{method} {url} timed out "
                        f"after {timeout} seconds "
                        f"and {attempt + 1} attempts"
                    ) from exc

                delay = min(
                    2 ** attempt,
                    60,
                )

            except URLError as exc:
                if attempt >= max_retries:
                    raise ApiError(
                        f"{method} {url} failed: "
                        f"{exc.reason}"
                    ) from exc

                delay = min(
                    2 ** attempt,
                    60,
                )

            time.sleep(
                delay
            )

        raise AssertionError(
            "unreachable"
        )

    def _validate_url(
        self,
        url: str,
    ) -> None:
        parsed = urlparse(
            url
        )

        if parsed.scheme != "https":
            raise ApiError(
                "Refusing non-HTTPS API request"
            )

        if not parsed.hostname:
            raise ApiError(
                "Refusing API request without a hostname"
            )

        if (
            self.allowed_hosts is not None
            and parsed.hostname
            not in self.allowed_hosts
        ):
            raise ApiError(
                "Refusing API request to unexpected host: "
                f"{parsed.hostname}"
            )