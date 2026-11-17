import json
import logging
import ssl
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen


LOG = logging.getLogger(__name__)


class ApiError(RuntimeError):
    pass


MAX_RESPONSE_BYTES = 250 * 1024 * 1024
MAX_RETRY_DELAY_SECONDS = 60


class HttpClient:
    def __init__(
        self,
        headers: dict[str, str] | None = None,
        retries: int = 5,
        allowed_hosts: set[str] | None = None,
    ) -> None:
        if (
            isinstance(retries, bool)
            or not isinstance(retries, int)
            or retries < 0
        ):
            raise ValueError(
                "HTTP retry count must be a non-negative integer"
            )

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
        retries: int | None = None,
    ) -> Any:
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, int)
            or timeout <= 0
        ):
            raise ValueError(
                "HTTP timeout must be a positive integer"
            )

        if (
            retries is not None
            and (
                isinstance(retries, bool)
                or not isinstance(retries, int)
                or retries < 0
            )
        ):
            raise ValueError(
                "HTTP retry count must be a non-negative integer"
            )

        if params:
            query_string = urlencode(
                params
            )

            separator = (
                "&"
                if "?" in url
                else "?"
            )

            url = (
                f"{url}"
                f"{separator}"
                f"{query_string}"
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
            if body is not None:
                raise ValueError(
                    "Specify either json_body or body, not both"
                )

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

        if not retryable:
            max_retries = 0
        elif retries is not None:
            max_retries = retries
        else:
            max_retries = self.retries

        total_attempts = (
            max_retries + 1
        )

        for attempt in range(
            total_attempts
        ):
            attempt_number = (
                attempt + 1
            )

            started = time.monotonic()

            try:
                with urlopen(
                    request,
                    timeout=timeout,
                    context=self.ssl_context,
                ) as response:
                    raw = response.read(
                        MAX_RESPONSE_BYTES + 1
                    )

                duration = (
                    time.monotonic()
                    - started
                )

                LOG.debug(
                    "%s request completed in %.2f seconds "
                    "on attempt %s/%s",
                    method,
                    duration,
                    attempt_number,
                    total_attempts,
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
                duration = (
                    time.monotonic()
                    - started
                )

                response_body = (
                    exc.read()
                    .decode(
                        "utf-8",
                        errors="replace",
                    )[:1000]
                )

                retryable_status = (
                    exc.code
                    in {
                        429,
                        500,
                        502,
                        503,
                        504,
                    }
                )

                if (
                    not retryable_status
                    or attempt >= max_retries
                ):
                    raise ApiError(
                        f"{method} {url} returned "
                        f"{exc.code} after "
                        f"{duration:.2f} seconds: "
                        f"{response_body}"
                    ) from exc

                delay = self._retry_delay(
                    attempt,
                    exc.headers.get(
                        "Retry-After"
                    ),
                )

                LOG.warning(
                    "%s request returned HTTP %s after "
                    "%.2f seconds on attempt %s/%s. "
                    "Retrying in %.1f seconds.",
                    method,
                    exc.code,
                    duration,
                    attempt_number,
                    total_attempts,
                    delay,
                )

            except TimeoutError as exc:
                duration = (
                    time.monotonic()
                    - started
                )

                if attempt >= max_retries:
                    raise ApiError(
                        f"{method} {url} timed out after "
                        f"{duration:.2f} seconds on attempt "
                        f"{attempt_number}/{total_attempts}"
                    ) from exc

                delay = self._retry_delay(
                    attempt
                )

                LOG.warning(
                    "%s request timed out after %.2f seconds "
                    "on attempt %s/%s. Retrying in "
                    "%.1f seconds.",
                    method,
                    duration,
                    attempt_number,
                    total_attempts,
                    delay,
                )

            except URLError as exc:
                duration = (
                    time.monotonic()
                    - started
                )

                if attempt >= max_retries:
                    raise ApiError(
                        f"{method} {url} failed after "
                        f"{duration:.2f} seconds on attempt "
                        f"{attempt_number}/{total_attempts}: "
                        f"{exc.reason}"
                    ) from exc

                delay = self._retry_delay(
                    attempt
                )

                LOG.warning(
                    "%s request failed after %.2f seconds "
                    "on attempt %s/%s: %s. Retrying in "
                    "%.1f seconds.",
                    method,
                    duration,
                    attempt_number,
                    total_attempts,
                    exc.reason,
                    delay,
                )

            time.sleep(
                delay
            )

        raise AssertionError(
            "unreachable"
        )

    @staticmethod
    def _retry_delay(
        attempt: int,
        retry_after: str | None = None,
    ) -> float:
        if retry_after:
            try:
                return min(
                    max(
                        float(
                            retry_after
                        ),
                        0,
                    ),
                    MAX_RETRY_DELAY_SECONDS,
                )
            except ValueError:
                pass

        return float(
            min(
                2 ** attempt,
                MAX_RETRY_DELAY_SECONDS,
            )
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