import http.client
import json
import logging
import socket
import urllib.parse
from dataclasses import dataclass
from typing import Any

from nfc.tag import tt3
from nfc.tag.tt3_sony import FelicaStandard

log = logging.getLogger(__name__)


class FelicaRemoteClientError(Exception):
    """Raised for client-side transport or validation issues."""


def _extract_error_from_payload(
    data: bytes, default_reason: str
) -> tuple[str, int | None]:
    try:
        payload = json.loads(data.decode("utf-8") or "{}")
    except json.JSONDecodeError:
        return default_reason, None
    error = payload.get("error", {})
    message = error.get("message", default_reason)
    errno = error.get("code")
    return message, errno


def _to_json_bytes(payload: Any) -> bytes:
    return json.dumps(payload).encode("utf-8")


class _KeepAliveHTTPClient:
    """Maintain a reusable HTTP(S) connection to the auth server."""

    def __init__(self, base_url: str) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Authentication server URL must use HTTP or HTTPS.")
        if not parsed.hostname:
            raise ValueError("Authentication server URL missing hostname.")

        self._scheme = parsed.scheme.lower()
        self._hostname = parsed.hostname
        self._port = parsed.port
        self._netloc = parsed.netloc
        self._path_prefix = parsed.path.rstrip("/")
        self._connection: http.client.HTTPConnection | None = None
        self._base_url_for_log = urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, self._path_prefix, "", "")
        ).rstrip("/")
        if not self._base_url_for_log:
            self._base_url_for_log = f"{parsed.scheme}://{parsed.netloc}"

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def post(self, path: str, payload: dict[str, Any], timeout: float) -> bytes:
        if not path.startswith("/"):
            raise ValueError("Request path must start with '/'.")
        body = _to_json_bytes(payload)
        log.debug(
            "POST %s%s keys=%s",
            self._base_url_for_log,
            path,
            list(payload.keys()),
        )
        request_path = f"{self._path_prefix}{path}" if self._path_prefix else path
        headers = {
            "Content-Type": "application/json",
            "Connection": "keep-alive",
        }
        last_error: Exception | None = None
        for attempt in range(2):
            connection = self._ensure_connection(timeout)
            try:
                connection.request("POST", request_path, body=body, headers=headers)
                response = connection.getresponse()
                data = response.read()
            except (http.client.HTTPException, OSError, socket.timeout) as exc:
                last_error = exc
                self.close()
                continue

            if response.status >= 400:
                message, errno = _extract_error_from_payload(data, response.reason)
                if errno is not None:
                    raise tt3.Type3TagCommandError(errno)
                raise FelicaRemoteClientError(
                    f"{response.status} {response.reason}: {message}"
                )
            return data

        if last_error is None:
            raise FelicaRemoteClientError("failed to reach server: unknown error")

        if isinstance(last_error, socket.timeout):
            reason = "timed out"
        else:
            reason = getattr(last_error, "strerror", None) or str(last_error)
        raise FelicaRemoteClientError(
            f"failed to reach server: {reason}"
        ) from last_error

    def _ensure_connection(self, timeout: float) -> http.client.HTTPConnection:
        if self._connection is None:
            self._connection = self._create_connection(timeout)
        else:
            self._connection.timeout = timeout
        return self._connection

    def _create_connection(self, timeout: float) -> http.client.HTTPConnection:
        if self._scheme == "https":
            return http.client.HTTPSConnection(
                self._hostname, self._port, timeout=timeout
            )
        return http.client.HTTPConnection(self._hostname, self._port, timeout=timeout)


@dataclass
class _CommandEnvelope:
    frame: bytes
    timeout: float | None


class FelicaRemoteClient:
    """Coordinate card I/O with the remote crypto server."""

    def __init__(
        self,
        server_url: str,
        tag: FelicaStandard,
        *,
        session_id: str | None = None,
        http_timeout: float = 10.0,
        default_exchange_timeout: float = 1.0,
    ) -> None:
        trimmed_url = server_url.rstrip("/") or server_url
        self.server_url = trimmed_url
        self.tag = tag
        self.session_id = session_id
        self.http_timeout = http_timeout
        self.default_exchange_timeout = default_exchange_timeout
        self.authenticated = False
        try:
            self._http_client = _KeepAliveHTTPClient(self.server_url)
        except ValueError as exc:
            raise FelicaRemoteClientError(str(exc)) from exc

    @property
    def idm(self) -> bytes:
        return bytes(self.tag.idm)

    @property
    def pmm(self) -> bytes:
        return bytes(self.tag.pmm)

    def mutual_authentication(
        self,
        system_code: int,
        areas: list[int],
        services: list[int],
    ) -> dict[str, Any]:
        """Perform a remote mutual authentication sequence."""
        request_payload: dict[str, Any] = {
            "session_id": self.session_id,
            "idm": self.idm.hex(),
            "pmm": self.pmm.hex(),
            "system_code": system_code,
            "areas": areas,
            "services": services,
        }

        response = self._post("/mutual-authentication", request_payload)
        self._update_session_id(response)

        while True:
            step = response.get("step")
            if step in ("auth1", "auth2"):
                command = self._extract_command(response)
                card_response = self._exchange_with_card(command)
                response = self._post(
                    "/mutual-authentication",
                    {
                        "session_id": self.session_id,
                        "card_response": card_response.hex(),
                    },
                )
                self._update_session_id(response)
                continue
            if step == "complete":
                result = response.get("result", {})
                self.authenticated = True
                return result
            raise FelicaRemoteClientError(f"unexpected server response: {response}")

    def encryption_exchange(
        self,
        cmd_code: int,
        payload: bytes,
        timeout: float | None = None,
    ) -> bytes:
        """Send an encrypted command through the server and return the plain response."""
        if not self.authenticated:
            raise FelicaRemoteClientError(
                "mutual authentication must be completed first"
            )
        request_payload: dict[str, Any] = {
            "session_id": self.session_id,
            "cmd_code": cmd_code,
            "payload": payload.hex(),
        }
        if timeout is not None:
            request_payload["timeout"] = timeout

        response = self._post("/encryption-exchange", request_payload)
        self._update_session_id(response)

        command = self._extract_command(response)
        card_response = self._exchange_with_card(command)
        final_response = self._post(
            "/encryption-exchange",
            {
                "session_id": self.session_id,
                "card_response": card_response.hex(),
            },
        )
        self._update_session_id(final_response)
        try:
            response_hex = final_response["response"]
        except KeyError as exc:
            raise FelicaRemoteClientError(
                f"unexpected server response: {final_response}"
            ) from exc
        return bytes.fromhex(response_hex)

    def close(self) -> None:
        self._http_client.close()

    def reset(
        self,
        tag: FelicaStandard,
        session_id: str | None = None,
    ) -> None:
        """Reuse the same transport for a new tag/session."""
        self.tag = tag
        self.session_id = session_id
        self.authenticated = False

    def _exchange_with_card(self, command: _CommandEnvelope) -> bytes:
        timeout = (
            command.timeout
            if command.timeout is not None
            else self.default_exchange_timeout
        )
        log.debug(">> %s", command.frame.hex())
        response = self.tag.clf.exchange(command.frame, timeout)
        log.debug("<< %s", response.hex())
        return response

    def _extract_command(self, response: dict[str, Any]) -> _CommandEnvelope:
        try:
            command_info = response["command"]
            frame_hex = command_info["frame"]
        except KeyError as exc:
            raise FelicaRemoteClientError(
                f"missing command data in response: {response}"
            ) from exc
        try:
            frame = bytes.fromhex(frame_hex)
        except ValueError as exc:
            raise FelicaRemoteClientError(
                f"invalid command frame encoding: {frame_hex}"
            ) from exc
        timeout_value = command_info.get("timeout")
        timeout = float(timeout_value) if timeout_value is not None else None
        return _CommandEnvelope(frame=frame, timeout=timeout)

    def _update_session_id(self, response: dict[str, Any]) -> None:
        session_id = response.get("session_id")
        if session_id:
            self.session_id = session_id

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        data = self._http_client.post(path, payload, self.http_timeout)
        try:
            decoded = json.loads(data.decode("utf-8") or "{}")
        except json.JSONDecodeError as exc:
            raise FelicaRemoteClientError("server returned invalid JSON") from exc
        if "error" in decoded:
            error_info = decoded["error"]
            errno = error_info.get("code")
            if errno is not None:
                raise tt3.Type3TagCommandError(errno)
            raise FelicaRemoteClientError(
                error_info.get("message", "server reported an error")
            )
        return decoded
