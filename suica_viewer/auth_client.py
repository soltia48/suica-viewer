import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from nfc.tag import tt3
from nfc.tag.tt3_sony import FelicaStandard

log = logging.getLogger(__name__)


class FelicaRemoteClientError(Exception):
    """Raised for client-side transport or validation issues."""


def _extract_error_from_http_error(
    exc: urllib.error.HTTPError,
) -> tuple[str, int | None]:
    try:
        payload = json.loads(exc.read().decode("utf-8") or "{}")
    except json.JSONDecodeError:
        return exc.reason, None
    error = payload.get("error", {})
    message = error.get("message", exc.reason)
    errno = error.get("code")
    return message, errno


def _to_json_bytes(payload: Any) -> bytes:
    return json.dumps(payload).encode("utf-8")


def _post_json(
    server_url: str,
    path: str,
    payload: dict[str, Any],
    timeout: float,
) -> dict[str, Any]:
    url = server_url + path
    body = _to_json_bytes(payload)
    log.debug("POST %s keys=%s", url, list(payload.keys()))
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = response.read()
    except urllib.error.HTTPError as exc:
        message, errno = _extract_error_from_http_error(exc)
        if errno is not None:
            raise tt3.Type3TagCommandError(errno)
        raise FelicaRemoteClientError(f"{exc.code} {exc.reason}: {message}")
    except urllib.error.URLError as exc:
        raise FelicaRemoteClientError(f"failed to reach server: {exc.reason}") from exc

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
        self.server_url = server_url.rstrip("/")
        self.tag = tag
        self.session_id = session_id
        self.http_timeout = http_timeout
        self.default_exchange_timeout = default_exchange_timeout
        self.authenticated = False

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
        return _post_json(self.server_url, path, payload, self.http_timeout)
