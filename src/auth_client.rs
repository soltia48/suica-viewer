//! Client for the remote mutual-authentication server.
//!
//! The card's long-term keys live on the server, not here, so the
//! authentication is a ping-pong: the server builds a frame, this client puts
//! it on the card, and the card's reply goes back for the server to interpret.
//!
//! That is the server's *whole* involvement. On success it returns the
//! ephemeral session material and forgets the session, and the client runs the
//! encrypted reads itself — so card data never reaches the server, and the
//! long-term keys never leave it.

use std::time::Duration;

use serde_json::{Map, Value, json};

use crate::card::{CardError, CardSession, SecureSession};

/// Auth server used when neither `--server` nor `AUTH_SERVER_URL` is set.
pub const DEFAULT_AUTH_SERVER_URL: &str = "https://felica-auth.nyaa.ws";

/// How long to wait on the auth server for one HTTP round trip.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Card exchange timeout used when the server does not specify one.
const DEFAULT_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(1);

/// A transport hiccup is retried once, because a pooled connection can be
/// closed by the far end between requests through no fault of this request.
const POST_ATTEMPTS: usize = 2;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// The card rejected a command; the server passed its status code through.
    #[error("カードがエラーを返しました (0x{0:04X})")]
    Card(u16),

    /// The server was reached but reported a problem.
    #[error("{0}")]
    Server(String),

    /// The server could not be reached, or the reply was not usable.
    #[error("サーバ通信エラー: {0}")]
    Transport(String),

    /// Talking to the card itself failed.
    #[error("{0}")]
    Reader(#[from] CardError),
}

/// Resolves the auth server URL from an explicit override, the environment, or
/// the built-in default, in that order.
pub fn resolve_server_url(override_url: Option<&str>) -> String {
    if let Some(url) = override_url {
        let trimmed = url.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    match std::env::var("AUTH_SERVER_URL") {
        Ok(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => DEFAULT_AUTH_SERVER_URL.to_string(),
    }
}

/// What the server returns once mutual authentication completes.
#[derive(Debug, Clone)]
pub struct AuthenticationResult {
    /// Issue ID (IDi) as uppercase hex.
    pub issue_id_hex: String,
    /// Issue parameter (PMi) as uppercase hex.
    pub issue_parameter_hex: String,
    /// The ephemeral secure session, which the client drives from here on.
    pub session: SecureSession,
}

/// The only secure-session scheme the server issues.
const DES_SCHEME: &str = "des";

/// One frame the server wants delivered to the card.
struct CommandEnvelope {
    frame: Vec<u8>,
    timeout: Duration,
}

/// Coordinates card I/O with the remote crypto server.
pub struct AuthClient {
    agent: ureq::Agent,
    base_url: String,
    /// Set only while an authentication is in flight; the server destroys the
    /// session as soon as it completes.
    session_id: Option<String>,
}

impl AuthClient {
    /// Builds a client for `server_url`.
    ///
    /// The URL is validated up front so a typo surfaces before a card is ever
    /// touched, rather than as a confusing failure mid-authentication.
    pub fn new(server_url: &str) -> Result<Self, AuthError> {
        let base_url = server_url.trim_end_matches('/').to_string();
        let base_url = if base_url.is_empty() {
            server_url.to_string()
        } else {
            base_url
        };

        let scheme = base_url.split("://").next().unwrap_or("").to_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(AuthError::Server(
                "認証サーバの URL は http または https である必要があります。".to_string(),
            ));
        }
        if base_url
            .split("://")
            .nth(1)
            .is_none_or(|rest| rest.is_empty())
        {
            return Err(AuthError::Server(
                "認証サーバの URL にホスト名がありません。".to_string(),
            ));
        }

        let config = ureq::Agent::config_builder()
            .timeout_global(Some(HTTP_TIMEOUT))
            // 4xx/5xx carry the server's own error payload, which is more
            // informative than the bare status code.
            .http_status_as_error(false)
            .build();

        Ok(Self {
            agent: config.into(),
            base_url,
            session_id: None,
        })
    }

    /// Drops any session state so the same transport can serve a new card.
    pub fn reset(&mut self) {
        self.session_id = None;
    }

    /// Runs a full mutual-authentication sequence against `card`.
    pub fn mutual_authentication(
        &mut self,
        card: &mut CardSession<'_, '_>,
        system_code: u16,
        areas: &[u16],
        services: &[u16],
    ) -> Result<AuthenticationResult, AuthError> {
        let mut response = self.post(
            "/mutual-authentication",
            json!({
                "session_id": self.session_id,
                "idm": hex::encode(card.idm()),
                "pmm": hex::encode(card.pmm()),
                "system_code": system_code,
                "areas": areas,
                "services": services,
            }),
        )?;

        loop {
            match response.get("step").and_then(Value::as_str) {
                Some("auth1") | Some("auth2") => {
                    let card_response = self.relay(card, &response)?;
                    response = self.post(
                        "/mutual-authentication",
                        json!({
                            "session_id": self.session_id,
                            "card_response": hex::encode(card_response),
                        }),
                    )?;
                }
                Some("complete") => {
                    // The server discards the session the moment it hands the
                    // material over, so the id is already dead here — keeping it
                    // would only earn a 404 on the next card.
                    self.session_id = None;
                    return authentication_result(&response);
                }
                _ => {
                    return Err(AuthError::Server(format!(
                        "サーバから予期しない応答が返りました: {}",
                        Value::Object(response)
                    )));
                }
            }
        }
    }

    /// Delivers the server's frame to the card and returns the card's reply.
    fn relay(
        &self,
        card: &mut CardSession<'_, '_>,
        response: &Map<String, Value>,
    ) -> Result<Vec<u8>, AuthError> {
        let command = extract_command(response)?;
        Ok(card.exchange(&command.frame, command.timeout)?)
    }

    /// POSTs `payload` to `path` and returns the decoded JSON object.
    fn post(&mut self, path: &str, payload: Value) -> Result<Map<String, Value>, AuthError> {
        let url = format!("{}{}", self.base_url, path);
        let mut last_error: Option<String> = None;

        for _ in 0..POST_ATTEMPTS {
            let response = match self.agent.post(&url).send_json(&payload) {
                Ok(response) => response,
                Err(error) => {
                    last_error = Some(describe_transport_error(&error));
                    continue;
                }
            };

            let status = response.status().as_u16();
            let body = match response.into_body().read_to_string() {
                Ok(body) => body,
                Err(error) => {
                    last_error = Some(describe_transport_error(&error));
                    continue;
                }
            };

            return self.interpret(status, &body);
        }

        Err(AuthError::Transport(
            last_error.unwrap_or_else(|| "原因不明のエラー".to_string()),
        ))
    }

    /// Turns one HTTP reply into either a JSON object or the error it reports.
    fn interpret(&mut self, status: u16, body: &str) -> Result<Map<String, Value>, AuthError> {
        let parsed: Value = serde_json::from_str(if body.is_empty() { "{}" } else { body })
            .map_err(|_| {
                if status >= 400 {
                    AuthError::Server(format!("HTTP {status}: {body}"))
                } else {
                    AuthError::Transport("サーバの応答が JSON ではありません。".to_string())
                }
            })?;

        let Value::Object(object) = parsed else {
            return Err(AuthError::Transport(
                "サーバの応答が JSON オブジェクトではありません。".to_string(),
            ));
        };

        if let Some(error) = object.get("error") {
            // A numeric code means the card itself rejected the command, which
            // the caller may want to handle differently from a server fault.
            if let Some(code) = error.get("code").and_then(Value::as_u64) {
                return Err(AuthError::Card(code as u16));
            }
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("サーバがエラーを報告しました");
            return Err(AuthError::Server(if status >= 400 {
                format!("HTTP {status}: {message}")
            } else {
                message.to_string()
            }));
        }

        if status >= 400 {
            return Err(AuthError::Server(format!("HTTP {status}: {body}")));
        }

        if let Some(session_id) = object.get("session_id").and_then(Value::as_str) {
            if !session_id.is_empty() {
                self.session_id = Some(session_id.to_string());
            }
        }

        Ok(object)
    }
}

fn extract_command(response: &Map<String, Value>) -> Result<CommandEnvelope, AuthError> {
    let command = response.get("command").ok_or_else(|| {
        AuthError::Server(format!(
            "サーバ応答にコマンドが含まれていません: {}",
            Value::Object(response.clone())
        ))
    })?;

    let frame_hex = command
        .get("frame")
        .and_then(Value::as_str)
        .ok_or_else(|| AuthError::Server("サーバ応答に frame がありません。".to_string()))?;

    let frame = hex::decode(frame_hex)
        .map_err(|_| AuthError::Server(format!("コマンドの hex 形式が不正です: {frame_hex}")))?;

    let timeout = command
        .get("timeout")
        .and_then(Value::as_f64)
        .filter(|seconds| seconds.is_finite() && *seconds > 0.0)
        .map(Duration::from_secs_f64)
        .unwrap_or(DEFAULT_EXCHANGE_TIMEOUT);

    Ok(CommandEnvelope { frame, timeout })
}

fn authentication_result(response: &Map<String, Value>) -> Result<AuthenticationResult, AuthError> {
    let result = response.get("result");
    let field = |names: [&str; 2]| -> Option<String> {
        let result = result?;
        names
            .iter()
            .find_map(|name| result.get(*name).and_then(Value::as_str))
            .map(str::to_uppercase)
            .filter(|value| !value.is_empty())
    };

    let issue_id_hex = field(["issue_id", "idi"]).ok_or_else(|| {
        AuthError::Server("サーバ応答に Issue ID が含まれていません。".to_string())
    })?;
    let issue_parameter_hex = field(["issue_parameter", "pmi"]).ok_or_else(|| {
        AuthError::Server("サーバ応答に Issue Parameter が含まれていません。".to_string())
    })?;

    if hex::decode(&issue_id_hex).is_err() {
        return Err(AuthError::Server("Issue ID の形式が不正です。".to_string()));
    }

    let session = result
        .and_then(|result| result.get("session"))
        .ok_or_else(|| {
            AuthError::Server(
                "サーバ応答にセッション情報が含まれていません。認証サーバが対応バージョンか確認してください。"
                    .to_string(),
            )
        })
        .and_then(secure_session)?;

    Ok(AuthenticationResult {
        issue_id_hex,
        issue_parameter_hex,
        session,
    })
}

/// Reads the ephemeral session material out of a completed authentication.
fn secure_session(session: &Value) -> Result<SecureSession, AuthError> {
    let scheme = session
        .get("scheme")
        .and_then(Value::as_str)
        .unwrap_or(DES_SCHEME);
    if !scheme.eq_ignore_ascii_case(DES_SCHEME) {
        return Err(AuthError::Server(format!(
            "未対応のセッション方式です: {scheme}"
        )));
    }

    let key = session_bytes(session, "key")?;
    let transaction_id = session_bytes(session, "transaction_id")?;
    let transaction_number = session
        .get("transaction_number")
        .and_then(Value::as_u64)
        .filter(|value| *value <= u64::from(u16::MAX))
        .ok_or_else(|| {
            AuthError::Server("セッション情報の transaction_number が不正です。".to_string())
        })? as u16;

    Ok(SecureSession {
        key,
        transaction_id,
        transaction_number,
    })
}

/// Decodes a fixed-width hex field of the session material.
fn session_bytes<const N: usize>(session: &Value, name: &str) -> Result<[u8; N], AuthError> {
    let hex_value = session
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| AuthError::Server(format!("セッション情報に {name} がありません。")))?;

    hex::decode(hex_value)
        .ok()
        .and_then(|bytes| <[u8; N]>::try_from(bytes.as_slice()).ok())
        .ok_or_else(|| {
            AuthError::Server(format!(
                "セッション情報の {name} が不正です（{N} バイトの hex が必要）。"
            ))
        })
}

fn describe_transport_error(error: &impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_url_resolution_prefers_the_explicit_override() {
        unsafe { std::env::set_var("AUTH_SERVER_URL", "https://env.example") };
        assert_eq!(
            resolve_server_url(Some("https://flag.example")),
            "https://flag.example"
        );
        assert_eq!(resolve_server_url(None), "https://env.example");
        unsafe { std::env::remove_var("AUTH_SERVER_URL") };
        assert_eq!(resolve_server_url(None), DEFAULT_AUTH_SERVER_URL);
        assert_eq!(resolve_server_url(Some("  ")), DEFAULT_AUTH_SERVER_URL);
    }

    #[test]
    fn only_http_urls_are_accepted() {
        assert!(AuthClient::new("https://example.com").is_ok());
        assert!(AuthClient::new("http://example.com/prefix/").is_ok());
        assert!(AuthClient::new("ftp://example.com").is_err());
        assert!(AuthClient::new("example.com").is_err());
        assert!(AuthClient::new("https://").is_err());
    }

    #[test]
    fn a_trailing_slash_does_not_double_up_in_request_paths() {
        let client = AuthClient::new("https://example.com/").unwrap();
        assert_eq!(client.base_url, "https://example.com");
    }

    #[test]
    fn a_numeric_error_code_is_reported_as_a_card_error() {
        let mut client = AuthClient::new("https://example.com").unwrap();
        let error = client
            .interpret(
                400,
                r#"{"error": {"code": 43094, "message": "card said no"}}"#,
            )
            .unwrap_err();
        assert!(matches!(error, AuthError::Card(0xA856)));
    }

    #[test]
    fn an_error_without_a_code_is_reported_as_a_server_error() {
        let mut client = AuthClient::new("https://example.com").unwrap();
        let error = client
            .interpret(500, r#"{"error": {"message": "no key for node"}}"#)
            .unwrap_err();
        match error {
            AuthError::Server(message) => assert!(message.contains("no key for node")),
            other => panic!("expected a server error, got {other}"),
        }
    }

    #[test]
    fn session_ids_are_captured_from_successful_replies() {
        let mut client = AuthClient::new("https://example.com").unwrap();
        client
            .interpret(200, r#"{"session_id": "abc", "step": "auth1"}"#)
            .unwrap();
        assert_eq!(client.session_id.as_deref(), Some("abc"));

        // A reply without a session id keeps the one already established.
        client.interpret(200, r#"{"step": "complete"}"#).unwrap();
        assert_eq!(client.session_id.as_deref(), Some("abc"));
    }

    #[test]
    fn commands_carry_the_servers_timeout_when_it_supplies_one() {
        let response: Map<String, Value> =
            serde_json::from_str(r#"{"command": {"frame": "0a06", "timeout": 2.5}}"#).unwrap();
        let command = extract_command(&response).unwrap();
        assert_eq!(command.frame, vec![0x0A, 0x06]);
        assert_eq!(command.timeout, Duration::from_millis(2500));

        let response: Map<String, Value> =
            serde_json::from_str(r#"{"command": {"frame": "0a06"}}"#).unwrap();
        assert_eq!(
            extract_command(&response).unwrap().timeout,
            DEFAULT_EXCHANGE_TIMEOUT
        );
    }

    /// A completion payload in the shape the server sends.
    fn completion(id_field: &str, parameter_field: &str, session: &str) -> Map<String, Value> {
        serde_json::from_str(&format!(
            r#"{{"result": {{"{id_field}": "0103abcd", "{parameter_field}": "00ff",
                 "session": {session}}}}}"#
        ))
        .unwrap()
    }

    const SESSION: &str = r#"{"scheme": "des", "key": "0011223344556677",
        "transaction_id": "aabbccddeeff", "transaction_number": 3}"#;

    #[test]
    fn the_completion_payload_accepts_both_field_spellings() {
        let result = authentication_result(&completion("idi", "pmi", SESSION)).unwrap();
        assert_eq!(result.issue_id_hex, "0103ABCD");
        assert_eq!(result.issue_parameter_hex, "00FF");

        let result =
            authentication_result(&completion("issue_id", "issue_parameter", SESSION)).unwrap();
        assert_eq!(result.issue_id_hex, "0103ABCD");
    }

    #[test]
    fn the_completion_payload_carries_the_secure_session() {
        let result = authentication_result(&completion("idi", "pmi", SESSION)).unwrap();
        assert_eq!(
            result.session.key,
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]
        );
        assert_eq!(
            result.session.transaction_id,
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
        );
        assert_eq!(result.session.transaction_number, 3);
    }

    #[test]
    fn a_completion_payload_without_session_material_is_rejected() {
        // This is what an older server returns; the read cannot proceed without
        // the session, so say so rather than failing later and opaquely.
        let response: Map<String, Value> =
            serde_json::from_str(r#"{"result": {"idi": "0103abcd", "pmi": "00ff"}}"#).unwrap();
        let error = authentication_result(&response).unwrap_err();
        assert!(error.to_string().contains("セッション"));
    }

    #[test]
    fn malformed_session_material_is_rejected() {
        // Wrong key length, wrong transaction id length, unsupported scheme, and
        // a counter that cannot be a u16.
        for session in [
            r#"{"key": "0011", "transaction_id": "aabbccddeeff", "transaction_number": 0}"#,
            r#"{"key": "0011223344556677", "transaction_id": "aabb", "transaction_number": 0}"#,
            r#"{"scheme": "aes128", "key": "0011223344556677",
                "transaction_id": "aabbccddeeff", "transaction_number": 0}"#,
            r#"{"key": "0011223344556677", "transaction_id": "aabbccddeeff",
                "transaction_number": 70000}"#,
            r#"{"key": "zzzzzzzzzzzzzzzz", "transaction_id": "aabbccddeeff",
                "transaction_number": 0}"#,
        ] {
            assert!(
                authentication_result(&completion("idi", "pmi", session)).is_err(),
                "should have rejected {session}"
            );
        }
    }

    #[test]
    fn the_scheme_defaults_to_des_when_the_server_omits_it() {
        let session = r#"{"key": "0011223344556677", "transaction_id": "aabbccddeeff",
            "transaction_number": 0}"#;
        assert!(authentication_result(&completion("idi", "pmi", session)).is_ok());
    }

    #[test]
    fn a_completion_payload_missing_the_issue_id_is_rejected() {
        let response: Map<String, Value> =
            serde_json::from_str(r#"{"result": {"pmi": "00ff"}}"#).unwrap();
        assert!(authentication_result(&response).is_err());

        let response: Map<String, Value> =
            serde_json::from_str(r#"{"result": {"idi": "zz", "pmi": "00ff"}}"#).unwrap();
        assert!(authentication_result(&response).is_err());
    }
}
