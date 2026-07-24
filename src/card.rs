//! A polled FeliCa card, held open across the whole read.
//!
//! The mutual-authentication relay needs to push server-built frames straight at
//! the card and hand back the raw reply, which is what [`CardSession::exchange`]
//! does. Protocol-level helpers such as the service probe still go through
//! `felica-rs`, so this type only owns what the relay genuinely needs: the
//! driver, the bitrate the card answered at, and its polling result.
//!
//! Note that the card changes mode as the read progresses. It answers Polling
//! while it is in Mode 0, but a completed mutual authentication moves it to
//! Mode 2, where it no longer answers Polling for that system. Anything that
//! has to work after the authentication — presence tracking above all — must
//! therefore use a command the card answers in every mode.

use std::time::Duration;

use felica_rs::felica_standard::{
    FelicaDriver, FelicaStandard, FelicaStandardCommand, FelicaStandardResponse, ServiceCode,
    Type3TagPollingResult,
};
use felica_rs::{DriverError, FelicaStandardError, RemoteTarget};

/// FeliCa bitrates to poll at. 424F is preferred and 212F is the fallback.
const BITRATES: [&str; 2] = ["212F", "424F"];

/// Longest exchange the reader can be asked to wait for, in milliseconds.
const MAX_TIMEOUT_MS: u128 = u16::MAX as u128;

/// Length of a FeliCa IDm.
const IDM_LEN: usize = 8;

#[derive(Debug, thiserror::Error)]
pub enum CardError {
    #[error("{0}")]
    Driver(#[from] DriverError),
    #[error("{0}")]
    Protocol(#[from] FelicaStandardError),
}

/// A card sitting on the reader, addressed at the bitrate it answered at.
pub struct CardSession<'a> {
    driver: &'a mut dyn FelicaDriver,
    target: RemoteTarget,
    /// Kept whole because the PMm it carries is what sets each command's timeout.
    polling: Type3TagPollingResult,
}

impl<'a> CardSession<'a> {
    /// Polls for a card and captures its identifiers.
    ///
    /// Returns `Ok(None)` when no card answered, which is the ordinary idle
    /// state of a reader rather than a failure worth reporting.
    pub fn poll(
        driver: &'a mut dyn FelicaDriver,
        system_code: u16,
    ) -> Result<Option<Self>, CardError> {
        // The borrow taken by `FelicaStandard` ends with this block, which is
        // what lets the driver move into the session below.
        let polled = {
            match FelicaStandard::polling_multi(&mut *driver, &BITRATES, system_code, 0x00, 0x00) {
                Ok((felica, polling)) => Some((felica.bitrate().to_string(), polling)),
                Err(_) => None,
            }
        };

        let Some((bitrate, polling)) = polled else {
            return Ok(None);
        };

        Ok(Some(Self {
            driver,
            target: RemoteTarget::new(bitrate).map_err(DriverError::from)?,
            polling,
        }))
    }

    pub fn idm(&self) -> &[u8] {
        &self.polling.idm
    }

    pub fn pmm(&self) -> &[u8] {
        &self.polling.pmm
    }

    pub fn bitrate(&self) -> &str {
        self.target.bitrate()
    }

    /// Sends a raw Type 3 frame (length byte included) and returns the reply.
    pub fn exchange(&mut self, frame: &[u8], timeout: Duration) -> Result<Vec<u8>, CardError> {
        let timeout_ms = timeout.as_millis().clamp(1, MAX_TIMEOUT_MS) as u16;
        log::debug!(">> {}", hex::encode(frame));
        let response = self
            .driver
            .transceive(&self.target, frame, Some(timeout_ms))?;
        log::debug!("<< {}", hex::encode(&response));
        Ok(response)
    }

    /// Re-polls the card, refreshing the identifiers.
    ///
    /// Used to get back to a clean state after a failed authentication, since
    /// the card keeps no session of its own to reset.
    pub fn repoll(&mut self, system_code: u16) -> Result<(), CardError> {
        let (_, polling) = FelicaStandard::polling_multi(
            &mut *self.driver,
            &[self.target.bitrate()],
            system_code,
            0x00,
            0x00,
        )?;
        self.polling = polling;
        Ok(())
    }

    /// Reports whether the card carries `service`.
    ///
    /// Request Service is unencrypted, so this answers "is the service there"
    /// without involving the auth server or any key.
    pub fn has_service(&mut self, service: u16, system_code: u16) -> Result<bool, CardError> {
        let (mut felica, _) = FelicaStandard::polling_multi(
            &mut *self.driver,
            &[self.target.bitrate()],
            system_code,
            0x00,
            0x00,
        )?;
        let versions = felica.request_service(&[ServiceCode::new(service)])?;
        // 0xFFFF is the card's way of saying "no such node".
        Ok(matches!(versions.first(), Some(&version) if version != 0xFFFF))
    }

    /// Checks whether the card is still on the reader.
    ///
    /// Polling cannot answer this once the card has been read: a completed
    /// mutual authentication leaves the card in Mode 2, where it stops
    /// responding to Polling for the system it authenticated against. Request
    /// Response is answered in every mode, so it is what actually tracks
    /// presence — and its reply carries the mode, which is also how the card
    /// reports that it fell back to Mode 0.
    pub fn is_present(&mut self) -> bool {
        match self.request_response() {
            Ok(mode) => {
                log::trace!("card present, mode {mode}");
                true
            }
            Err(error) => {
                log::debug!("presence check failed: {error}");
                false
            }
        }
    }

    /// Issues Request Response and returns the card's current mode.
    pub fn request_response(&mut self) -> Result<u8, CardError> {
        let idm = self.idm_bytes()?;
        let frame = FelicaStandardCommand::RequestResponse { idm }.to_frame();
        // The card states its own timing in PMm; honour it rather than guessing.
        let timeout = Duration::from_millis(self.polling.request_response_timeout_ms().into());

        let response = self.exchange(&frame, timeout)?;
        match FelicaStandardResponse::from_bytes(&response)? {
            FelicaStandardResponse::RequestResponse { idm: echoed, mode } if echoed == idm => {
                Ok(mode)
            }
            // A reply from some other card in the field says nothing about ours.
            _ => Err(
                FelicaStandardError::Protocol("unexpected Request Response reply".into()).into(),
            ),
        }
    }

    fn idm_bytes(&self) -> Result<[u8; IDM_LEN], CardError> {
        self.polling.idm.as_slice().try_into().map_err(|_| {
            CardError::Protocol(FelicaStandardError::InvalidParameter(
                "IDm must be 8 bytes long".into(),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    const IDM: [u8; IDM_LEN] = [0x01, 0x13, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    const PMM: [u8; 8] = [0x03, 0x89, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF];

    const POLLING_COMMAND_CODE: u8 = 0x00;
    const REQUEST_RESPONSE_COMMAND_CODE: u8 = 0x04;

    /// A driver that answers polling and replays queued frame replies.
    struct ScriptedDriver {
        sent: Vec<Vec<u8>>,
        replies: VecDeque<Result<Vec<u8>, DriverError>>,
    }

    impl ScriptedDriver {
        fn new(replies: Vec<Result<Vec<u8>, DriverError>>) -> Self {
            Self {
                sent: Vec::new(),
                replies: replies.into(),
            }
        }
    }

    impl FelicaDriver for ScriptedDriver {
        fn detect_type_f(
            &mut self,
            _target: &RemoteTarget,
            _system_code: u16,
            _request_code: u8,
            _time_slots: u8,
        ) -> Result<Type3TagPollingResult, DriverError> {
            Ok(Type3TagPollingResult {
                idm: IDM.to_vec(),
                pmm: PMM.to_vec(),
                optional: Vec::new(),
            })
        }

        fn transceive(
            &mut self,
            _target: &RemoteTarget,
            data: &[u8],
            _timeout_ms: Option<u16>,
        ) -> Result<Vec<u8>, DriverError> {
            self.sent.push(data.to_vec());
            self.replies
                .pop_front()
                .unwrap_or_else(|| Err(DriverError::other("no scripted reply")))
        }
    }

    /// Builds a Request Response reply frame for `idm`.
    fn request_response_reply(idm: [u8; IDM_LEN], mode: u8) -> Vec<u8> {
        let mut frame = vec![0x0B, 0x05];
        frame.extend_from_slice(&idm);
        frame.push(mode);
        frame
    }

    fn session(driver: &mut ScriptedDriver) -> CardSession<'_> {
        CardSession::poll(driver, 0x0003)
            .expect("polling should succeed")
            .expect("a card should be found")
    }

    #[test]
    fn polling_captures_the_identifiers_the_card_reported() {
        let mut driver = ScriptedDriver::new(vec![]);
        let card = session(&mut driver);
        assert_eq!(card.idm(), IDM);
        assert_eq!(card.pmm(), PMM);
        assert_eq!(card.bitrate(), "424F");
    }

    #[test]
    fn presence_is_probed_with_request_response_not_polling() {
        let mut driver = ScriptedDriver::new(vec![Ok(request_response_reply(IDM, 0x00))]);
        let mut card = session(&mut driver);

        assert!(card.is_present());

        // Polling is the wrong question to ask here: after mutual authentication
        // the card sits in Mode 2 and stops answering it, which would read as a
        // removed card the moment a read finished.
        let frame = driver.sent.first().expect("a frame should have been sent");
        assert_eq!(frame[1], REQUEST_RESPONSE_COMMAND_CODE);
        assert_ne!(frame[1], POLLING_COMMAND_CODE);
        // Length byte, command code, then the IDm.
        assert_eq!(frame[0] as usize, frame.len());
        assert_eq!(&frame[2..], IDM);
    }

    #[test]
    fn a_card_still_in_mode_2_counts_as_present() {
        // Mode 2 is exactly the state a just-read card is left in, and it is the
        // state in which Polling would have gone unanswered.
        let mut driver = ScriptedDriver::new(vec![
            Ok(request_response_reply(IDM, 0x02)),
            Ok(request_response_reply(IDM, 0x02)),
        ]);
        let mut card = session(&mut driver);
        assert_eq!(card.request_response().expect("mode should be read"), 0x02);
        assert!(card.is_present());
    }

    #[test]
    fn a_card_that_stops_answering_counts_as_removed() {
        let mut driver = ScriptedDriver::new(vec![Err(DriverError::other("receive timeout"))]);
        let mut card = session(&mut driver);
        assert!(!card.is_present());
    }

    #[test]
    fn a_reply_from_a_different_card_does_not_count_as_present() {
        let other = [0x02, 0x24, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let mut driver = ScriptedDriver::new(vec![Ok(request_response_reply(other, 0x00))]);
        let mut card = session(&mut driver);
        assert!(!card.is_present());
    }

    #[test]
    fn a_malformed_reply_does_not_count_as_present() {
        let mut driver = ScriptedDriver::new(vec![Ok(vec![0x02, 0x05])]);
        let mut card = session(&mut driver);
        assert!(!card.is_present());
    }
}
