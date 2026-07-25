//! A polled FeliCa card, held open across the whole read.
//!
//! The card changes mode as the read progresses, and that dictates the shape of
//! this module. Polling leaves the card in Mode 0; a completed mutual
//! authentication moves it to Mode 2, where it no longer answers Polling for
//! that system. So the card can be polled exactly once, at the start, and
//! everything afterwards — the authentication relay, the encrypted reads,
//! presence tracking — has to run against that same activation.
//!
//! [`FelicaStandard`] can only be built by polling and takes the driver
//! exclusively for as long as it lives, yet the authentication frames the
//! server builds still have to reach the card while it is alive. [`SharedDriver`]
//! resolves that: the protocol object drives ordinary commands through one
//! handle while [`CardSession::exchange`] pushes raw frames through another.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use felica_rs::felica_standard::{
    AuthenticatedContext, BlockListElement, FelicaDriver, FelicaStandard, FelicaStandardCommand,
    SecureSessionCredentials, ServiceCode, Type3TagPollingResult,
};
use felica_rs::{DriverError, FelicaStandardError, RemoteTarget};

/// FeliCa bitrates to poll at. 424F is preferred and 212F is the fallback.
const BITRATES: [&str; 2] = ["212F", "424F"];

/// Longest exchange the reader can be asked to wait for, in milliseconds.
const MAX_TIMEOUT_MS: u128 = u16::MAX as u128;

/// A block of card data.
pub const BLOCK_SIZE: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum CardError {
    #[error("{0}")]
    Driver(#[from] DriverError),
    #[error("{0}")]
    Protocol(#[from] FelicaStandardError),
}

/// A handle to the reader's driver that can be cloned and lent out.
///
/// Every clone drives the same reader. Nothing holds the inner borrow across a
/// call, so a [`FelicaStandard`] built on one handle and a raw exchange issued
/// through another interleave safely.
pub struct SharedDriver<'a> {
    inner: Rc<RefCell<&'a mut dyn FelicaDriver>>,
}

impl<'a> SharedDriver<'a> {
    pub fn new(driver: &'a mut dyn FelicaDriver) -> Self {
        Self {
            inner: Rc::new(RefCell::new(driver)),
        }
    }

    /// Returns another handle to the same reader.
    fn handle(&self) -> Self {
        Self {
            inner: Rc::clone(&self.inner),
        }
    }
}

impl FelicaDriver for SharedDriver<'_> {
    fn detect_type_f(
        &mut self,
        target: &RemoteTarget,
        system_code: u16,
        request_code: u8,
        time_slots: u8,
    ) -> Result<Type3TagPollingResult, DriverError> {
        self.inner
            .borrow_mut()
            .detect_type_f(target, system_code, request_code, time_slots)
    }

    fn transceive(
        &mut self,
        target: &RemoteTarget,
        data: &[u8],
        timeout_ms: Option<u16>,
    ) -> Result<Vec<u8>, DriverError> {
        self.inner.borrow_mut().transceive(target, data, timeout_ms)
    }
}

/// The ephemeral secure session the auth server hands back once authentication
/// completes. It is what lets the client run encrypted commands on its own.
#[derive(Debug, Clone, Copy)]
pub struct SecureSession {
    pub key: [u8; 8],
    pub transaction_id: [u8; 6],
    pub transaction_number: u16,
}

/// A card sitting on the reader, addressed at the bitrate it answered at.
pub struct CardSession<'a, 'd> {
    felica: FelicaStandard<'a, SharedDriver<'d>>,
    /// A second handle to the same reader, for frames the protocol object did
    /// not build — that is, the ones the auth server sends.
    raw: SharedDriver<'d>,
    target: RemoteTarget,
    /// Kept whole because the PMm it carries is what sets each command's timeout.
    polling: Type3TagPollingResult,
}

impl<'a, 'd> CardSession<'a, 'd> {
    /// Polls for a card and holds the activation open.
    ///
    /// Returns `Ok(None)` when no card answered, which is the ordinary idle
    /// state of a reader rather than a failure worth reporting.
    pub fn poll(
        driver: &'a mut SharedDriver<'d>,
        system_code: u16,
    ) -> Result<Option<Self>, CardError> {
        // Taken before the protocol object borrows the handle, so the relay has
        // a way in for as long as the session lives.
        let raw = driver.handle();

        let (felica, polling) =
            match FelicaStandard::polling_multi(driver, &BITRATES, system_code, 0x00, 0x00) {
                Ok(found) => found,
                Err(_) => return Ok(None),
            };

        Ok(Some(Self {
            target: RemoteTarget::new(felica.bitrate()).map_err(DriverError::from)?,
            felica,
            raw,
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
    ///
    /// This is the relay path: the auth server builds the frame, the card
    /// answers it, and neither end is interpreted here.
    pub fn exchange(&mut self, frame: &[u8], timeout: Duration) -> Result<Vec<u8>, CardError> {
        let timeout_ms = timeout.as_millis().clamp(1, MAX_TIMEOUT_MS) as u16;
        log::debug!(">> {}", hex::encode(frame));
        let response = self.raw.transceive(&self.target, frame, Some(timeout_ms))?;
        log::debug!("<< {}", hex::encode(&response));
        Ok(response)
    }

    /// Adopts the session material the auth server established.
    ///
    /// From here the card's encrypted commands run locally: the server has
    /// already forgotten the session and never sees the data.
    pub fn begin_secure_session(&mut self, session: &SecureSession) {
        self.felica
            .set_authenticated_context(AuthenticatedContext::new(
                session.transaction_number,
                session.transaction_id,
                SecureSessionCredentials::Des(session.key),
            ));
    }

    /// Reads `count` blocks of an authenticated service, starting at `first`.
    ///
    /// `service_index` is the position of the service in the list that was
    /// authenticated, not a service code.
    pub fn read_blocks_from(
        &mut self,
        service_index: u8,
        first: usize,
        count: usize,
    ) -> Result<Vec<[u8; BLOCK_SIZE]>, CardError> {
        let block_list: Vec<BlockListElement> = (first..first + count)
            .map(|block| BlockListElement::new(block as u16, service_index, 0))
            .collect();
        Ok(self.felica.read(&block_list)?)
    }

    /// Returns the card to Mode 0 so a fresh authentication can start.
    ///
    /// A failed authentication can leave the card mid-protocol, and it will not
    /// entertain a new Authentication1 from there.
    pub fn reset(&mut self, system_code: u16) -> Result<(), CardError> {
        self.felica.clear_authenticated_context();
        let frame = FelicaStandardCommand::Polling {
            system_code,
            request_code: 0x00,
            time_slots: 0x00,
        }
        .to_frame()?;
        self.exchange(&frame, POLLING_TIMEOUT)?;
        Ok(())
    }

    /// Reports whether the card carries `service`.
    ///
    /// Request Service is unencrypted, so this answers "is the service there"
    /// without involving the auth server or any key.
    pub fn has_service(&mut self, service: u16) -> Result<bool, CardError> {
        let versions = self.felica.request_service(&[ServiceCode::new(service)])?;
        // 0xFFFF is the card's way of saying "no such node".
        Ok(matches!(versions.first(), Some(&version) if version != 0xFFFF))
    }

    /// Checks whether the card is still on the reader.
    ///
    /// Polling cannot answer this once the card has been read: a completed
    /// mutual authentication leaves the card in Mode 2, where it stops
    /// responding to Polling for the system it authenticated against. Request
    /// Response is answered in every mode, so it is what actually tracks
    /// presence — and its reply carries the mode the card is currently in.
    pub fn is_present(&mut self) -> bool {
        match self.felica.request_response() {
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
}

/// Timeout for the Polling frame used to reset the card, per the FeliCa
/// specification's time-slot budget for a single-slot poll.
const POLLING_TIMEOUT: Duration = Duration::from_millis(4);

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    const IDM: [u8; 8] = [0x01, 0x13, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
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
    fn request_response_reply(idm: [u8; 8], mode: u8) -> Vec<u8> {
        let mut frame = vec![0x0B, 0x05];
        frame.extend_from_slice(&idm);
        frame.push(mode);
        frame
    }

    #[test]
    fn polling_captures_the_identifiers_the_card_reported() {
        let mut driver = ScriptedDriver::new(vec![]);
        let mut handle = SharedDriver::new(&mut driver);
        let card = CardSession::poll(&mut handle, 0x0003).unwrap().unwrap();

        assert_eq!(card.idm(), IDM);
        assert_eq!(card.pmm(), PMM);
        assert_eq!(card.bitrate(), "424F");
    }

    #[test]
    fn presence_is_probed_with_request_response_not_polling() {
        let mut driver = ScriptedDriver::new(vec![Ok(request_response_reply(IDM, 0x00))]);
        {
            let mut handle = SharedDriver::new(&mut driver);
            let mut card = CardSession::poll(&mut handle, 0x0003).unwrap().unwrap();
            assert!(card.is_present());
        }

        // Polling is the wrong question to ask here: after mutual authentication
        // the card sits in Mode 2 and stops answering it, which would read as a
        // removed card the moment a read finished.
        let frame = driver.sent.first().expect("a frame should have been sent");
        assert_eq!(frame[1], REQUEST_RESPONSE_COMMAND_CODE);
        assert_ne!(frame[1], POLLING_COMMAND_CODE);
        assert_eq!(frame[0] as usize, frame.len());
        assert_eq!(&frame[2..], IDM);
    }

    #[test]
    fn a_card_still_in_mode_2_counts_as_present() {
        // Mode 2 is exactly the state a just-read card is left in, and it is the
        // state in which Polling would have gone unanswered.
        let mut driver = ScriptedDriver::new(vec![Ok(request_response_reply(IDM, 0x02))]);
        let mut handle = SharedDriver::new(&mut driver);
        let mut card = CardSession::poll(&mut handle, 0x0003).unwrap().unwrap();
        assert!(card.is_present());
    }

    #[test]
    fn a_card_that_stops_answering_counts_as_removed() {
        let mut driver = ScriptedDriver::new(vec![Err(DriverError::other("receive timeout"))]);
        let mut handle = SharedDriver::new(&mut driver);
        let mut card = CardSession::poll(&mut handle, 0x0003).unwrap().unwrap();
        assert!(!card.is_present());
    }

    #[test]
    fn a_reply_that_is_not_a_request_response_does_not_count_as_present() {
        // Truncated frame, and a frame carrying some other response code.
        for reply in [vec![0x02, 0x05], vec![0x03, 0x01, 0x00]] {
            let mut driver = ScriptedDriver::new(vec![Ok(reply)]);
            let mut handle = SharedDriver::new(&mut driver);
            let mut card = CardSession::poll(&mut handle, 0x0003).unwrap().unwrap();
            assert!(!card.is_present());
        }
    }

    #[test]
    fn relayed_frames_and_protocol_commands_share_one_reader() {
        // The relay and the protocol object hold separate handles; both must
        // reach the card without tripping over each other.
        let mut driver = ScriptedDriver::new(vec![
            Ok(vec![0xAA]),
            Ok(request_response_reply(IDM, 0x02)),
            Ok(vec![0xBB]),
        ]);
        {
            let mut handle = SharedDriver::new(&mut driver);
            let mut card = CardSession::poll(&mut handle, 0x0003).unwrap().unwrap();

            assert_eq!(
                card.exchange(&[0x02, 0x99], Duration::from_millis(10))
                    .unwrap(),
                vec![0xAA]
            );
            assert!(card.is_present());
            assert_eq!(
                card.exchange(&[0x02, 0x98], Duration::from_millis(10))
                    .unwrap(),
                vec![0xBB]
            );
        }

        assert_eq!(driver.sent.len(), 3);
        assert_eq!(driver.sent[0], vec![0x02, 0x99]);
        assert_eq!(driver.sent[1][1], REQUEST_RESPONSE_COMMAND_CODE);
        assert_eq!(driver.sent[2], vec![0x02, 0x98]);
    }

    #[test]
    fn resetting_sends_a_polling_frame_to_return_the_card_to_mode_0() {
        let mut driver = ScriptedDriver::new(vec![Ok(vec![0x12, 0x01])]);
        {
            let mut handle = SharedDriver::new(&mut driver);
            let mut card = CardSession::poll(&mut handle, 0x0003).unwrap().unwrap();
            card.reset(0x0003).unwrap();
        }

        let frame = driver.sent.first().expect("a frame should have been sent");
        assert_eq!(frame[1], POLLING_COMMAND_CODE);
    }
}
