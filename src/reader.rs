//! Opening the USB reader and waiting for a card.

use std::time::Duration;

use felica_rs::{Reader, ReaderPreference, open_reader};

use crate::reader_errors::describe_reader_error;

/// How long to wait between polling attempts while no card is on the reader.
pub const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Opens the first supported reader, describing the failure in user terms.
pub fn open() -> Result<Reader, String> {
    open_reader(ReaderPreference::Auto).map_err(|error| describe_reader_error(&error))
}
