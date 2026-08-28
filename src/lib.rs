//! Reads FeliCa transit cards (Suica and friends) and renders what is on them.
//!
//! The card's encrypted areas can only be read after a mutual authentication
//! whose keys live on a remote server, so a read is a three-way conversation:
//! this crate polls the card with [`felica`], relays the server's frames to
//! it, and decodes the blocks that come back.
//!
//! - [`card`] — the polled card and the raw frame relay
//! - [`auth_client`] — the remote authentication server
//! - [`card_data`] — block decoding into the [`card_data::CardData`] structure
//!   both front ends render
//! - [`station_codes`] / [`utils`] — name and value resolution

pub mod auth_client;
pub mod card;
pub mod card_data;
pub mod reader;
pub mod reader_errors;
pub mod station_codes;
pub mod bus_company_codes;
pub mod utils;

pub use auth_client::{AuthClient, AuthError, resolve_server_url};
pub use card::{CardError, CardSession};
pub use card_data::{CardData, CardDataError, CardDataService};
pub use station_codes::StationCodeLookup;
pub use utils::SYSTEM_CODE;
