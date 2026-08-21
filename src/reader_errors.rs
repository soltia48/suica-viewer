//! Turns a reader-open failure into a message that says what to do about it.
//!
//! libusb reports "device is there but I cannot open it" and "you lack
//! permission" as two distinct errors that look equally opaque to a user. The
//! driver layer surfaces them as text, so the cause is recovered from the
//! message and paired with the fix for the current platform.

use felica::DriverError;

pub const ZADIG_URL: &str = "https://zadig.akeo.ie/";

const WINUSB_HINT: &str = concat!(
    "リーダーに WinUSB 互換ドライバがバインドされていません。",
    "Zadig (https://zadig.akeo.ie/) でリーダーのドライバを WinUSB に置き換えてください。"
);

const LINUX_ACCESS_HINT: &str = concat!(
    "リーダーへのアクセス権がありません。",
    "udev ルールを追加するか、root 権限で実行してください。"
);

const NO_READER_HINT: &str = "USB に接続されたリーダーが見つかりません。接続を確認してください。";

/// Describes a reader initialization error, appending a fix where one is known.
pub fn describe_reader_error(error: &DriverError) -> String {
    let message = error.to_string();
    match hint_for(&message) {
        Some(hint) => format!("{message}\n\n{hint}"),
        None => message,
    }
}

/// Picks the hint for a libusb failure, based on the platform it happened on.
///
/// Checked most specific first: a driver-binding failure and a permission
/// failure can both mention the device, so "not supported" has to win over the
/// broader "no such device" match.
fn hint_for(message: &str) -> Option<&'static str> {
    let lowered = message.to_lowercase();

    if cfg!(target_os = "windows") && lowered.contains("not supported") {
        return Some(WINUSB_HINT);
    }
    if cfg!(target_os = "linux") && lowered.contains("access denied") {
        return Some(LINUX_ACCESS_HINT);
    }
    if lowered.contains("no such device")
        || lowered.contains("not found")
        || lowered.contains("entity not found")
    {
        return Some(NO_READER_HINT);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_reader_is_explained_on_every_platform() {
        let error = DriverError::other("RC-S380 reader not found");
        let described = describe_reader_error(&error);
        assert!(described.contains("RC-S380 reader not found"));
        assert!(described.contains(NO_READER_HINT));
    }

    #[test]
    fn platform_specific_hints_only_fire_on_their_platform() {
        let access = hint_for("Access denied (insufficient permissions)");
        if cfg!(target_os = "linux") {
            assert_eq!(access, Some(LINUX_ACCESS_HINT));
        } else {
            assert_ne!(access, Some(LINUX_ACCESS_HINT));
        }

        let unsupported = hint_for("Operation not supported or unimplemented on this platform");
        if cfg!(target_os = "windows") {
            assert_eq!(unsupported, Some(WINUSB_HINT));
        } else {
            assert_ne!(unsupported, Some(WINUSB_HINT));
        }
    }

    #[test]
    fn an_unrecognized_error_is_passed_through_unchanged() {
        let error = DriverError::other("something else entirely");
        assert_eq!(describe_reader_error(&error), "something else entirely");
    }
}
