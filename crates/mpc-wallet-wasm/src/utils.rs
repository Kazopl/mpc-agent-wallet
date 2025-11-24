//! WASM utility functions

/// Set panic hook for better error messages in browser console
pub fn set_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// Log a message to the browser console
#[allow(dead_code)]
pub fn console_log(msg: &str) {
    web_sys::console::log_1(&msg.into());
}

/// Log an error to the browser console
#[allow(dead_code)]
pub fn console_error(msg: &str) {
    web_sys::console::error_1(&msg.into());
}
