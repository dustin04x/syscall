fn main() {
    // The Tauri application can be disabled so the command-independent service
    // layer remains testable on hosts without GTK/WebKit development headers.
    if std::env::var_os("CARGO_FEATURE_DESKTOP_APP").is_some() {
        tauri_build::build();
    }
}
