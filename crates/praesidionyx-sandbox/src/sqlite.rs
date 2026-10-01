//! The only SQLite FFI bridge. Kept here to preserve forbid(unsafe_code) elsewhere.
use anyhow::{ensure, Result};
use rusqlite::ffi;
use std::sync::OnceLock;

pub fn register_vector_extension() -> Result<()> {
    static RESULT: OnceLock<i32> = OnceLock::new();
    let result = *RESULT.get_or_init(|| {
        type Entry = unsafe extern "C" fn(
            *mut ffi::sqlite3,
            *mut *mut std::ffi::c_char,
            *const ffi::sqlite3_api_routines,
        ) -> std::ffi::c_int;
        // SAFETY: sqlite-vec documents this SQLite extension entry-point ABI. Its
        // Rust declaration erases the arguments; both crates link the same bundled
        // SQLite library. Registration is once-only, thread-safe, and the statically
        // linked function remains alive for every subsequent connection.
        unsafe {
            let entry =
                std::mem::transmute::<*const (), Entry>(sqlite_vec::sqlite3_vec_init as *const ());
            ffi::sqlite3_auto_extension(Some(entry))
        }
    });
    ensure!(
        result == ffi::SQLITE_OK,
        "sqlite-vec registration failed: {result}"
    );
    Ok(())
}
