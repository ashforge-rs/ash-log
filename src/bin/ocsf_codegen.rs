//! OCSF Rust type generator (OCSF 1.8.0).
//!
//! Reads the ash-log OCSF schema JSON (default: `schemas/ocsf-1.8.0.json`) and
//! emits Rust source code for all enumerations, supporting objects, and event
//! classes defined in the schema.  The same generation logic is used at compile
//! time by `build.rs` (via `include!("src/codegen_shared.rs")`).
//!
//! # Usage
//!
//! ```text
//! cargo run --features ocsf --bin ocsf_codegen
//! cargo run --features ocsf --bin ocsf_codegen -- path/to/custom-schema.json
//! ```
//!
//! Redirect to a file to inspect the generated code:
//!
//! ```text
//! cargo run --features ocsf --bin ocsf_codegen > /tmp/ocsf_generated.rs
//! ```

include!("../codegen_shared.rs");

fn main() {
    let schema_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "schemas/ocsf-1.8.0.json".to_string());

    match generate_from_schema(&schema_path) {
        Ok(code) => print!("{}", code),
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(1);
        }
    }
}
