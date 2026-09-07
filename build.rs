// build.rs — runs at compile time to generate OCSF types from schemas/ocsf-1.8.0.json.
// The generated file is written to $OUT_DIR/ocsf_generated.rs and pulled into the
// `ocsf` module via `include!(concat!(env!("OUT_DIR"), "/ocsf_generated.rs"))`.

include!("src/codegen_shared.rs");

fn main() {
    let schema_path = "schemas/ocsf-1.8.0.json";

    // Re-run the build step whenever the schema or the shared codegen logic changes.
    println!("cargo:rerun-if-changed={}", schema_path);
    println!("cargo:rerun-if-changed=src/codegen_shared.rs");

    // The generated types are only included by the `ocsf` module, so skip the
    // work entirely when that feature is off. Consumers of the default feature
    // set should not pay to generate two thousand lines they never compile.
    if std::env::var_os("CARGO_FEATURE_OCSF").is_none() {
        return;
    }

    let code = generate_from_schema(schema_path)
        .unwrap_or_else(|e| panic!("OCSF codegen failed for '{}': {}", schema_path, e));

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set by Cargo");
    let dest = std::path::Path::new(&out_dir).join("ocsf_generated.rs");
    std::fs::write(&dest, code)
        .unwrap_or_else(|e| panic!("Failed to write '{}': {}", dest.display(), e));
}
