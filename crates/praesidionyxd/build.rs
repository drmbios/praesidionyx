#![forbid(unsafe_code)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/praesidionyx.proto");
    tonic_prost_build::configure()
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .field_attribute(
            "praesidionyx.v1.InvokeRequest.approval_id",
            "#[serde(default)]",
        )
        .compile_protos(&["proto/praesidionyx.proto"], &["proto"])?;
    Ok(())
}
