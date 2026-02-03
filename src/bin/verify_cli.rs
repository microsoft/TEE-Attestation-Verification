#[cfg(not(target_arch = "wasm32"))]
use std::env;
#[cfg(not(target_arch = "wasm32"))]
use verification_lib::{AttestationReport, SevVerifier};

#[cfg(not(target_arch = "wasm32"))]
async fn verify(
    hex_input: &String,
) -> Result<verification_lib::SevVerificationResult, Box<dyn std::error::Error>> {
    use zerocopy::FromBytes;

    let bytes = hex::decode(hex_input).map_err(|e| format!("Serialisation error: {}", e))?;
    // Parse the bytes as an AttestationReport
    let attestation_report = AttestationReport::read_from_bytes(&bytes)
        .map_err(|e| format!("Failed to parse attestation report from bytes: {:?}", e))?;

    // Create verifier and run verification
    let mut verifier = SevVerifier::new()
        .await
        .map_err(|e| format!("Failed to initialize verifier: {}", e))?;

    verifier.verify_attestation(&attestation_report).await
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <hex_string>", args[0]);
        std::process::exit(1);
    }

    let hex_input = &args[1];

    match verify(hex_input).await {
        Ok(res) if res.is_valid => {
            println!("Verification successful");
            std::process::exit(0);
        }
        Ok(res) => {
            eprintln!("Verification failed:\n{:?}", res);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Verification failed:\n{}", e);
            std::process::exit(1);
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn main() {
    // CLI is not supported on WASM
    panic!("verify-cli is not supported on wasm32 target");
}
