// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Rust oracle for the differential fuzzer. Same protocol as oracle.cpp:
//! `oracle DID CHAIN_PEM_PATH` prints `ok` and the leaf JWK, or `err` and a message.

use tee_attestation_verification_didx509::{
    validation_sync::resolve_pem, PolicyConfig, ValidationTime,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, did, path] = args.as_slice() else {
        eprintln!("usage: oracle DID CHAIN_PEM_PATH");
        std::process::exit(2);
    };
    let pem = std::fs::read_to_string(path).expect("read chain");
    match resolve_pem(did, &pem, ValidationTime::Now, PolicyConfig::default()) {
        Ok(document) => {
            println!(
                "ok\n{}",
                document.verification_method.public_key_jwk.to_json()
            );
        }
        Err(error) => println!("err\n{}", error.to_string().replace('\n', " ")),
    }
}
