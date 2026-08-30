//! SPEC-0049 §39 — RFC 3161 timestamp material is an exposed parsing surface,
//! and an unusually sensitive one: the bytes arrive from a *timestamp
//! authority*, an external party the database must talk to in order to prove
//! anything about when a record existed.
//!
//! A malformed or hostile token must be rejected. The failure that would matter
//! is not a crash in the abstract — it is a crash while ingesting a receipt,
//! which is exactly the moment a compliance chain is being built.

#![no_main]

use heraclitus_compliance::rfc3161::TimeStampReq;
use heraclitus_compliance::verify::is_dev_token;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // DER decoding of arbitrary bytes: Err is the expected answer, never a
    // panic and never an unbounded allocation.
    if let Ok(request) = TimeStampReq::from_der_bytes(data) {
        // A request that decoded must be re-encodable and inspectable. Nothing
        // here claims the request is *legitimate* — an attacker can produce a
        // well-formed one — only that handling it is safe.
        let _ = request.to_der_bytes();
        let _ = format!("{request:?}");
    }

    // Development tokens are recognised by shape. The classifier separates
    // "cannot validate this format" from "signature does not match", so it sees
    // every token, including bytes that merely resemble one.
    let _ = is_dev_token(data);

    // Verification against a fixed imprint: the interesting property is that a
    // forged or truncated token fails cleanly rather than aborting.
    let _ = heraclitus_compliance::verify::verify_dev_token(data, &[0x5A; 32]);
});
