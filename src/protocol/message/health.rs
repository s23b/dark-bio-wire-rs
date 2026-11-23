// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Invented health envelopes with manually specified protobuf encodings.
//!
//! `make vectors` writes these cases to `vectors/health.json` for other clients.
//! `make fuzz-seeds` records the same envelopes. These fixtures check the wire
//! representation; applications enforce content limits and prompt lifetimes.

use crate::protocol::envelope::{DecodeError, Side};
use crate::protocol::mock::envelope;
use crate::protocol::schema::*;
use crate::protocol::{Error, Message};
use prost::bytes::Bytes;

/// Expected wire result, keeping malformed protobuf apart from invalid envelopes.
enum Expected {
    /// Decoded message body or application error, including all its fields.
    Body(Result<Message, crate::protocol::schema::Error>),
    /// Invalid protobuf encoding, including truncated or invalid UTF-8 fields.
    Protobuf,
    /// Simultaneous response content and error, forbidden by the envelope.
    ConflictingBody,
}

/// One independently encoded envelope and the body it must decode to.
struct Case {
    /// Stable fixture name shared by portable vectors and assertion failures.
    name: &'static str,
    /// Whether the envelope travels from the Ark to the host.
    response: bool,
    /// Expected decoding result, independent of the production encoder.
    expected: Expected,
    /// Manually encoded envelope with request id 1 and a health content tag.
    hex: &'static str,
}

/// Returns a fixed 16-byte import identifier unrelated to any resource id.
fn import_id() -> Vec<u8> {
    (0..16).collect()
}

/// Returns invented class counts with a different number for every class.
fn counts() -> HealthClassCounts {
    HealthClassCounts {
        clinical: 1,
        measurement: 2,
        signal: 3,
        attachment: 4,
        other: 5,
        packaging: 6,
        invalid: 7,
    }
}

/// Returns invented clinical bounds, distinct from the import's received time.
fn time_span() -> HealthTimeSpan {
    HealthTimeSpan {
        first: 10,
        last: 20,
    }
}

/// Returns an invented completed import exercising every summary field.
fn summary() -> HealthImportSummary {
    HealthImportSummary {
        import_id: import_id(),
        received: 42,
        file_kind: HealthFileKind::Bundle.into(),
        counts: Some(counts()),
        protected_entries: 2,
        unplaced: 3,
        export_errors: 4,
        time_span: Some(time_span()),
    }
}

/// Returns invented prompted details with a second kind at the protected level.
fn details(include_protected: bool) -> HealthDetailsResponse {
    // Keep public metadata identical at both approval levels
    let mut kinds = vec![HealthKind {
        category: HealthCategory::Measurement.into(),
        system: "urn:example".into(),
        code: "A".into(),
        name: "Kind A".into(),
        count: 3,
        time_span: Some(time_span()),
        unique_entries: 2,
        protected_categories: Vec::new(),
    }];

    // A resource in several protected categories still counts once
    if include_protected {
        kinds.push(HealthKind {
            category: HealthCategory::Measurement.into(),
            system: "urn:example".into(),
            code: "B".into(),
            name: "Kind B".into(),
            count: 2,
            time_span: Some(time_span()),
            unique_entries: 1,
            protected_categories: vec![
                HealthProtectedCategory::MentalHealth.into(),
                HealthProtectedCategory::GeneticTests.into(),
            ],
        });
    }

    // The name and aggregate protected count do not depend on approval level
    HealthDetailsResponse {
        remaining_seconds: 120,
        include_protected,
        imports: vec![HealthImportDetails {
            import_id: import_id(),
            name: HealthImportName::Measurements.into(),
            received: 42,
            received_size: 64,
            stored_size: 32,
            time_span: Some(time_span()),
            kinds,
            protected_entries: 2,
            unsupported: Some(HealthUnsupportedCounts {
                attachment: 1,
                other: 2,
                invalid: 3,
                unplaced: 1,
            }),
        }],
    }
}

/// Returns golden envelopes for every health request, reply and approval level.
fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "start-request",
            response: false,
            expected: Expected::Body(Ok(HealthImportStartRequest {
                size: 2,
                chunk: b"{".to_vec(),
            }
            .into())),
            hex: "08018a90010510021a017b",
        },
        Case {
            name: "start-approved",
            response: true,
            expected: Expected::Body(Ok(HealthImportStartResponse { session: 7 }.into())),
            hex: "08018a9001020807",
        },
        Case {
            name: "chunk-request",
            response: false,
            expected: Expected::Body(Ok(HealthImportChunkRequest {
                session: 7,
                chunk: b"}".to_vec(),
            }
            .into())),
            hex: "080192900105080712017d",
        },
        Case {
            name: "chunk-accepted",
            response: true,
            expected: Expected::Body(Ok(HealthImportChunkResponse {}.into())),
            hex: "080192900100",
        },
        Case {
            name: "cancel-request",
            response: false,
            expected: Expected::Body(Ok(HealthImportCancelRequest { session: 7 }.into())),
            hex: "08019a9001020807",
        },
        Case {
            name: "cancel-accepted",
            response: true,
            expected: Expected::Body(Ok(HealthImportCancelResponse {}.into())),
            hex: "08019a900100",
        },
        Case {
            name: "process-request",
            response: false,
            expected: Expected::Body(Ok(HealthImportProcessRequest { session: 7 }.into())),
            hex: "0801a29001020807",
        },
        Case {
            name: "process-processing",
            response: true,
            expected: Expected::Body(Ok(HealthImportProcessResponse {
                state: HealthImportState::Processing.into(),
                progress: 5000,
                failure: HealthImportFailure::Unspecified.into(),
                summary: None,
            }
            .into())),
            hex: "0801a29001050801108827",
        },
        Case {
            name: "process-done",
            response: true,
            expected: Expected::Body(Ok(HealthImportProcessResponse {
                state: HealthImportState::Done.into(),
                progress: 10000,
                failure: HealthImportFailure::Unspecified.into(),
                summary: Some(summary()),
            }
            .into())),
            hex: concat!(
                "0801a2900139080210904e2232",
                "0a10000102030405060708090a0b0c0d0e0f102a1801",
                "220e0801100218032004280530063807",
                "2802300338044204080a1014",
            ),
        },
        Case {
            name: "list-request",
            response: false,
            expected: Expected::Body(Ok(HealthListRequest {}.into())),
            hex: "0801aa900100",
        },
        Case {
            name: "list-empty",
            response: true,
            expected: Expected::Body(Ok(HealthListResponse { imports: vec![] }.into())),
            hex: "0801aa900100",
        },
        Case {
            name: "list-bundle",
            response: true,
            expected: Expected::Body(Ok(HealthListResponse {
                imports: vec![HealthImportInfo {
                    import_id: import_id(),
                    received: 42,
                    file_kind: HealthFileKind::Bundle.into(),
                }],
            }
            .into())),
            hex: "0801aa9001180a160a10000102030405060708090a0b0c0d0e0f102a1801",
        },
        Case {
            name: "list-ndjson",
            response: true,
            expected: Expected::Body(Ok(HealthListResponse {
                imports: vec![HealthImportInfo {
                    import_id: import_id(),
                    received: 42,
                    file_kind: HealthFileKind::Ndjson.into(),
                }],
            }
            .into())),
            hex: "0801aa9001180a160a10000102030405060708090a0b0c0d0e0f102a1802",
        },
        Case {
            name: "list-single-resource",
            response: true,
            expected: Expected::Body(Ok(HealthListResponse {
                imports: vec![HealthImportInfo {
                    import_id: import_id(),
                    received: 42,
                    file_kind: HealthFileKind::SingleResource.into(),
                }],
            }
            .into())),
            hex: "0801aa9001180a160a10000102030405060708090a0b0c0d0e0f102a1803",
        },
        Case {
            name: "delete-request",
            response: false,
            expected: Expected::Body(Ok(HealthDeleteRequest {
                import_id: import_id(),
            }
            .into())),
            hex: "0801b29001120a10000102030405060708090a0b0c0d0e0f",
        },
        Case {
            name: "delete-accepted",
            response: true,
            expected: Expected::Body(Ok(HealthDeleteResponse {}.into())),
            hex: "0801b2900100",
        },
        Case {
            name: "details-request",
            response: false,
            expected: Expected::Body(Ok(HealthDetailsRequest {
                include_protected: false,
            }
            .into())),
            hex: "0801ba900100",
        },
        Case {
            name: "details-protected-request",
            response: false,
            expected: Expected::Body(Ok(HealthDetailsRequest {
                include_protected: true,
            }
            .into())),
            hex: "0801ba9001020801",
        },
        Case {
            name: "details-counts-only-protected",
            response: true,
            expected: Expected::Body(Ok(details(false).into())),
            hex: concat!(
                "0801ba90015608781a52",
                "0a10000102030405060708090a0b0c0d0e0f1005182a20402820",
                "3204080a1014",
                "3a240802120b75726e3a6578616d706c651a014122064b696e642041",
                "28033204080a10143802",
                "40024a080801100218032001",
            ),
        },
        Case {
            name: "details-protected-kinds",
            response: true,
            expected: Expected::Body(Ok(details(true).into())),
            hex: concat!(
                "0801ba90018201087810011a7c",
                "0a10000102030405060708090a0b0c0d0e0f1005182a20402820",
                "3204080a1014",
                "3a240802120b75726e3a6578616d706c651a014122064b696e642041",
                "28033204080a10143802",
                "3a280802120b75726e3a6578616d706c651a014222064b696e642042",
                "28023204080a1014380142020305",
                "40024a080801100218032001",
            ),
        },
        Case {
            name: "details-empty",
            response: true,
            expected: Expected::Body(Ok(HealthDetailsResponse {
                remaining_seconds: 1,
                include_protected: false,
                imports: vec![],
            }
            .into())),
            hex: "0801ba9001020801",
        },
        Case {
            name: "details-expired",
            response: true,
            expected: Expected::Body(Ok(HealthDetailsResponse::default().into())),
            hex: "0801ba900100",
        },
        Case {
            name: "process-unknown-failure-code",
            response: true,
            expected: Expected::Body(Ok(HealthImportProcessResponse {
                state: HealthImportState::Failed.into(),
                progress: 0,
                failure: 99,
                summary: None,
            }
            .into())),
            hex: "0801a290010408031863",
        },
        Case {
            name: "start-truncated-chunk",
            response: false,
            expected: Expected::Protobuf,
            hex: "08018a90010510021a027b",
        },
        Case {
            name: "process-truncated-summary",
            response: true,
            expected: Expected::Protobuf,
            hex: "0801a29001050802220208",
        },
        Case {
            name: "process-failure-is-not-text",
            response: true,
            expected: Expected::Protobuf,
            hex: "0801a290010a08031a066661696c6564",
        },
        Case {
            name: "details-import-name-is-not-text",
            response: true,
            expected: Expected::Protobuf,
            hex: "0801ba9001071a051203616263",
        },
        Case {
            name: "details-invalid-kind-name",
            response: true,
            expected: Expected::Protobuf,
            hex: "0801ba9001071a053a032201ff",
        },
        Case {
            name: "delete-truncated-id",
            response: false,
            expected: Expected::Protobuf,
            hex: "0801b29001030a1000",
        },
        Case {
            name: "approval-error-with-content",
            response: true,
            expected: Expected::ConflictingBody,
            hex: "0801120208058a9001020807",
        },
    ]
}

/// Returns terminal failures with literal encodings independent of enum values.
fn failures() -> Vec<Case> {
    [
        (
            "not-fhir",
            HealthImportFailure::NotFhir,
            "0801a290010408031801",
        ),
        (
            "several-patients",
            HealthImportFailure::SeveralPatients,
            "0801a290010408031802",
        ),
        (
            "already-imported",
            HealthImportFailure::AlreadyImported,
            "0801a290010408031803",
        ),
        (
            "over-limit",
            HealthImportFailure::Limit,
            "0801a290010408031804",
        ),
        (
            "storage-failed",
            HealthImportFailure::StorageFailed,
            "0801a290010408031805",
        ),
    ]
    .into_iter()
    .map(|(name, failure, hex)| Case {
        name,
        response: true,
        expected: Expected::Body(Ok(HealthImportProcessResponse {
            state: HealthImportState::Failed.into(),
            progress: 0,
            failure: failure.into(),
            summary: None,
        }
        .into())),
        hex,
    })
    .collect()
}

/// Returns health request and prompt errors with independently encoded codes.
fn request_errors() -> Vec<Case> {
    [
        (
            "approval-declined",
            ReservedErrors::Unauthorized as u64,
            "080112020805",
        ),
        (
            "approval-expired",
            ReservedErrors::Unconfirmed as u64,
            "080112020806",
        ),
        (
            "approval-undelivered",
            ReservedErrors::Undelivered as u64,
            "080112020807",
        ),
        (
            "request-invalid",
            HealthErrors::RequestInvalid as u64,
            "08011203088112",
        ),
        (
            "storage-locked",
            HealthErrors::StorageLocked as u64,
            "08011203088212",
        ),
        ("busy", HealthErrors::Busy as u64, "08011203088312"),
        (
            "session-unknown",
            HealthErrors::SessionUnknown as u64,
            "08011203088412",
        ),
        (
            "session-state",
            HealthErrors::SessionState as u64,
            "08011203088512",
        ),
        (
            "upload-incomplete",
            HealthErrors::UploadIncomplete as u64,
            "08011203088612",
        ),
        (
            "import-unknown",
            HealthErrors::ImportUnknown as u64,
            "08011203088712",
        ),
        (
            "storage-error",
            HealthErrors::StorageFailed as u64,
            "08011203088812",
        ),
        (
            "response-limit",
            HealthErrors::Limit as u64,
            "08011203088912",
        ),
    ]
    .into_iter()
    .map(|(name, code, hex)| Case {
        name,
        response: true,
        expected: Expected::Body(Err(crate::protocol::schema::Error {
            code,
            msg: String::new(),
        })),
        hex,
    })
    .collect()
}

/// Pins encodings, deferred decoding, direction checks and malformed health bodies.
#[test]
fn test_health_wire_vectors() {
    let mut vectors = Vec::new();
    for case in cases()
        .into_iter()
        .chain(failures())
        .chain(request_errors())
    {
        // Decode literal fixtures without using any protobuf encoder
        let (pairs, rest) = case.hex.as_bytes().as_chunks::<2>();
        assert!(rest.is_empty(), "{}", case.name);
        let bytes: Vec<u8> = pairs
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let (sender, receiver) = if case.response {
            (Side::Server, Side::Client)
        } else {
            (Side::Client, Side::Server)
        };

        // Both schema views must agree with independently specified expectations
        match &case.expected {
            Expected::Body(expected) => {
                assert_eq!(
                    sender.encode(1, expected.clone()).unwrap(),
                    bytes,
                    "{}",
                    case.name
                );
                let header = receiver.decode_header(Bytes::from(bytes.clone())).unwrap();
                assert!(!header.unknown, "{}", case.name);
                assert_eq!(header.failed, expected.is_err(), "{}", case.name);
                assert_eq!(
                    receiver.decode(Bytes::from(bytes.clone())).unwrap(),
                    (1, expected.clone()),
                    "{}",
                    case.name
                );

                // Each typed health body belongs to exactly one direction
                if let Ok(body) = expected {
                    assert_eq!(header.payload, Some(body.field_name()), "{}", case.name);
                    assert!(
                        matches!(
                            receiver.encode(1, Ok(body.clone())),
                            Err(Error::WrongDirection(_))
                        ),
                        "{}",
                        case.name
                    );
                }
            }
            Expected::Protobuf => {
                assert!(
                    matches!(
                        receiver.decode(Bytes::from(bytes.clone())),
                        Err(DecodeError::Protobuf(_))
                    ),
                    "{}",
                    case.name
                );
            }
            Expected::ConflictingBody => {
                assert!(
                    matches!(
                        receiver.decode_header(Bytes::from(bytes.clone())),
                        Err(Error::Malformed)
                    ),
                    "{}",
                    case.name
                );
                assert!(
                    matches!(
                        receiver.decode(Bytes::from(bytes.clone())),
                        Err(DecodeError::Body)
                    ),
                    "{}",
                    case.name
                );
            }
        }

        // Share accepted and rejected inputs with the envelope fuzzer
        let accepted = matches!(case.expected, Expected::Body(_));
        let mut input = vec![u8::from(case.response)];
        input.extend(bytes);
        assert_eq!(envelope::run(&input), accepted, "{}", case.name);
        vectors.push(serde_json::json!({
            "name": case.name,
            "direction": if case.response { "ark_to_host" } else { "host_to_ark" },
            "accepted": accepted,
            "hex": case.hex,
        }));
    }

    // Write portable plaintext fixtures only through the repository's make target
    if let Some(directory) = std::env::var_os("WIRE_VECTORS") {
        let path = std::path::Path::new(&directory).join("health.json");
        let document = serde_json::json!({ "version": 1, "cases": vectors });
        std::fs::write(
            path,
            serde_json::to_string_pretty(&document).unwrap() + "\n",
        )
        .unwrap();
    }
}
