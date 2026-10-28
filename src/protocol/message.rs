// wire-rs: encrypted protocol between Ark and host
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Shared message bodies, generated from both protobuf content oneofs.

use super::Error;
use super::schema::*;

/// Defines the shared body enum and conversions from the schema-derived payload list.
///
/// The generated `message.rs` invokes it once, with the union of both envelope
/// directions.
macro_rules! messages {
    ($($variant:ident($payload:ty),)*) => {
        /// Request or successful response body from either direction.
        ///
        /// Variants are named by their body type, so a request and its response
        /// stay apart. Request IDs and wire envelopes remain internal to the
        /// session API. The session checks whether it can send this message in
        /// its direction.
        ///
        /// Use `From`/`.into()` to submit a body and `TryFrom` to extract an expected
        /// body type. Extraction checks the variant and returns
        /// [`Error::UnexpectedResponse`] on mismatch. There is no static
        /// request/response pairing table. Convert into [`host_to_ark::Content`]
        /// or [`ark_to_host::Content`] to dispatch on one direction exhaustively.
        /// A body from the other direction fails that conversion with
        /// [`Error::WrongDirection`].
        #[derive(Clone, Debug, PartialEq)]
        pub enum Message {
            $(
                #[doc = concat!("A `", stringify!($payload), "` payload.")]
                $variant($payload),
            )*
        }

        impl Message {
            /// Returns the payload's Rust type name for type mismatch and
            /// direction errors.
            fn type_name(&self) -> &'static str {
                match self {
                    $(Self::$variant(_) => stringify!($payload),)*
                }
            }
        }

        $(
            impl From<$payload> for Message {
                /// Wraps a concrete payload in its corresponding message variant.
                fn from(message: $payload) -> Self {
                    Self::$variant(message)
                }
            }

            impl TryFrom<Message> for $payload {
                /// Variant mismatch between the received and requested payload types.
                type Error = Error;

                /// Extracts this payload only when the message variant matches.
                fn try_from(message: Message) -> Result<Self, Self::Error> {
                    match message {
                        Message::$variant(message) => Ok(message),
                        other => Err(Error::UnexpectedResponse {
                            expected: stringify!($payload),
                            received: other.type_name(),
                        }),
                    }
                }
            }
        )*
    };
}

/// Generates direction conversion from each envelope's actual schema fields.
///
/// Shared bodies remain usable in either direction without a hand-maintained list.
macro_rules! contents {
    ($module:ident, $($field:ident => $variant:ident,)*) => {
        impl From<$module::Content> for Message {
            /// Converts this envelope's content into the shared `Message` enum.
            fn from(content: $module::Content) -> Self {
                match content {
                    $($module::Content::$field(body) => Self::$variant(body),)*
                }
            }
        }

        impl TryFrom<Message> for $module::Content {
            /// A body absent from this envelope cannot travel in this direction.
            type Error = Error;

            /// Selects the envelope field by body type, independently of request ID.
            fn try_from(message: Message) -> Result<Self, Self::Error> {
                match message {
                    $(Message::$variant(body) => Ok(Self::$field(body)),)*
                    other => Err(Error::WrongDirection(other.type_name())),
                }
            }
        }
    };
}

include!("generated/message.rs");

/// Checks variant-safe conversion between message bodies and concrete payloads.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use crate::protocol::schema::{self, DeviceInfoRequest, DeviceInfoResponse};
    use crate::protocol::{Error, Message};

    /// Pins the export family's wire tags and checks both envelope directions.
    #[test]
    fn test_export_wire_tags() {
        use prost::Message as _;
        use schema::{ArkToHost, HostToArk, ark_to_host, host_to_ark};

        let requests = [
            host_to_ark::Content::ExportCreate(schema::ExportCreateRequest {
                paths: vec!["v1/genome/rsids/rs671".into()],
                optional: vec!["v1/genome/genes/ALDH2".into()],
            }),
            host_to_ark::Content::ExportLoad(schema::ExportLoadRequest { taskid: 9 }),
            host_to_ark::Content::ExportStart(schema::ExportStartRequest { taskid: 9 }),
            host_to_ark::Content::ExportStatus(schema::ExportStatusRequest { taskid: 9 }),
            host_to_ark::Content::ExportCancel(schema::ExportCancelRequest { taskid: 9 }),
            host_to_ark::Content::ExportResult(schema::ExportResultRequest { taskid: 9 }),
            host_to_ark::Content::ExportOutput(schema::ExportOutputRequest {
                taskid: 9,
                offset: 262144,
                size: 262144,
            }),
        ];
        let responses = [
            ark_to_host::Content::ExportCreate(schema::ExportCreateResponse { taskid: 9 }),
            ark_to_host::Content::ExportLoad(schema::ExportLoadResponse {}),
            ark_to_host::Content::ExportStart(schema::ExportStartResponse {}),
            ark_to_host::Content::ExportStatus(schema::ExportStatusResponse {
                state: schema::ExportState::AwaitingApproval as i32,
            }),
            ark_to_host::Content::ExportCancel(schema::ExportCancelResponse {}),
            ark_to_host::Content::ExportResult(schema::ExportResultResponse {
                paths: vec!["v1/genome/rsids/rs671".into()],
                media: "application/fhir+json; fhirVersion=4.0".into(),
                bytes: 12345,
            }),
            ark_to_host::Content::ExportOutput(schema::ExportOutputResponse {
                chunk: b"{}".to_vec(),
            }),
        ];
        for (tag, (request, response)) in [0x801, 0x802, 0x803, 0x804, 0x805, 0x806, 0x807]
            .into_iter()
            .zip(requests.into_iter().zip(responses))
        {
            let request = HostToArk {
                content: Some(request),
                ..Default::default()
            };
            let response = ArkToHost {
                content: Some(response),
                ..Default::default()
            };
            let request_bytes = request.encode_to_vec();
            let response_bytes = response.encode_to_vec();
            assert_eq!(
                prost::encoding::decode_key(&mut request_bytes.as_slice())
                    .unwrap()
                    .0,
                tag
            );
            assert_eq!(
                prost::encoding::decode_key(&mut response_bytes.as_slice())
                    .unwrap()
                    .0,
                tag
            );
            assert_eq!(
                HostToArk::decode(request_bytes.as_slice()).unwrap(),
                request
            );
            assert_eq!(
                ArkToHost::decode(response_bytes.as_slice()).unwrap(),
                response
            );
        }
    }

    /// Checks that extraction rejects a different `Message` variant, even when
    /// its protobuf fields could decode as the requested type.
    #[test]
    fn test_response_extraction_checks_the_variant() {
        use prost::Message as _;

        // Reject a different variant even when its encoded fields would decode
        let other = schema::OnboardingResponse {};
        assert!(DeviceInfoResponse::decode(other.encode_to_vec().as_slice()).is_ok());
        let message: Message = other.into();
        assert!(matches!(
            DeviceInfoResponse::try_from(message),
            Err(Error::UnexpectedResponse {
                expected: "DeviceInfoResponse",
                received: "OnboardingResponse",
            })
        ));

        // Keep bodies apart that share a field name and tag in opposite wire
        // envelopes, since they are distinct variants of the public message enum
        let message: Message = DeviceInfoRequest {}.into();
        assert!(matches!(
            DeviceInfoResponse::try_from(message),
            Err(Error::UnexpectedResponse {
                expected: "DeviceInfoResponse",
                received: "DeviceInfoRequest",
            })
        ));

        // Extract the matching structured response without changing its fields
        let response = DeviceInfoResponse {
            version_id: 7,
            ..Default::default()
        };
        let message: Message = response.clone().into();
        assert_eq!(DeviceInfoResponse::try_from(message).unwrap(), response);

        // Extract opaque development bytes through the same conversion API
        let message: Message = vec![1, 2, 3].into();
        assert_eq!(Vec::<u8>::try_from(message).unwrap(), vec![1, 2, 3]);
    }
}
