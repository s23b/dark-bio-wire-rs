# Ark encrypted wire protocol

[![](https://img.shields.io/crates/v/darkbio-wire.svg)](https://crates.io/crates/darkbio-wire)
[![](https://docs.rs/darkbio-wire/badge.svg)](https://docs.rs/darkbio-wire)
[![](https://github.com/dark-bio/wire-rs/workflows/tests/badge.svg)](https://github.com/dark-bio/wire-rs/actions/workflows/ci.yml)
[![License: BSD-3-Clause](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](https://github.com/dark-bio/wire-rs/blob/main/LICENSE)

This crate implements the encrypted protocol between an [Ark](https://dark.bio) enclave and the host it is plugged into. It turns any duplex byte stream into encrypted sessions with a verified Ark, carrying protobuf requests and replies in both directions.

The Ark is the server, and host software connects to it as a client. Opening the byte stream is up to the caller. Arks connect over USB bulk endpoints, emulated Arks over a WebSocket, and tests over the in-memory streams of this crate. Waiting blocks the calling thread, and no async runtime is needed.

The crate has three parts:

- `transport` turns a byte stream into encrypted sessions. It frames packets, runs the handshake and seals every message.
- `protocol` exchanges requests and replies over a transport session. `connect` opens a session to an Ark, `Server` accepts sessions from successive clients, and `schema` holds the protobuf messages.
- `memory` provides in-memory streams for local connections, emulators and tests.

The crates whose types appear in the API are re-exported as `clock`, `cobs`, `crypto`, `trust` and `prost`. Callers can name their types through these, at the versions this crate was built with.

## Sessions

The protocol is built for USB bulk endpoints, which browsers can drive through WebUSB. Bulk endpoints carry bytes but have no notion of a connection:

- The device gets no lifecycle events. The host's OS opens the endpoints when the Ark is plugged in, and applications then come and go without a trace. Only one application holds them at a time.
- There is one long-lived stream, created by the device and shared by every application in turn. Bytes one application leaves in the buffers may reach the next.
- An application can close its own handle and rely on the usual I/O events. The Ark cannot recreate its endpoints without a slow and noisy USB reconnect.

So the protocol runs its own sessions and tolerates junk already on the line when a client arrives. Packets travel as [COBS](https://en.wikipedia.org/wiki/Consistent_Overhead_Byte_Stuffing) frames delimited by zero bytes, and an empty frame is a reset. Frames are at most 2 MiB, and a larger one ends the session. A client opens every session with a reset and a handshake, skipping stale data until the Ark answers. When the Ark ends a session or receives data outside one, it tries to send a reset too, so the client knows to connect again.

## Handshake and trust

A handshake takes three messages. The host sends fresh ephemeral keys. The Ark answers with an ephemeral key of its own, sealed to the host's keys and signed by its identity key. The host's acknowledgement then completes one encryption context per direction.

The Ark's answer carries its attestation, a [darkbio-trust](https://github.com/dark-bio/trust-rs) CWT that binds its identity key to a device. The client decides which Arks to trust through a `Verifier`:

- `Roots` accepts Arks attested by the given hardware and emulator roots. darkbio-trust embeds them for each environment its features enable.
- A pinned `xdsa::PublicKey` accepts only the Ark holding that key, whoever attested it.
- Other policies, such as also accepting Arks that were never onboarded, implement `Verifier` themselves.

The Ark does not authenticate the host, as the threat model explains.

## Threat model

The wire assumes the host computer may be malicious. The host only relays encrypted traffic between the Ark, the Dark Bio cloud and Ark Companion. Being plugged in does not earn it any trust from the Ark. Application security happens in the layers above the wire, so the wire itself has no reason to authenticate the host and does not try to.

What the wire does protect against is someone sitting between the host's client and the Ark. That could be another process on the same computer, something on the USB path, or a recording of an earlier session. Such an attacker cannot pretend to be an Ark, cannot read or alter what the two sides exchange, and cannot reuse a recorded session.

The wire does not protect availability. A malicious host can drop or reset sessions whenever it likes. The wire only guarantees that a new client gets noticed.

## Requests and replies

Both sides send requests and answer the peer's, with any number in flight at once. A session's `Requester` sends requests. `Session::recv` returns the peer's requests, each with a `Responder` for the answer. Messages go out in the order they are queued and arrive in the order they were sent. Clients number their requests with odd IDs and servers with even ones, and a reply carries its request's ID.

A request returns a `Promise` at once, and `wait` blocks until the reply arrives or the deadline passes. The deadline includes the time spent in the outgoing queue. An expired request can still reach the peer. A responder dropped without an answer sends an `UNANSWERED` error. A request whose content this build does not know gets `UNKNOWN`, so a newer peer learns what an older one serves.

The application must keep receiving and answering the peer's requests while its own requests wait for replies. By default, a session holds at most 1024 pending peer requests and 16 MiB of buffered incoming messages. Exceeding either closes the session, since the protocol has no flow control.

A host runs an app through `exec_create`, `exec_load` and `exec_start`. Creation names the main module by its SHA-256 digest and returns a task id. While loading waits, the host answers the Ark's `exec_module_size` and `exec_module_read` requests for the main module and its dependencies. Loading has no overall deadline; each module request gets 30s. Starting opens the approval on the owner's phone in Ark Companion, and the task's apps run once the owner approves.

## Health imports

A host imports FHIR R4 through `health_import_start`, `health_import_chunk` and `health_import_process`. Starting sends the size and first chunk and waits for the owner's approval in Ark Companion. The response returns an upload handle scoped to the host session. Chunks follow in order. Processing reports its state, active phase (storing or indexing) and overall progress, followed by the committed import's summary or a failure code. `health_import_cancel` discards temporary upload state.

`health_list` needs no prompt and returns only each import's 16-byte random id, received time and file kind. Hosts number imports by received time, breaking ties by id. File kinds distinguish Bundles of any type, NDJSON and single resources.

`health_details` takes no fields and requires a new phone prompt every time. The Ark keeps no approval state between requests. The prompt allows 120s for a decision. It states that the computer receives names, counts and date ranges, including protected categories, and may keep a copy. Values stay on the Ark.

The response carries the complete details and a 32-byte `digest`. `health_digest` takes no fields and returns only that digest, never opening a prompt. Both requests require unlocked storage. Hosts can compare a saved response's digest with the current one from the same Ark to check whether the copy still matches.

The digest is HMAC-SHA256 over a canonical encoding of every details field except the digest itself, including nested fields and their presence. It covers imports, kinds, names, counts, spans, protected tags and totals. Importing, deleting or changing names or classification changes it. The Ark creates and persists a secret 32-byte key once, separate from its opaque-id key, and domain-separates this use. Keying prevents a host without approval from testing guesses about the details against the digest.

Details describe each import's name, received and stored sizes, time span and kinds of data. Import names use only unprotected kinds, in this order of precedence: the single kind's name, Lab results when every kind is a lab result, Hospital stay when its visits include one, or Health record. An import with no unprotected kinds is a Health record.

Each import's `HealthKind` carries a category, an area assigned by the Ark, a code, a name, a distinct resource count, a time span and `unique_entries`. The last field counts entries that disappear when that import is deleted. The response's `HealthKindOverview` list counts each resource identity once per kind across all imports and gives its time span. Hosts join the lists on category, system, code and protected categories. Clinical areas distinguish lab results, other observations, conditions, medications, vaccines, allergies, procedures, visits, reports, imaging and family history. Measurement and signal areas are unspecified; hosts group them by code.

Kind names use Ark terminology or a code-based fallback. Protected kinds are always included and tagged with their protected categories. Each import also carries a protected count. Attachment, other, invalid and unplaced counts describe unsupported entries, including protected entries; unplaced is already included in other. Received time and sizes cover the whole import.

The response's `protected_entries` counts distinct protected resource identities across all imports. Its `unsupported_entries` counts distinct attachment, other and invalid identities, including protected entries and excluding packaging. `unsupported_time_span` gives their known time bounds, or is absent when none are known. Each identity uses its newest unsupported copy by export time, else received time, and its last occurrence within that import. These totals count each identity once despite multiple codings, classes or protected categories; hosts must not add per-import counts to obtain them.

The process summary describes what the host uploaded, so its counts and time span include protected entries. Summaries and details exclude values, narrative, source names and resource ids. `health_delete` waits for phone approval to delete one import. Approval declines, expiries and delivery failures use the reserved envelope errors; other request failures use `HealthErrors` with fixed wording.

The health range is `0x901-0xA00`. [The schema](proto/wire.proto) defines field limits, count semantics and session lifetimes. Applications enforce semantic constraints; generated protobuf codecs only enforce wire encoding. The proof of concept estimates progress across both processing phases, uses corpus-derived terminology and returns complete lists within the wire limit. An oversized reply fails with the limit error.

## Timeouts and clocks

A handshake has 5 s to complete, and each outgoing frame 5 s to be written. `Stream::set_write_timeout` changes the frame budget. Reads in an established session have no timeout. They wait until data arrives or the stream shuts down.

The crate reads all time from the stream's clock, the one its reader and writer report. That clock is real by default, and it drives every deadline and the check of the attestation's validity. Tests build in-memory streams on a [darkbio-clock](https://github.com/dark-bio/clock-rs) `TestClock` and advance it by hand, so a 5 s timeout passes without waiting 5 s.

## Test vectors

The `vectors` directory holds golden transcripts for validating third-party clients. Each JSON file holds one client scenario, such as stale data before a handshake, an oversized frame or a timeout. It records the server's keys, the client's calls with their results, and every byte read and written. A client under test replays the reads and must produce the recorded writes. Encrypted frames differ between runs, so the replay opens them with the server's keys and compares their contents. There are no server vectors, since the Ark, genuine or emulated, is the only server.

`vectors/health.json` contains invented plaintext protobuf envelopes for every health request and response, processing failures, protected details, digests and request errors. Each case records its direction, hexadecimal bytes and expected wire acceptance. These fixtures pin tags, enum values, id and digest bytes, and optional-message presence. Digest bytes are invented and do not test HMAC computation. Application validation, including the 32-byte digest requirement, is separate from wire acceptance. The same cases seed the envelope fuzzer.

`make generate`, `make vectors` and `make fuzz-seeds` regenerate the bindings, vectors and seeds. Set `CARGO_NET_OFFLINE=true` to use cached dependencies. Vectors and seeds require cargo-nextest. CI checks that regeneration leaves the tracked artifacts unchanged.

## Stability

The protocol is still evolving, from the Rust API through the transport to the protobuf messages. This crate is published so other software can talk to Arks. Expect frequent breaking changes, which Ark Hub, the Dark Bio cloud and the `ark` command line tool may roll out at any time.

## License

This library is licensed under the [BSD 3-Clause License](https://github.com/dark-bio/wire-rs/blob/main/LICENSE).
