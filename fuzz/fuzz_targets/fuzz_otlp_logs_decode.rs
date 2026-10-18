#![no_main]
use libfuzzer_sys::fuzz_target;
use prost::Message;
use rsigma_runtime::{ExportLogsServiceRequest, logs_request_to_raw_events};

// `POST /v1/logs` and the gRPC `LogsService` decode untrusted protobuf and
// flatten every log record to a JSON event. Decoding must fail cleanly, and
// any request that decodes must convert to valid JSON without panicking.
fuzz_target!(|data: &[u8]| {
    let Ok(request) = ExportLogsServiceRequest::decode(data) else {
        return;
    };
    for event in logs_request_to_raw_events(&request) {
        serde_json::from_str::<serde_json::Value>(&event.payload)
            .expect("a converted OTLP log record is valid JSON");
    }
});
