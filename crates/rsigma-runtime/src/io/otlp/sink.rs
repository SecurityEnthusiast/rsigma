//! OTLP output sink: export evaluation results to an OpenTelemetry collector
//! over OTLP/HTTP (protobuf) or OTLP/gRPC.

use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, logs_service_client::LogsServiceClient,
};
use prost::Message;
use tonic::codec::CompressionEncoding;
use tonic::transport::Channel;

use rsigma_eval::ProcessResult;

use super::convert::evaluation_results_to_logs_request;
use crate::error::RuntimeError;

/// OTLP transport, selected by the sink URL scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtlpProtocol {
    /// OTLP/gRPC. Default OTLP port 4317.
    Grpc,
    /// OTLP/HTTP with protobuf encoding. Default OTLP port 4318, path `/v1/logs`.
    Http,
}

enum Transport {
    Http {
        client: reqwest::Client,
        url: String,
        gzip: bool,
    },
    Grpc {
        client: LogsServiceClient<Channel>,
    },
}

/// Exports detection and correlation results to an OTLP collector.
///
/// The gRPC channel connects lazily, so a collector that is not yet reachable
/// does not fail daemon startup; delivery failures are surfaced to the
/// delivery layer, which retries and ultimately routes to the DLQ.
pub struct OtlpSink {
    transport: Transport,
}

impl OtlpSink {
    /// Build an OTLP sink targeting `endpoint` (`host:port`). `gzip` enables
    /// payload compression on the wire.
    pub fn new(protocol: OtlpProtocol, endpoint: &str, gzip: bool) -> Result<Self, RuntimeError> {
        let transport = match protocol {
            OtlpProtocol::Http => Transport::Http {
                client: reqwest::Client::new(),
                url: format!("http://{}/v1/logs", endpoint.trim_end_matches('/')),
                gzip,
            },
            OtlpProtocol::Grpc => {
                let channel = Channel::from_shared(format!("http://{endpoint}"))
                    .map_err(|e| RuntimeError::Io(std::io::Error::other(e)))?
                    .connect_lazy();
                let mut client = LogsServiceClient::new(channel);
                if gzip {
                    client = client
                        .send_compressed(CompressionEncoding::Gzip)
                        .accept_compressed(CompressionEncoding::Gzip);
                }
                Transport::Grpc { client }
            }
        };
        Ok(OtlpSink { transport })
    }

    /// Serialize and export a batch of results to the collector.
    pub async fn send(&mut self, result: &ProcessResult) -> Result<(), RuntimeError> {
        if result.is_empty() {
            return Ok(());
        }
        self.export(evaluation_results_to_logs_request(result))
            .await
    }

    /// Export a pre-serialized line as a single OTLP log-record body. Used when
    /// an OTLP sink is configured as a DLQ target.
    pub async fn send_raw(&mut self, json: &str) -> Result<(), RuntimeError> {
        use opentelemetry_proto::tonic::{
            common::v1::{AnyValue, any_value},
            logs::v1::{LogRecord, ResourceLogs, ScopeLogs},
        };
        let request = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                scope_logs: vec![ScopeLogs {
                    log_records: vec![LogRecord {
                        body: Some(AnyValue {
                            value: Some(any_value::Value::StringValue(json.to_string())),
                        }),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        self.export(request).await
    }

    async fn export(&mut self, request: ExportLogsServiceRequest) -> Result<(), RuntimeError> {
        match &mut self.transport {
            Transport::Http { client, url, gzip } => {
                let mut builder = client
                    .post(url.as_str())
                    .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf");
                let body = if *gzip {
                    builder = builder.header(reqwest::header::CONTENT_ENCODING, "gzip");
                    gzip_compress(&request.encode_to_vec())?
                } else {
                    request.encode_to_vec()
                };
                let response = builder
                    .body(body)
                    .send()
                    .await
                    .map_err(|e| RuntimeError::Io(std::io::Error::other(e)))?;
                if !response.status().is_success() {
                    return Err(RuntimeError::Io(std::io::Error::other(format!(
                        "OTLP/HTTP export returned status {}",
                        response.status()
                    ))));
                }
                Ok(())
            }
            Transport::Grpc { client } => {
                client
                    .export(request)
                    .await
                    .map_err(|e| RuntimeError::Io(std::io::Error::other(e)))?;
                Ok(())
            }
        }
    }
}

fn gzip_compress(data: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}
