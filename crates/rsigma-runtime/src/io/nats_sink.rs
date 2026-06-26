use std::collections::HashSet;

use async_nats::jetstream;
use async_nats::subject::Subject;
use parking_lot::Mutex;

use rsigma_eval::ProcessResult;

use crate::error::RuntimeError;

use super::nats_config::NatsConnectConfig;
use super::nats_source::derive_nats_name;

/// Publishes ProcessResult as NDJSON to a NATS JetStream subject.
///
/// Uses JetStream `publish` with publish-ack confirmation to guarantee that the
/// NATS server has persisted each message. This completes the at-least-once
/// guarantee end-to-end: the source acks only after this sink's JetStream
/// publish is confirmed.
pub struct NatsSink {
    jetstream: jetstream::Context,
    subject: Subject,
    /// Subjects whose JetStream stream has been ensured, so an incident subject
    /// override only triggers stream creation once.
    ensured: Mutex<HashSet<String>>,
}

impl NatsSink {
    /// Connect to NATS and prepare to publish to a JetStream subject.
    ///
    /// Creates or reuses the JetStream stream for the given subject, then
    /// publishes via `jetstream::Context::publish` for server-confirmed delivery.
    pub async fn connect(
        config: &NatsConnectConfig,
        subject: &str,
    ) -> Result<Self, async_nats::Error> {
        let client = config.connect().await?;
        let js = jetstream::new(client);

        let stream_name = derive_nats_name("rsigma", subject);

        js.get_or_create_stream(jetstream::stream::Config {
            name: stream_name,
            subjects: vec![subject.to_string()],
            ..Default::default()
        })
        .await?;

        let ensured = Mutex::new(HashSet::from([subject.to_string()]));
        Ok(NatsSink {
            jetstream: js,
            subject: Subject::from(subject),
            ensured,
        })
    }

    /// Serialize and publish a ProcessResult to the configured JetStream subject.
    ///
    /// Each message is published with publish-ack: the call blocks until the
    /// server confirms persistence, or returns an error on failure.
    pub async fn send(&self, result: &ProcessResult) -> Result<(), RuntimeError> {
        if result.is_empty() {
            return Ok(());
        }

        let mut published = 0_usize;
        for m in result {
            let json = serde_json::to_string(m)?;
            self.publish_one(&self.subject, &json).await?;
            published += 1;
        }

        tracing::debug!(
            subject = %self.subject,
            messages = published,
            "NATS messages published",
        );
        Ok(())
    }

    /// Publish a pre-serialized JSON string directly to the JetStream subject.
    pub async fn send_raw(&self, json: &str) -> Result<(), RuntimeError> {
        self.publish_one(&self.subject, json).await?;
        tracing::debug!(subject = %self.subject, "NATS message published (raw)");
        Ok(())
    }

    /// Publish an incident line, optionally to a dedicated subject override so
    /// incident consumers can subscribe without filtering the detection stream.
    pub async fn send_incident(
        &self,
        json: &str,
        subject_override: Option<&str>,
    ) -> Result<(), RuntimeError> {
        match subject_override {
            Some(subject) => {
                self.ensure_stream(subject).await?;
                self.publish_one(&Subject::from(subject.to_string()), json)
                    .await
            }
            None => self.publish_one(&self.subject, json).await,
        }
    }

    /// Ensure a JetStream stream exists for `subject`, once per subject.
    async fn ensure_stream(&self, subject: &str) -> Result<(), RuntimeError> {
        if self.ensured.lock().contains(subject) {
            return Ok(());
        }
        let stream_name = derive_nats_name("rsigma", subject);
        self.jetstream
            .get_or_create_stream(jetstream::stream::Config {
                name: stream_name,
                subjects: vec![subject.to_string()],
                ..Default::default()
            })
            .await
            .map_err(|e| {
                tracing::warn!(subject, error = %e, "NATS incident stream ensure failed");
                RuntimeError::Io(std::io::Error::other(e))
            })?;
        self.ensured.lock().insert(subject.to_string());
        Ok(())
    }

    /// Publish a single JSON payload to `subject`, logging on failure.
    async fn publish_one(&self, subject: &Subject, json: &str) -> Result<(), RuntimeError> {
        let ack = self
            .jetstream
            .publish(subject.clone(), json.to_string().into())
            .await
            .map_err(|e| {
                tracing::warn!(subject = %subject, error = %e, "NATS publish failed");
                RuntimeError::Io(std::io::Error::other(e))
            })?;
        ack.await.map_err(|e| {
            tracing::warn!(subject = %subject, error = %e, "NATS publish ack failed");
            RuntimeError::Io(std::io::Error::other(e))
        })?;
        Ok(())
    }
}
