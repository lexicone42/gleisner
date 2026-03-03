//! Needs negotiation protocol for inner Claude ↔ management Claude coordination.
//!
//! During a sandboxed session, the inner Claude may discover it needs resources
//! that weren't included in the original forge composition (a new package, network
//! access to an unexpected host, a filesystem path not in the policy). Rather than
//! failing, it can write a [`NeedsRequest`] to a well-known path and wait for
//! a [`NeedsResponse`] from the management Claude or an automated watcher.
//!
//! # Protocol
//!
//! ```text
//! Inner Claude                     Watcher / Management Claude
//! ─────────────                    ───────────────────────────
//!   writes .gleisner/needs-request.json
//!                            ──→   reads request
//!                                  evaluates against forge policy
//!                                  applies approved changes
//!   reads .gleisner/needs-response.json
//!                            ←──   writes response
//!   continues with new resources
//! ```
//!
//! # Trust model
//!
//! - Requests are **advisory**: the inner Claude explains *why* it needs something
//! - Approval is **auditable**: every decision is recorded in the response with a reason
//! - Changes are **attested**: approved modifications appear in the session manifest
//! - Boundaries are **enforced**: the watcher cannot grant access beyond the profile's
//!   maximum bounds (a request for `/etc/shadow` will always be denied)
//!
//! # File paths
//!
//! - Request: `.gleisner/needs-request.json` (inner Claude writes)
//! - Response: `.gleisner/needs-response.json` (watcher writes)
//! - Negotiation log: `.gleisner/negotiation-log.jsonl` (append-only audit trail)

use std::path::{Path, PathBuf};

/// Schema version for the needs request format.
pub const REQUEST_SCHEMA: &str = "gleisner.dev/needs-request/v1";

/// Schema version for the needs response format.
pub const RESPONSE_SCHEMA: &str = "gleisner.dev/needs-response/v1";

/// Well-known filename for needs requests (relative to `.gleisner/`).
pub const REQUEST_FILENAME: &str = "needs-request.json";

/// Well-known filename for needs responses (relative to `.gleisner/`).
pub const RESPONSE_FILENAME: &str = "needs-response.json";

/// Well-known filename for the negotiation audit log (relative to `.gleisner/`).
pub const NEGOTIATION_LOG_FILENAME: &str = "negotiation-log.jsonl";

/// A request from the inner Claude for additional resources.
///
/// Written to `.gleisner/needs-request.json` inside the sandbox. The inner
/// Claude should write the full request atomically (write to temp file, rename)
/// to avoid partial reads by the watcher.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NeedsRequest {
    /// Schema identifier for version negotiation.
    pub schema: String,
    /// ISO 8601 timestamp when the request was made.
    pub requested_at: String,
    /// Session identifier (matches the session manifest).
    pub session_id: String,
    /// Sequence number for this request (monotonically increasing).
    /// Allows multiple negotiation rounds within a session.
    pub sequence: u32,
    /// The resources being requested.
    pub needs: Vec<NeedItem>,
    /// Free-form context from the inner Claude explaining why these
    /// resources are needed. The management Claude uses this to make
    /// an informed approval decision.
    pub context: String,
}

/// A single resource being requested.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NeedItem {
    /// Request a minimal.dev package be added to the environment.
    Package {
        /// Package name (as it appears in the minimal.dev tree).
        name: String,
        /// Why this package is needed.
        reason: String,
    },
    /// Request network access to a specific host.
    Network {
        /// Hostname or IP.
        host: String,
        /// Port number.
        port: u16,
        /// Protocol (tcp/udp).
        #[serde(default = "default_protocol")]
        protocol: String,
        /// Why this network access is needed.
        reason: String,
    },
    /// Request a filesystem path be added to the sandbox.
    Filesystem {
        /// Path to mount.
        path: String,
        /// Whether read-only access is sufficient.
        read_only: bool,
        /// Why this path is needed.
        reason: String,
    },
    /// Request an environment variable be set.
    Environment {
        /// Variable name.
        name: String,
        /// Whether the value is sensitive (should be redacted in logs).
        #[serde(default)]
        sensitive: bool,
        /// Why this variable is needed.
        reason: String,
    },
}

/// A response from the management Claude or automated watcher.
///
/// Written to `.gleisner/needs-response.json`. The inner Claude polls
/// for this file after writing a request.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NeedsResponse {
    /// Schema identifier for version negotiation.
    pub schema: String,
    /// ISO 8601 timestamp when the response was made.
    pub responded_at: String,
    /// Session identifier (must match the request).
    pub session_id: String,
    /// Sequence number (must match the request).
    pub sequence: u32,
    /// Per-item decisions.
    pub decisions: Vec<NeedDecision>,
    /// Optional message from the management Claude to the inner Claude.
    pub message: Option<String>,
}

/// A decision on a single need item.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NeedDecision {
    /// Which need this decision is for (type:identifier format).
    /// E.g., "package:openssh", "network:github.com:443", "<filesystem:/data>".
    pub need_id: String,
    /// Whether the need was approved.
    pub approved: bool,
    /// Whether the approved change has been applied to the sandbox.
    /// False if approved but waiting for manual application.
    pub applied: bool,
    /// Reason for the decision (especially important for denials).
    pub reason: Option<String>,
}

impl NeedsRequest {
    /// Create a new needs request.
    pub fn new(session_id: &str, sequence: u32, context: &str) -> Self {
        Self {
            schema: REQUEST_SCHEMA.to_string(),
            requested_at: chrono::Utc::now().to_rfc3339(),
            session_id: session_id.to_string(),
            sequence,
            needs: Vec::new(),
            context: context.to_string(),
        }
    }

    /// Add a package need.
    pub fn add_package(&mut self, name: &str, reason: &str) -> &mut Self {
        self.needs.push(NeedItem::Package {
            name: name.to_string(),
            reason: reason.to_string(),
        });
        self
    }

    /// Add a network need.
    pub fn add_network(&mut self, host: &str, port: u16, reason: &str) -> &mut Self {
        self.needs.push(NeedItem::Network {
            host: host.to_string(),
            port,
            protocol: "tcp".to_string(),
            reason: reason.to_string(),
        });
        self
    }

    /// Add a filesystem need.
    pub fn add_filesystem(&mut self, path: &str, read_only: bool, reason: &str) -> &mut Self {
        self.needs.push(NeedItem::Filesystem {
            path: path.to_string(),
            read_only,
            reason: reason.to_string(),
        });
        self
    }

    /// Generate a need ID for a given need item.
    pub fn need_id(item: &NeedItem) -> String {
        match item {
            NeedItem::Package { name, .. } => format!("package:{name}"),
            NeedItem::Network { host, port, .. } => format!("network:{host}:{port}"),
            NeedItem::Filesystem { path, .. } => format!("filesystem:{path}"),
            NeedItem::Environment { name, .. } => format!("env:{name}"),
        }
    }

    /// Write this request atomically to the given directory.
    ///
    /// Uses write-to-temp + rename to avoid partial reads.
    pub fn write_to(&self, gleisner_dir: &Path) -> Result<PathBuf, std::io::Error> {
        let target = gleisner_dir.join(REQUEST_FILENAME);
        let tmp = gleisner_dir.join(format!(".{REQUEST_FILENAME}.tmp"));

        std::fs::create_dir_all(gleisner_dir)?;
        std::fs::write(
            &tmp,
            serde_json::to_string_pretty(self)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
        )?;
        std::fs::rename(&tmp, &target)?;

        Ok(target)
    }
}

impl NeedsResponse {
    /// Create a response for a given request.
    pub fn for_request(request: &NeedsRequest) -> Self {
        Self {
            schema: RESPONSE_SCHEMA.to_string(),
            responded_at: chrono::Utc::now().to_rfc3339(),
            session_id: request.session_id.clone(),
            sequence: request.sequence,
            decisions: Vec::new(),
            message: None,
        }
    }

    /// Approve a need item.
    pub fn approve(&mut self, need_id: &str, applied: bool, reason: Option<&str>) -> &mut Self {
        self.decisions.push(NeedDecision {
            need_id: need_id.to_string(),
            approved: true,
            applied,
            reason: reason.map(String::from),
        });
        self
    }

    /// Deny a need item.
    pub fn deny(&mut self, need_id: &str, reason: &str) -> &mut Self {
        self.decisions.push(NeedDecision {
            need_id: need_id.to_string(),
            approved: false,
            applied: false,
            reason: Some(reason.to_string()),
        });
        self
    }

    /// Write this response atomically to the given directory.
    pub fn write_to(&self, gleisner_dir: &Path) -> Result<PathBuf, std::io::Error> {
        let target = gleisner_dir.join(RESPONSE_FILENAME);
        let tmp = gleisner_dir.join(format!(".{RESPONSE_FILENAME}.tmp"));

        std::fs::create_dir_all(gleisner_dir)?;
        std::fs::write(
            &tmp,
            serde_json::to_string_pretty(self)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
        )?;
        std::fs::rename(&tmp, &target)?;

        Ok(target)
    }
}

/// Read a needs request from the well-known path.
///
/// Returns `None` if the file doesn't exist yet.
pub fn read_request(gleisner_dir: &Path) -> Result<Option<NeedsRequest>, std::io::Error> {
    let path = gleisner_dir.join(REQUEST_FILENAME);
    match std::fs::read_to_string(&path) {
        Ok(content) => {
            let request: NeedsRequest = serde_json::from_str(&content)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            Ok(Some(request))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Read a needs response from the well-known path.
///
/// Returns `None` if the file doesn't exist yet.
pub fn read_response(gleisner_dir: &Path) -> Result<Option<NeedsResponse>, std::io::Error> {
    let path = gleisner_dir.join(RESPONSE_FILENAME);
    match std::fs::read_to_string(&path) {
        Ok(content) => {
            let response: NeedsResponse = serde_json::from_str(&content)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            Ok(Some(response))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Append a negotiation event to the audit log.
///
/// Both requests and responses are logged as JSONL entries for post-session analysis.
pub fn append_to_log(gleisner_dir: &Path, event: &serde_json::Value) -> Result<(), std::io::Error> {
    use std::io::Write;

    let path = gleisner_dir.join(NEGOTIATION_LOG_FILENAME);
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;

    let line = serde_json::to_string(event)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    writeln!(file, "{line}")?;

    Ok(())
}

fn default_protocol() -> String {
    "tcp".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrips_json() {
        let mut req = NeedsRequest::new("session-001", 1, "I need SSH to clone a private repo");
        req.add_package("openssh", "need SSH for git clone");
        req.add_network("github.com", 443, "clone private repository");
        req.add_filesystem("/data/models", true, "read pre-trained model weights");

        let json = serde_json::to_string_pretty(&req).unwrap();
        let parsed: NeedsRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.schema, REQUEST_SCHEMA);
        assert_eq!(parsed.session_id, "session-001");
        assert_eq!(parsed.sequence, 1);
        assert_eq!(parsed.needs.len(), 3);
    }

    #[test]
    fn response_roundtrips_json() {
        let req = NeedsRequest::new("session-001", 1, "test");
        let mut resp = NeedsResponse::for_request(&req);
        resp.approve("package:openssh", true, Some("source provenance verified"));
        resp.deny("network:evil.com:443", "not in allowed hosts");

        let json = serde_json::to_string_pretty(&resp).unwrap();
        let parsed: NeedsResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.decisions.len(), 2);
        assert!(parsed.decisions[0].approved);
        assert!(!parsed.decisions[1].approved);
        assert_eq!(
            parsed.decisions[1].reason.as_deref(),
            Some("not in allowed hosts")
        );
    }

    #[test]
    fn need_id_generation() {
        assert_eq!(
            NeedsRequest::need_id(&NeedItem::Package {
                name: "openssh".to_string(),
                reason: String::new()
            }),
            "package:openssh"
        );
        assert_eq!(
            NeedsRequest::need_id(&NeedItem::Network {
                host: "github.com".to_string(),
                port: 443,
                protocol: "tcp".to_string(),
                reason: String::new()
            }),
            "network:github.com:443"
        );
        assert_eq!(
            NeedsRequest::need_id(&NeedItem::Filesystem {
                path: "/data".to_string(),
                read_only: true,
                reason: String::new()
            }),
            "filesystem:/data"
        );
    }

    #[test]
    fn write_and_read_request() {
        let dir = tempfile::tempdir().unwrap();
        let gleisner_dir = dir.path().join(".gleisner");

        let mut req = NeedsRequest::new("session-002", 1, "need git");
        req.add_package("git", "version control");

        req.write_to(&gleisner_dir).unwrap();

        let read_back = read_request(&gleisner_dir).unwrap();
        assert!(read_back.is_some());
        let read_back = read_back.unwrap();
        assert_eq!(read_back.session_id, "session-002");
        assert_eq!(read_back.needs.len(), 1);
    }

    #[test]
    fn write_and_read_response() {
        let dir = tempfile::tempdir().unwrap();
        let gleisner_dir = dir.path().join(".gleisner");

        let req = NeedsRequest::new("session-003", 1, "test");
        let mut resp = NeedsResponse::for_request(&req);
        resp.approve("package:git", true, None);
        resp.message = Some("Approved — git has verified provenance".to_string());

        resp.write_to(&gleisner_dir).unwrap();

        let read_back = read_response(&gleisner_dir).unwrap();
        assert!(read_back.is_some());
        let read_back = read_back.unwrap();
        assert_eq!(read_back.decisions.len(), 1);
        assert!(read_back.decisions[0].approved);
        assert!(read_back.message.unwrap().contains("provenance"));
    }

    #[test]
    fn read_missing_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let gleisner_dir = dir.path().join(".gleisner");
        std::fs::create_dir_all(&gleisner_dir).unwrap();

        assert!(read_request(&gleisner_dir).unwrap().is_none());
        assert!(read_response(&gleisner_dir).unwrap().is_none());
    }

    #[test]
    fn audit_log_appends() {
        let dir = tempfile::tempdir().unwrap();
        let gleisner_dir = dir.path().join(".gleisner");
        std::fs::create_dir_all(&gleisner_dir).unwrap();

        append_to_log(
            &gleisner_dir,
            &serde_json::json!({"event": "request", "seq": 1}),
        )
        .unwrap();
        append_to_log(
            &gleisner_dir,
            &serde_json::json!({"event": "response", "seq": 1}),
        )
        .unwrap();

        let content = std::fs::read_to_string(gleisner_dir.join(NEGOTIATION_LOG_FILENAME)).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
    }
}
