//! `CycloneDX` 1.6 SBOM generation from forge evaluation results.
//!
//! Converts [`ForgeAttestation`] package metadata into a `CycloneDX` 1.6
//! BOM document. The key `CycloneDX` 1.6 feature used here is
//! **Declarations** — structured attestation claims with evidence that
//! can carry formal verification proof status.
//!
//! # Proof-carrying SBOMs
//!
//! When a package declares [`VerifiedProperty`] entries (formal proofs
//! checked by a proof kernel like Lean 4), those are represented as
//! `CycloneDX` declarations with:
//! - **Claims**: The verified property (e.g., "roundtrip correctness")
//! - **Evidence**: The proof artifact hash and URI
//! - **Conformance**: 1.0 for forge-verified proofs, 0.0 for unchecked
//!
//! This is, to our knowledge, the first implementation of proof-carrying
//! evidence in a standard SBOM format.
//!
//! See: Leo de Moura, "When AI Writes the World's Software, Who Verifies It?"
//! <https://leodemoura.github.io/blog/2026/02/28/when-ai-writes-the-worlds-software.html>

use chrono::Utc;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::attest::{
    ForgeAttestation, PackageMetadata, PolicyComplianceProof, SourceProvenance, VerifiedProperty,
};

// ────────────────────────────────────────────────────────────────────
// CycloneDX 1.6 document types
// ────────────────────────────────────────────────────────────────────

/// Top-level `CycloneDX` 1.6 BOM document.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxBom {
    /// Always `"CycloneDX"`.
    pub bom_format: &'static str,
    /// Specification version.
    pub spec_version: &'static str,
    /// BOM version (incremented on updates).
    pub version: u32,
    /// Unique serial number for this BOM instance.
    pub serial_number: String,
    /// BOM metadata.
    pub metadata: BomMetadata,
    /// Software components (packages).
    pub components: Vec<Component>,
    /// Formal verification declarations (`CycloneDX` 1.6 attestations).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declarations: Option<Declarations>,
}

/// BOM metadata block.
#[derive(Debug, Clone, Serialize)]
pub struct BomMetadata {
    /// ISO-8601 timestamp of generation.
    pub timestamp: String,
    /// Tools that generated the BOM.
    pub tools: Tools,
    /// The component this BOM describes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component: Option<Component>,
}

/// `CycloneDX` 1.6 tools block (components format).
#[derive(Debug, Clone, Serialize)]
pub struct Tools {
    /// Tool components.
    pub components: Vec<ToolComponent>,
}

/// A tool component in the metadata.
#[derive(Debug, Clone, Serialize)]
pub struct ToolComponent {
    /// Component type.
    #[serde(rename = "type")]
    pub type_: &'static str,
    /// Tool author/vendor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    /// Tool name.
    pub name: String,
    /// Tool version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// A software component in the BOM.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Component {
    /// Component type.
    #[serde(rename = "type")]
    pub type_: &'static str,
    /// Unique BOM reference for this component.
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    /// Package name.
    pub name: String,
    /// Package version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Package URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    /// Cryptographic hashes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hashes: Vec<Hash>,
    /// External references (source repos, proof URIs).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub external_references: Vec<ExternalReference>,
    /// Custom properties.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub properties: Vec<Property>,
}

/// A cryptographic hash.
#[derive(Debug, Clone, Serialize)]
pub struct Hash {
    /// Algorithm name (e.g., `"SHA-256"`).
    pub alg: String,
    /// Hex-encoded hash value.
    pub content: String,
}

/// An external reference (VCS, issue tracker, etc.).
#[derive(Debug, Clone, Serialize)]
pub struct ExternalReference {
    /// Reference type.
    #[serde(rename = "type")]
    pub type_: &'static str,
    /// URL.
    pub url: String,
    /// Human-readable comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// A name-value property.
#[derive(Debug, Clone, Serialize)]
pub struct Property {
    /// Property name (namespace:key format).
    pub name: String,
    /// Property value.
    pub value: String,
}

// ────────────────────────────────────────────────────────────────────
// CycloneDX 1.6 Declarations (attestation model)
// ────────────────────────────────────────────────────────────────────

/// `CycloneDX` 1.6 declarations block.
///
/// Contains structured attestation claims with evidence about
/// components. This is where formal verification proofs are recorded.
#[derive(Debug, Clone, Serialize)]
pub struct Declarations {
    /// Assessors — entities that evaluated the claims.
    pub assessors: Vec<Assessor>,
    /// Attestations — groups of claims by an assessor.
    pub attestations: Vec<Attestation>,
}

/// An assessor (entity that evaluated claims).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Assessor {
    /// Unique BOM reference.
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    /// Whether the assessment was performed by an automated tool.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub third_party: Option<bool>,
    /// Organization that performed the assessment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<Organization>,
}

/// An organization.
#[derive(Debug, Clone, Serialize)]
pub struct Organization {
    /// Organization name.
    pub name: String,
    /// URLs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub url: Vec<String>,
}

/// An attestation — a group of claims made by an assessor.
#[derive(Debug, Clone, Serialize)]
pub struct Attestation {
    /// Summary of this attestation group.
    pub summary: String,
    /// The assessor who made these claims.
    pub assessor: String,
    /// Timestamp of the attestation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    /// Individual claims.
    pub map: Vec<AttestationClaim>,
}

/// A single attestation claim about a requirement.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationClaim {
    /// Requirement identifier.
    pub requirement: String,
    /// Claim details.
    pub claims: Vec<Claim>,
    /// Counter-claims (currently unused).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub counter_claims: Vec<Claim>,
    /// Conformance score (0.0 to 1.0).
    pub conformance: Conformance,
}

/// A claim with supporting evidence.
#[derive(Debug, Clone, Serialize)]
pub struct Claim {
    /// Unique BOM reference.
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    /// The component this claim is about.
    pub target: String,
    /// Predicate text (what is claimed).
    pub predicate: String,
    /// Reasoning or methodology.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<String>,
    /// Supporting evidence.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

/// Evidence supporting a claim.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    /// Unique BOM reference.
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    /// Description of the evidence.
    pub description: String,
    /// Custom properties (proof system, kernel version, etc.).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub properties: Vec<Property>,
    /// Resource references (proof artifact URIs/hashes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<EvidenceData>>,
}

/// Data attached to evidence (proof artifacts).
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceData {
    /// Human-readable name.
    pub name: String,
    /// Content type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// Value or reference.
    pub value: String,
}

/// Conformance score for an attestation claim.
#[derive(Debug, Clone, Serialize)]
pub struct Conformance {
    /// Score from 0.0 (not conformant) to 1.0 (fully conformant).
    pub score: f64,
    /// Confidence in the score (0.0 to 1.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
}

// ────────────────────────────────────────────────────────────────────
// Conversion: ForgeAttestation → CycloneDX 1.6
// ────────────────────────────────────────────────────────────────────

/// Convert a [`ForgeAttestation`] into a `CycloneDX` 1.6 BOM.
///
/// Each package in `package_metadata` becomes a component. Packages
/// with [`VerifiedProperty`] entries generate `CycloneDX` declarations
/// with proof evidence.
pub fn forge_to_cyclonedx(attestation: &ForgeAttestation) -> CycloneDxBom {
    let components: Vec<Component> = attestation
        .package_metadata
        .iter()
        .map(metadata_to_component)
        .collect();

    let declarations = build_declarations(attestation);

    CycloneDxBom {
        bom_format: "CycloneDX",
        spec_version: "1.6",
        version: 1,
        serial_number: generate_serial_number(&attestation.package_metadata),
        metadata: BomMetadata {
            timestamp: Utc::now().to_rfc3339(),
            tools: Tools {
                components: vec![ToolComponent {
                    type_: "application",
                    author: Some("Gleisner".to_owned()),
                    name: "gleisner-forge".to_owned(),
                    version: Some(env!("CARGO_PKG_VERSION").to_owned()),
                }],
            },
            component: None,
        },
        components,
        declarations,
    }
}

/// Convert a single [`PackageMetadata`] into a `CycloneDX` component.
fn metadata_to_component(meta: &PackageMetadata) -> Component {
    let bom_ref = format!("pkg-{}", meta.name);

    let mut hashes = Vec::new();
    for source in &meta.source_urls {
        if !source.sha256.is_empty() {
            hashes.push(Hash {
                alg: "SHA-256".to_owned(),
                content: source.sha256.clone(),
            });
        }
    }

    let mut external_refs = Vec::new();

    // Source repository
    match &meta.source_provenance {
        Some(SourceProvenance::GithubRepo { owner, repo }) => {
            external_refs.push(ExternalReference {
                type_: "vcs",
                url: format!("https://github.com/{owner}/{repo}"),
                comment: None,
            });
        }
        Some(SourceProvenance::GnuProject { name }) => {
            external_refs.push(ExternalReference {
                type_: "vcs",
                url: format!("https://ftp.gnu.org/gnu/{name}/"),
                comment: Some("GNU project".to_owned()),
            });
        }
        None => {}
    }

    // Source download URLs
    for source in &meta.source_urls {
        if source.uri.starts_with("http") || source.uri.starts_with("gs://") {
            external_refs.push(ExternalReference {
                type_: "distribution",
                url: source.uri.clone(),
                comment: None,
            });
        }
    }

    // Proof artifact URIs
    for prop in &meta.verified_properties {
        if let Some(uri) = &prop.proof_uri {
            external_refs.push(ExternalReference {
                type_: "evidence",
                url: uri.clone(),
                comment: Some(format!(
                    "Formal proof: {} ({})",
                    prop.property, prop.proof_system
                )),
            });
        }
    }

    let mut properties = Vec::new();

    // Repology cross-distro tracking
    if let Some(repology) = &meta.repology_project {
        properties.push(Property {
            name: "cdx:forge:repology-project".to_owned(),
            value: repology.clone(),
        });
    }

    // Package ecosystem marker
    properties.push(Property {
        name: "cdx:forge:ecosystem".to_owned(),
        value: "minimal.dev".to_owned(),
    });

    // Verification summary per component
    if !meta.verified_properties.is_empty() {
        let verified = meta
            .verified_properties
            .iter()
            .filter(|p| p.verified_by_forge == Some(true))
            .count();
        properties.push(Property {
            name: "cdx:forge:verified-properties".to_owned(),
            value: format!("{}/{}", verified, meta.verified_properties.len()),
        });
    }

    Component {
        type_: "library",
        bom_ref,
        name: meta.name.clone(),
        version: meta.upstream_version.clone(),
        purl: Some(meta.purl.clone()),
        hashes,
        external_references: external_refs,
        properties,
    }
}

/// Build `CycloneDX` 1.6 declarations from verified properties and policy compliance.
///
/// Returns `None` if there are neither formal proofs nor policy compliance results.
fn build_declarations(attestation: &ForgeAttestation) -> Option<Declarations> {
    let packages_with_proofs: Vec<&PackageMetadata> = attestation
        .package_metadata
        .iter()
        .filter(|m| !m.verified_properties.is_empty())
        .collect();

    let has_proofs = !packages_with_proofs.is_empty();
    let has_compliance = !attestation.policy_compliance.is_empty();

    if !has_proofs && !has_compliance {
        return None;
    }

    // Assessors: the forge itself (always present)
    let mut assessors = vec![Assessor {
        bom_ref: "assessor-gleisner-forge".to_owned(),
        third_party: Some(false),
        organization: Some(Organization {
            name: "gleisner-forge".to_owned(),
            url: vec!["https://github.com/lexicone42/gleisner".to_owned()],
        }),
    }];

    let mut attestations = Vec::new();

    // ── Formal verification claims ──────────────────────────
    if has_proofs {
        let mut proof_systems: Vec<String> = packages_with_proofs
            .iter()
            .flat_map(|m| m.verified_properties.iter())
            .map(|p| p.proof_system.clone())
            .collect();
        proof_systems.sort();
        proof_systems.dedup();

        for system in &proof_systems {
            assessors.push(Assessor {
                bom_ref: format!("assessor-kernel-{system}"),
                third_party: Some(true),
                organization: Some(Organization {
                    name: format!("{system} proof kernel"),
                    url: kernel_urls(system),
                }),
            });
        }

        let mut proof_claims = Vec::new();
        for meta in &packages_with_proofs {
            for prop in &meta.verified_properties {
                proof_claims.push(property_to_claim(meta, prop));
            }
        }

        attestations.push(Attestation {
            summary: format!(
                "Formal verification of {} properties across {} packages",
                proof_claims.len(),
                packages_with_proofs.len(),
            ),
            assessor: "assessor-gleisner-forge".to_owned(),
            timestamp: Some(Utc::now().to_rfc3339()),
            map: proof_claims,
        });
    }

    // ── Policy compliance claims ────────────────────────────
    if has_compliance {
        assessors.push(Assessor {
            bom_ref: "assessor-z3-smt".to_owned(),
            third_party: Some(true),
            organization: Some(Organization {
                name: "Z3 SMT Solver".to_owned(),
                url: vec!["https://github.com/Z3Prover/z3".to_owned()],
            }),
        });

        let compliance_claims: Vec<AttestationClaim> = attestation
            .policy_compliance
            .iter()
            .map(policy_compliance_to_claim)
            .collect();

        let compliant_count = attestation
            .policy_compliance
            .iter()
            .filter(|p| p.is_compliant)
            .count();
        let total = attestation.policy_compliance.len();

        attestations.push(Attestation {
            summary: format!("Policy compliance: {compliant_count}/{total} baselines met"),
            assessor: "assessor-z3-smt".to_owned(),
            timestamp: Some(Utc::now().to_rfc3339()),
            map: compliance_claims,
        });
    }

    Some(Declarations {
        assessors,
        attestations,
    })
}

/// Convert a single [`VerifiedProperty`] into a `CycloneDX` attestation claim.
fn property_to_claim(meta: &PackageMetadata, prop: &VerifiedProperty) -> AttestationClaim {
    let claim_ref = format!("claim-{}-{}", meta.name, prop.property);
    let evidence_ref = format!("evidence-{}-{}", meta.name, prop.property);

    let mut evidence_properties = vec![
        Property {
            name: "cdx:forge:proof-system".to_owned(),
            value: prop.proof_system.clone(),
        },
        Property {
            name: "cdx:forge:kernel-version".to_owned(),
            value: prop.kernel_version.clone(),
        },
        Property {
            name: "cdx:forge:specification-hash".to_owned(),
            value: prop.specification_hash.clone(),
        },
        Property {
            name: "cdx:forge:proof-hash".to_owned(),
            value: prop.proof_hash.clone(),
        },
    ];

    if let Some(declared) = &prop.declared_proof_hash {
        evidence_properties.push(Property {
            name: "cdx:forge:declared-proof-hash".to_owned(),
            value: declared.clone(),
        });
    }

    if let Some(kernel_ver) = &prop.forge_kernel_version {
        evidence_properties.push(Property {
            name: "cdx:forge:forge-kernel-version".to_owned(),
            value: kernel_ver.clone(),
        });
    }

    let mut evidence_data = Vec::new();
    if let Some(uri) = &prop.proof_uri {
        evidence_data.push(EvidenceData {
            name: "proof-artifact".to_owned(),
            r#type: Some("url".to_owned()),
            value: uri.clone(),
        });
    }
    evidence_data.push(EvidenceData {
        name: "proof-hash".to_owned(),
        r#type: Some("sha256".to_owned()),
        value: prop.proof_hash.clone(),
    });
    evidence_data.push(EvidenceData {
        name: "specification-hash".to_owned(),
        r#type: Some("sha256".to_owned()),
        value: prop.specification_hash.clone(),
    });

    // Conformance: 1.0 if forge-verified, 0.0 if unchecked
    let (score, confidence) = match prop.verified_by_forge {
        Some(true) => (1.0, Some(1.0)),  // Mechanically verified — certainty
        Some(false) => (0.0, Some(1.0)), // Verification attempted and failed
        None => (0.0, Some(0.0)),        // Not checked — no confidence
    };

    let verification_status = match prop.verified_by_forge {
        Some(true) => "forge-verified: proof mechanically checked by kernel",
        Some(false) => "verification-failed: proof did not check",
        None => "unchecked: verification not attempted",
    };

    AttestationClaim {
        requirement: format!("formal-verification/{}/{}", meta.name, prop.property),
        claims: vec![Claim {
            bom_ref: claim_ref,
            target: format!("pkg-{}", meta.name),
            predicate: prop.description.clone(),
            reasoning: Some(format!(
                "Property '{}' proved in {} (kernel: {}). Status: {}",
                prop.property, prop.proof_system, prop.kernel_version, verification_status,
            )),
            evidence: vec![Evidence {
                bom_ref: evidence_ref,
                description: format!(
                    "Formal proof artifact for '{}' property of {} — checkable by {} kernel",
                    prop.property, meta.name, prop.proof_system,
                ),
                properties: evidence_properties,
                data: Some(evidence_data),
            }],
        }],
        counter_claims: vec![],
        conformance: Conformance { score, confidence },
    }
}

/// Convert a [`PolicyComplianceProof`] into a `CycloneDX` attestation claim.
///
/// Compliant baselines (UNSAT) produce a claim with conformance 1.0.
/// Non-compliant baselines (SAT) produce a counter-claim with the Z3
/// witness as evidence data.
fn policy_compliance_to_claim(proof: &PolicyComplianceProof) -> AttestationClaim {
    let claim_ref = format!("claim-policy-{}", proof.baseline_name);
    let evidence_ref = format!("evidence-policy-{}", proof.baseline_name);

    let evidence_properties = vec![
        Property {
            name: "cdx:forge:proof-method".to_owned(),
            value: "z3-smt-qf-lia".to_owned(),
        },
        Property {
            name: "cdx:forge:baseline-name".to_owned(),
            value: proof.baseline_name.clone(),
        },
        Property {
            name: "cdx:forge:baseline-description".to_owned(),
            value: proof.baseline_description.clone(),
        },
    ];

    if proof.is_compliant {
        // UNSAT: session policy subsumes baseline
        AttestationClaim {
            requirement: format!("policy-compliance/{}", proof.baseline_name),
            claims: vec![Claim {
                bom_ref: claim_ref,
                target: "session-policy".to_owned(),
                predicate: format!("Session policy meets {} requirements", proof.baseline_name,),
                reasoning: Some(proof.explanation.clone()),
                evidence: vec![Evidence {
                    bom_ref: evidence_ref,
                    description: format!(
                        "Z3 SMT solver proved subsumption: {}",
                        proof.baseline_description,
                    ),
                    properties: evidence_properties,
                    data: None,
                }],
            }],
            counter_claims: vec![],
            conformance: Conformance {
                score: 1.0,
                confidence: Some(1.0),
            },
        }
    } else {
        // SAT: found a witness — counter-claim with counterexample
        let counter_evidence_data = proof.witness.as_ref().map(|witness| {
            vec![EvidenceData {
                name: "counterexample-witness".to_owned(),
                r#type: Some("application/json".to_owned()),
                value: serde_json::to_string_pretty(witness).unwrap_or_default(),
            }]
        });

        AttestationClaim {
            requirement: format!("policy-compliance/{}", proof.baseline_name),
            claims: vec![],
            counter_claims: vec![Claim {
                bom_ref: claim_ref,
                target: "session-policy".to_owned(),
                predicate: format!(
                    "Session policy does NOT meet {} requirements",
                    proof.baseline_name,
                ),
                reasoning: Some(proof.explanation.clone()),
                evidence: vec![Evidence {
                    bom_ref: evidence_ref,
                    description: format!(
                        "Z3 SMT solver found counterexample: {}",
                        proof.baseline_description,
                    ),
                    properties: evidence_properties,
                    data: counter_evidence_data,
                }],
            }],
            conformance: Conformance {
                score: 0.0,
                confidence: Some(1.0),
            },
        }
    }
}

/// Get URLs for known proof system kernels.
fn kernel_urls(system: &str) -> Vec<String> {
    match system {
        "lean4" => vec!["https://github.com/leanprover/lean4".to_owned()],
        "coq" | "rocq" => vec!["https://github.com/coq/coq".to_owned()],
        "isabelle" => vec!["https://isabelle.in.tum.de/".to_owned()],
        _ => vec![],
    }
}

/// Generate a deterministic serial number from package metadata.
fn generate_serial_number(metadata: &[PackageMetadata]) -> String {
    let mut hasher = Sha256::new();
    for meta in metadata {
        hasher.update(meta.name.as_bytes());
        hasher.update(b"@");
        hasher.update(meta.purl.as_bytes());
        hasher.update(b"\n");
    }
    let hash = hasher.finalize();
    let hex = hex::encode(&hash[..16]);
    format!(
        "urn:uuid:{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[4..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..28],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::{ForgeMaterial, VerificationSummary};

    fn sample_attestation() -> ForgeAttestation {
        ForgeAttestation {
            materials: vec![
                ForgeMaterial {
                    uri: "pkg://minimal.dev/zlib".to_owned(),
                    sha256: String::new(),
                },
                ForgeMaterial {
                    uri: "pkg://minimal.dev/curl".to_owned(),
                    sha256: String::new(),
                },
            ],
            subjects: vec![],
            builder_id: "gleisner-forge/0.1.0".to_owned(),
            packages: vec!["zlib".to_owned(), "curl".to_owned()],
            package_metadata: vec![
                PackageMetadata {
                    name: "zlib".to_owned(),
                    upstream_version: Some("1.3.1".to_owned()),
                    source_provenance: Some(SourceProvenance::GithubRepo {
                        owner: "madler".to_owned(),
                        repo: "zlib".to_owned(),
                    }),
                    repology_project: Some("zlib".to_owned()),
                    purl: "pkg:github/madler/zlib@1.3.1".to_owned(),
                    source_urls: vec![ForgeMaterial {
                        uri: "gs://minimal-os/zlib-1.3.1.tar.gz".to_owned(),
                        sha256: "aabbccdd11223344".to_owned(),
                    }],
                    verified_properties: vec![
                        VerifiedProperty {
                            property: "roundtrip".to_owned(),
                            description: "decompress(compress(data)) = data for all inputs"
                                .to_owned(),
                            proof_system: "lean4".to_owned(),
                            kernel_version: "leanprover/lean4:v4.16.0".to_owned(),
                            specification_hash: "sha256:spec1111".to_owned(),
                            proof_hash: "sha256:proof2222".to_owned(),
                            declared_proof_hash: Some("sha256:declared3333".to_owned()),
                            proof_uri: Some(
                                "https://github.com/kim-em/lean-zip/tree/main/Zip".to_owned(),
                            ),
                            verified_by_forge: Some(true),
                            forge_kernel_version: Some("leanprover/lean4:v4.16.0".to_owned()),
                        },
                        VerifiedProperty {
                            property: "no_buffer_overflow".to_owned(),
                            description: "No out-of-bounds memory access in inflate/deflate"
                                .to_owned(),
                            proof_system: "lean4".to_owned(),
                            kernel_version: "leanprover/lean4:v4.16.0".to_owned(),
                            specification_hash: "sha256:spec4444".to_owned(),
                            proof_hash: "sha256:proof5555".to_owned(),
                            declared_proof_hash: None,
                            proof_uri: None,
                            verified_by_forge: None,
                            forge_kernel_version: None,
                        },
                    ],
                },
                PackageMetadata {
                    name: "curl".to_owned(),
                    upstream_version: Some("8.11.0".to_owned()),
                    source_provenance: Some(SourceProvenance::GithubRepo {
                        owner: "curl".to_owned(),
                        repo: "curl".to_owned(),
                    }),
                    repology_project: Some("curl".to_owned()),
                    purl: "pkg:github/curl/curl@8.11.0".to_owned(),
                    source_urls: vec![ForgeMaterial {
                        uri: "gs://minimal-os/curl-8.11.0.tar.gz".to_owned(),
                        sha256: "eeff00112233".to_owned(),
                    }],
                    verified_properties: vec![],
                },
            ],
            verification: Some(VerificationSummary {
                total_properties: 2,
                forge_verified: 1,
                unchecked: 1,
                packages_with_proofs: 1,
                packages_without_proofs: 1,
            }),
            policy_compliance: vec![],
        }
    }

    #[test]
    fn cyclonedx_16_structure() {
        let bom = forge_to_cyclonedx(&sample_attestation());
        assert_eq!(bom.bom_format, "CycloneDX");
        assert_eq!(bom.spec_version, "1.6");
        assert_eq!(bom.version, 1);
        assert!(bom.serial_number.starts_with("urn:uuid:"));
        assert_eq!(bom.components.len(), 2);
    }

    #[test]
    fn components_have_correct_metadata() {
        let bom = forge_to_cyclonedx(&sample_attestation());

        let zlib = &bom.components[0];
        assert_eq!(zlib.name, "zlib");
        assert_eq!(zlib.version.as_deref(), Some("1.3.1"));
        assert_eq!(zlib.purl.as_deref(), Some("pkg:github/madler/zlib@1.3.1"));
        assert_eq!(zlib.bom_ref, "pkg-zlib");
        assert_eq!(zlib.type_, "library");

        // Source hash
        assert_eq!(zlib.hashes.len(), 1);
        assert_eq!(zlib.hashes[0].content, "aabbccdd11223344");

        let curl = &bom.components[1];
        assert_eq!(curl.name, "curl");
        assert_eq!(curl.version.as_deref(), Some("8.11.0"));
        assert_eq!(curl.purl.as_deref(), Some("pkg:github/curl/curl@8.11.0"));
    }

    #[test]
    fn external_references_include_vcs_and_proofs() {
        let bom = forge_to_cyclonedx(&sample_attestation());
        let zlib = &bom.components[0];

        // VCS reference
        let vcs_refs: Vec<_> = zlib
            .external_references
            .iter()
            .filter(|r| r.type_ == "vcs")
            .collect();
        assert_eq!(vcs_refs.len(), 1);
        assert_eq!(vcs_refs[0].url, "https://github.com/madler/zlib");

        // Evidence reference (proof URI)
        let evidence_refs: Vec<_> = zlib
            .external_references
            .iter()
            .filter(|r| r.type_ == "evidence")
            .collect();
        assert_eq!(evidence_refs.len(), 1);
        assert!(evidence_refs[0].url.contains("lean-zip"));
    }

    #[test]
    fn properties_include_ecosystem_and_verification_count() {
        let bom = forge_to_cyclonedx(&sample_attestation());

        let zlib = &bom.components[0];
        let ecosystem = zlib
            .properties
            .iter()
            .find(|p| p.name == "cdx:forge:ecosystem");
        assert_eq!(ecosystem.unwrap().value, "minimal.dev");

        let verified = zlib
            .properties
            .iter()
            .find(|p| p.name == "cdx:forge:verified-properties");
        assert_eq!(verified.unwrap().value, "1/2");

        // curl has no verified properties — no verification count property
        let curl = &bom.components[1];
        let curl_verified = curl
            .properties
            .iter()
            .find(|p| p.name == "cdx:forge:verified-properties");
        assert!(curl_verified.is_none());
    }

    #[test]
    fn declarations_present_for_verified_packages() {
        let bom = forge_to_cyclonedx(&sample_attestation());
        let decl = bom
            .declarations
            .as_ref()
            .expect("declarations should exist");

        // Two assessors: forge + lean4 kernel
        assert_eq!(decl.assessors.len(), 2);
        assert_eq!(decl.assessors[0].bom_ref, "assessor-gleisner-forge");
        assert_eq!(decl.assessors[1].bom_ref, "assessor-kernel-lean4");

        // One attestation entry
        assert_eq!(decl.attestations.len(), 1);
        assert!(decl.attestations[0].summary.contains("2 properties"));
        assert!(decl.attestations[0].summary.contains("1 packages"));
    }

    #[test]
    fn attestation_claims_carry_proof_evidence() {
        let bom = forge_to_cyclonedx(&sample_attestation());
        let decl = bom.declarations.as_ref().unwrap();
        let claims = &decl.attestations[0].map;

        // Two claims: roundtrip + no_buffer_overflow
        assert_eq!(claims.len(), 2);

        let roundtrip = &claims[0];
        assert_eq!(roundtrip.requirement, "formal-verification/zlib/roundtrip");
        assert_eq!(roundtrip.conformance.score, 1.0); // forge-verified
        assert_eq!(roundtrip.conformance.confidence, Some(1.0));

        let claim = &roundtrip.claims[0];
        assert_eq!(claim.target, "pkg-zlib");
        assert_eq!(
            claim.predicate,
            "decompress(compress(data)) = data for all inputs"
        );
        assert!(claim.reasoning.as_ref().unwrap().contains("forge-verified"));

        // Evidence has proof artifact data
        let evidence = &claim.evidence[0];
        assert!(evidence.description.contains("lean4 kernel"));
        let proof_system = evidence
            .properties
            .iter()
            .find(|p| p.name == "cdx:forge:proof-system");
        assert_eq!(proof_system.unwrap().value, "lean4");

        let data = evidence.data.as_ref().unwrap();
        assert!(data.iter().any(|d| d.name == "proof-artifact"));
        assert!(data.iter().any(|d| d.name == "proof-hash"));
        assert!(data.iter().any(|d| d.name == "specification-hash"));
    }

    #[test]
    fn unchecked_property_has_zero_conformance() {
        let bom = forge_to_cyclonedx(&sample_attestation());
        let decl = bom.declarations.as_ref().unwrap();
        let claims = &decl.attestations[0].map;

        let buffer_claim = &claims[1];
        assert_eq!(
            buffer_claim.requirement,
            "formal-verification/zlib/no_buffer_overflow"
        );
        assert_eq!(buffer_claim.conformance.score, 0.0); // unchecked
        assert_eq!(buffer_claim.conformance.confidence, Some(0.0)); // no confidence
    }

    #[test]
    fn no_declarations_when_no_proofs() {
        let attestation = ForgeAttestation {
            materials: vec![],
            subjects: vec![],
            builder_id: "gleisner-forge/0.1.0".to_owned(),
            packages: vec!["curl".to_owned()],
            package_metadata: vec![PackageMetadata {
                name: "curl".to_owned(),
                upstream_version: Some("8.11.0".to_owned()),
                source_provenance: None,
                repology_project: None,
                purl: "pkg:github/curl/curl@8.11.0".to_owned(),
                source_urls: vec![],
                verified_properties: vec![],
            }],
            verification: None,
            policy_compliance: vec![],
        };

        let bom = forge_to_cyclonedx(&attestation);
        assert!(bom.declarations.is_none());
    }

    #[test]
    fn serializes_to_valid_json() {
        let bom = forge_to_cyclonedx(&sample_attestation());
        let json = serde_json::to_string_pretty(&bom).unwrap();

        // Key CycloneDX fields present
        assert!(json.contains("\"bomFormat\""));
        assert!(json.contains("\"specVersion\": \"1.6\""));
        assert!(json.contains("\"declarations\""));
        assert!(json.contains("\"attestations\""));
        assert!(json.contains("\"conformance\""));

        // Proof evidence present
        assert!(json.contains("formal-verification/zlib/roundtrip"));
        assert!(json.contains("lean4"));
        assert!(json.contains("proof-artifact"));

        // Roundtrip: parse back
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["specVersion"], "1.6");
        assert_eq!(parsed["components"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn serial_number_deterministic() {
        let att = sample_attestation();
        let s1 = generate_serial_number(&att.package_metadata);
        let s2 = generate_serial_number(&att.package_metadata);
        assert_eq!(s1, s2);
        assert!(s1.starts_with("urn:uuid:"));
    }

    #[test]
    fn gnu_provenance_generates_correct_external_ref() {
        let attestation = ForgeAttestation {
            materials: vec![],
            subjects: vec![],
            builder_id: "gleisner-forge/0.1.0".to_owned(),
            packages: vec!["bash".to_owned()],
            package_metadata: vec![PackageMetadata {
                name: "bash".to_owned(),
                upstream_version: Some("5.2".to_owned()),
                source_provenance: Some(SourceProvenance::GnuProject {
                    name: "bash".to_owned(),
                }),
                repology_project: Some("bash".to_owned()),
                purl: "pkg:gnu/bash@5.2".to_owned(),
                source_urls: vec![],
                verified_properties: vec![],
            }],
            verification: None,
            policy_compliance: vec![],
        };

        let bom = forge_to_cyclonedx(&attestation);
        let bash = &bom.components[0];
        let vcs = bash
            .external_references
            .iter()
            .find(|r| r.type_ == "vcs")
            .unwrap();
        assert_eq!(vcs.url, "https://ftp.gnu.org/gnu/bash/");
        assert_eq!(vcs.comment.as_deref(), Some("GNU project"));
    }

    // ── Policy compliance SBOM tests ────────────────────────

    fn sample_compliance_proofs() -> Vec<PolicyComplianceProof> {
        use crate::attest::PolicyComplianceProof;
        vec![
            PolicyComplianceProof {
                baseline_name: "slsa-build-l1".to_owned(),
                baseline_description: "SLSA Build Level 1: materials present".to_owned(),
                is_compliant: true,
                witness: None,
                explanation:
                    "Every input accepted by the candidate is also accepted by the baseline."
                        .to_owned(),
            },
            PolicyComplianceProof {
                baseline_name: "slsa-build-l2".to_owned(),
                baseline_description: "SLSA Build Level 2: sandbox + audit log + materials"
                    .to_owned(),
                is_compliant: true,
                witness: None,
                explanation:
                    "Every input accepted by the candidate is also accepted by the baseline."
                        .to_owned(),
            },
            PolicyComplianceProof {
                baseline_name: "slsa-build-l3".to_owned(),
                baseline_description: "SLSA Build Level 3: L2 + attestation chain + zero denials"
                    .to_owned(),
                is_compliant: false,
                witness: Some(serde_json::json!({
                    "sandboxed": true,
                    "has_audit_log": true,
                    "has_materials": true,
                    "has_parent_attestation": false,
                })),
                explanation:
                    "Found an input accepted by the candidate but rejected by the baseline."
                        .to_owned(),
            },
        ]
    }

    #[test]
    fn policy_compliance_creates_declarations() {
        let mut att = sample_attestation();
        att.policy_compliance = sample_compliance_proofs();

        let bom = forge_to_cyclonedx(&att);
        let decl = bom.declarations.as_ref().expect("should have declarations");

        // Assessors: forge + lean4 kernel + z3 smt
        assert_eq!(decl.assessors.len(), 3);
        assert_eq!(decl.assessors[2].bom_ref, "assessor-z3-smt");

        // Two attestation groups: proof verification + policy compliance
        assert_eq!(decl.attestations.len(), 2);
        assert!(decl.attestations[1].summary.contains("2/3 baselines met"));
        assert_eq!(decl.attestations[1].assessor, "assessor-z3-smt");
    }

    #[test]
    fn compliant_baseline_has_claim_with_score_1() {
        let mut att = sample_attestation();
        att.policy_compliance = sample_compliance_proofs();

        let bom = forge_to_cyclonedx(&att);
        let decl = bom.declarations.as_ref().unwrap();
        let compliance_claims = &decl.attestations[1].map;

        let l1 = &compliance_claims[0];
        assert_eq!(l1.requirement, "policy-compliance/slsa-build-l1");
        assert_eq!(l1.claims.len(), 1);
        assert!(l1.counter_claims.is_empty());
        assert_eq!(l1.conformance.score, 1.0);
        assert_eq!(l1.conformance.confidence, Some(1.0));
        assert!(l1.claims[0].predicate.contains("meets"));
    }

    #[test]
    fn non_compliant_baseline_has_counter_claim_with_witness() {
        let mut att = sample_attestation();
        att.policy_compliance = sample_compliance_proofs();

        let bom = forge_to_cyclonedx(&att);
        let decl = bom.declarations.as_ref().unwrap();
        let compliance_claims = &decl.attestations[1].map;

        let l3 = &compliance_claims[2];
        assert_eq!(l3.requirement, "policy-compliance/slsa-build-l3");
        assert!(l3.claims.is_empty());
        assert_eq!(l3.counter_claims.len(), 1);
        assert_eq!(l3.conformance.score, 0.0);
        assert_eq!(l3.conformance.confidence, Some(1.0));
        assert!(l3.counter_claims[0].predicate.contains("does NOT meet"));

        // Evidence should contain the counterexample witness
        let evidence = &l3.counter_claims[0].evidence[0];
        let data = evidence.data.as_ref().expect("should have evidence data");
        assert_eq!(data[0].name, "counterexample-witness");
        assert!(data[0].value.contains("has_parent_attestation"));
    }

    #[test]
    fn policy_compliance_only_creates_declarations_without_proofs() {
        use crate::attest::PolicyComplianceProof;

        let attestation = ForgeAttestation {
            materials: vec![],
            subjects: vec![],
            builder_id: "gleisner-forge/0.1.0".to_owned(),
            packages: vec!["curl".to_owned()],
            package_metadata: vec![PackageMetadata {
                name: "curl".to_owned(),
                upstream_version: Some("8.11.0".to_owned()),
                source_provenance: None,
                repology_project: None,
                purl: "pkg:github/curl/curl@8.11.0".to_owned(),
                source_urls: vec![],
                verified_properties: vec![],
            }],
            verification: None,
            policy_compliance: vec![PolicyComplianceProof {
                baseline_name: "slsa-build-l1".to_owned(),
                baseline_description: "SLSA Build Level 1".to_owned(),
                is_compliant: true,
                witness: None,
                explanation: "Proved.".to_owned(),
            }],
        };

        let bom = forge_to_cyclonedx(&attestation);
        let decl = bom.declarations.as_ref().expect("should have declarations");

        // Assessors: forge + z3 (no proof kernels)
        assert_eq!(decl.assessors.len(), 2);
        assert_eq!(decl.assessors[0].bom_ref, "assessor-gleisner-forge");
        assert_eq!(decl.assessors[1].bom_ref, "assessor-z3-smt");

        // Only one attestation group (policy compliance)
        assert_eq!(decl.attestations.len(), 1);
        assert!(decl.attestations[0].summary.contains("1/1 baselines met"));
    }

    #[test]
    fn policy_compliance_serializes_to_json() {
        let mut att = sample_attestation();
        att.policy_compliance = sample_compliance_proofs();

        let bom = forge_to_cyclonedx(&att);
        let json = serde_json::to_string_pretty(&bom).unwrap();

        // Policy compliance fields present
        assert!(json.contains("policy-compliance/slsa-build-l1"));
        assert!(json.contains("z3-smt-qf-lia"));
        assert!(json.contains("assessor-z3-smt"));
        assert!(json.contains("counterexample-witness"));

        // Roundtrip
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            parsed["declarations"]["attestations"]
                .as_array()
                .unwrap()
                .len()
                >= 2
        );
    }
}
