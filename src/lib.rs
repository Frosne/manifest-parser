use std::{error::Error, fmt};

use serde::Deserialize;
use std::collections::BTreeMap;


#[derive(Debug)]
pub enum ManifestParseError {
    /// The manifest text could not be parsed as JSON
    InvalidSyntax {
        detail: String,
    },

    /// The parsed data does not conform to the manifest schema
    InvalidStructure {
        detail: String,
    },

    /// The manifest version is not supported by this implementation
    UnsupportedVersion {
        version: u32,
    },
}

impl fmt::Display for ManifestParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ManifestParseError::InvalidSyntax { detail } => {
                write!(f, "manifest has invalid syntax: {detail}")
            }
            ManifestParseError::InvalidStructure { detail } => {
                write!(f, "manifest has invalid structure: {detail}")
            }
            ManifestParseError::UnsupportedVersion { version } => {
                write!(f, "unsupported manifest version {version}")
            }
        }
    }
}

impl Error for ManifestParseError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityPolicy {
    pub directives: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityPolicyParseError {
    Empty,
    InvalidDirective { detail: String },
    InvalidSyntax { detail: String },
    UnknownDirective { name: String },
}

/// https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Integrity-Policy
/// https://www.w3.org/TR/sri-2/
///
/// If dictionary["blocked-destinations"] exists:
///     If its value contains "script", append "script" to integrityPolicy’s blocked destinations.
///     If its value contains "style", append "style" to integrityPolicy’s blocked destinations.
/// (AW: We don't append anything, just checking that it parses correctly.)

/// AW: Btw, it's unclear if blocked-destinations are optional or mandatory. From the sri-2 spec,
/// it seems they are optional, but from the MDN docs, it seems they are mandatory. We'll treat them as optional for now.
fn validate_blocked_destinations(raw_value: &str) -> Result<(), IntegrityPolicyParseError> {
    let values = parse_value_list(raw_value).map_err(|detail| {
        IntegrityPolicyParseError::InvalidSyntax {
            detail: format!("{detail} (directive \"blocked-destinations\")"),
        }
    })?;

    for v in values {
        if v != "script" && v != "style" {
            return Err(IntegrityPolicyParseError::InvalidSyntax {
                detail: format!(
                    "invalid blocked-destinations value {v:?} (allowed: script, style)"
                ),
            });
        }
    }

    Ok(())
}

/// If dictionary["sources"] does not exist or if its value contains "inline",
/// append "inline" to integrityPolicy’s sources.
/// (AW: We don't append anything, just checking that it parses correctly.)
fn validate_sources(raw_value: &str) -> Result<(), IntegrityPolicyParseError> {
    let values = parse_value_list(raw_value).map_err(|detail| {
        IntegrityPolicyParseError::InvalidSyntax {
            detail: format!("{detail} (directive \"sources\")"),
        }
    })?;

    for v in values {
        if v != "inline" {
            return Err(IntegrityPolicyParseError::InvalidSyntax {
                detail: format!(
                    "invalid sources value {v:?} (allowed: inline)"
                ),
            });
        }
    }

    Ok(())
}

/// If dictionary["endpoints"] exists:
///     Set integrityPolicy’s endpoints to dictionary['endpoints'].
///
fn validate_endpoints(raw_value: &str) -> Result<(), IntegrityPolicyParseError> {
    parse_value_list(raw_value).map_err(|detail| {
        IntegrityPolicyParseError::InvalidSyntax {
            detail: format!("{detail} (directive \"endpoints\")"),
        }
    })?;
    Ok(())
}

pub fn validate_integrity_policy(input: &str) -> Result<(), IntegrityPolicyParseError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(IntegrityPolicyParseError::Empty);
    }

    for raw_part in s.split(',') {
        let part = raw_part.trim();
        if part.is_empty() {
            continue;
        }

        let (name, raw_value) = part
            .split_once('=')
            .ok_or_else(|| IntegrityPolicyParseError::InvalidDirective {
                detail: format!("missing '=' in directive: {part:?}"),
            })?;

        let name = name.trim();
        let raw_value = raw_value.trim();

        if raw_value.is_empty() {
            return Err(IntegrityPolicyParseError::InvalidSyntax {
                detail: format!("empty value for directive {name:?}"),
            });
        }

        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Integrity-Policy
        match name {
            "blocked-destinations" => {
                validate_blocked_destinations(raw_value)?;
            }
             "sources" => {
                validate_sources(raw_value)?;
            }
            "endpoints" => {
                validate_endpoints(raw_value)?;
            }
            "checked-destinations" => {
                // AW: Not specified in sri-2 spec, so just syntax-checking
                // found in the example
                parse_value_list(raw_value).map_err(|detail| {
                    IntegrityPolicyParseError::InvalidSyntax {
                        detail: format!("{detail} (directive {name:?})"),
                    }
                })?;
            }
            // For now: other directives are just syntax-checked if parenthesized
            other => {
                return Err(IntegrityPolicyParseError::InvalidSyntax {
                    detail: format!("unknown directive {other:?}"),
                });
            }
        }
    }

    Ok(())
}


// /// Parses either:
// /// - "(a b c)" -> ["a","b","c"]   (whitespace-separated)
// /// - "(a)" -> ["a"]
// /// - "a" -> ["a"]
fn parse_value_list(raw: &str) -> Result<Vec<String>, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("empty directive value".into());
    }

    let inner = if raw.starts_with('(') {
        if !raw.ends_with(')') {
            return Err(format!("missing closing ')' in value: {raw:?}"));
        }
        &raw[1..raw.len() - 1]
    } else {
        raw
    };

    let tokens: Vec<String> = inner
        .split_whitespace()
        .filter(|t| !t.is_empty())
        .map(|t| t.to_string())
        .collect();

    if tokens.is_empty() {
        return Err(format!("empty value list in {raw:?}"));
    }

    Ok(tokens)
}




#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum HashValue {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub version: u32,

    #[serde(rename = "integrity-policy")]
    pub integrity_policy: String,

    #[serde(rename = "bt-server")]
    pub bt_server: String,

    pub hashes: BTreeMap<String, HashValue>,

    pub metadata: serde_json::Value,
}

pub fn parse_manifest_json5(input: &str) -> Result<Manifest, ManifestParseError> {
    let manifest: Manifest = json5::from_str(input).map_err(|e| ManifestParseError::InvalidSyntax {
        detail: e.to_string(),
    })?;

    Ok(manifest)
}

fn is_supported_version(version: u32) -> bool {
    matches!(version, 1)
}

fn validate_manifest_structure(m: &Manifest) -> Result<(), ManifestParseError> {
    if !is_supported_version(m.version) {
        return Err(ManifestParseError::UnsupportedVersion { version: m.version });
    }

    validate_integrity_policy(&m.integrity_policy).map_err(|e| ManifestParseError::InvalidStructure {
        detail: format!("invalid integrity-policy: {e:?}"),
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_manifest() {
        let input = include_str!("../tests/manifests/valid_manifest.json5");
        let manifest = parse_manifest_json5(input);
        assert!(manifest.is_ok(), "expected Ok, got {:?}", manifest);
    }

    #[test]
    fn valid_changed_order_manifest() {
        let input = include_str!("../tests/manifests/valid_manifest_changed_order.json5");
        let manifest = parse_manifest_json5(input);
        assert!(manifest.is_ok(), "expected Ok, got {:?}", manifest);
    }
    #[test]
    fn invalid_manifest_missing_brackets() {
        let input = include_str!("../tests/manifests/invalid_manifest_missing_brackets.json5");
        let manifest = parse_manifest_json5(input);
        assert!(
            matches!(manifest, Err(ManifestParseError::InvalidSyntax { .. })),
            "expected InvalidSyntax, got {:?}",
            manifest
        );
    }

    #[test]
    fn invalid_manifest_unsupported_version() {
        let input = include_str!("../tests/manifests/invalid_manifest_unsupported_version.json5");
        let manifest = parse_manifest_json5(input).and_then(|m| validate_manifest_structure(&m));
        assert!(
            matches!(manifest, Err(ManifestParseError::UnsupportedVersion { .. })),
            "expected UnsupportedVersion, got {:?}",
            manifest
        );
    }

    #[test]
    fn invalid_manifest_blocked_destinations_bad_value() {
        let input = include_str!("../tests/manifests/integrity-policy/invalid_manifest_blocked_destinations_bad_value.json5");
        let manifest = parse_manifest_json5(input).and_then(|m| validate_manifest_structure(&m));
        assert!(
            matches!(manifest, Err(ManifestParseError::InvalidStructure { .. })),
            "expected InvalidStructure, got {:?}",
            manifest
        );
    }

    #[test]
    fn invalid_manifest_blocked_destinations_missing_paren() {
        let input = include_str!("../tests/manifests/integrity-policy/invalid_manifest_blocked_destinations_missing_paren.json5");
        let manifest = parse_manifest_json5(input).and_then(|m| validate_manifest_structure(&m));
        assert!(
            matches!(manifest, Err(ManifestParseError::InvalidStructure { .. })),
            "expected InvalidStructure, got {:?}",
            manifest
        );
    }

    #[test]
    fn invalid_manifest_empty_integrity_policy() {
        let input = include_str!("../tests/manifests/integrity-policy/invalid_manifest_empty_integrity_policy.json5");
        let manifest = parse_manifest_json5(input).and_then(|m| validate_manifest_structure(&m));
        assert!(
            matches!(manifest, Err(ManifestParseError::InvalidStructure { .. })),
            "expected InvalidStructure, got {:?}",
            manifest
        );
    }

    #[test]
    fn invalid_manifest_missing_equals() {
        let input = include_str!("../tests/manifests/integrity-policy/invalid_manifest_missing_equals.json5");
        let manifest = parse_manifest_json5(input).and_then(|m| validate_manifest_structure(&m));
        assert!(
            matches!(manifest, Err(ManifestParseError::InvalidStructure { .. })),
            "expected InvalidStructure, got {:?}",
            manifest
        );
    }

    #[test]
    fn invalid_manifest_sources_bad_value() {
        let input = include_str!("../tests/manifests/integrity-policy/invalid_manifest_sources_bad_value.json5");
        let manifest = parse_manifest_json5(input).and_then(|m| validate_manifest_structure(&m));
        assert!(
            matches!(manifest, Err(ManifestParseError::InvalidStructure { .. })),
            "expected InvalidStructure, got {:?}",
            manifest
        );
    }

    #[test]
    fn invalid_manifest_unknown_directive() {
        let input = include_str!("../tests/manifests/integrity-policy/invalid_manifest_unknown_directive.json5");
        let manifest = parse_manifest_json5(input).and_then(|m| validate_manifest_structure(&m));
        assert!(
            matches!(manifest, Err(ManifestParseError::InvalidStructure { .. })),
            "expected InvalidStructure, got {:?}",
            manifest
        );
    }
}