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
}