/* -*- Mode: rust; rust-indent-offset: 4 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::{c_char, CStr, CString};
use std::fmt;
use std::ptr;


use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

/// Custom deserializer for the hashes map that checks for duplicate keys.
///
/// Used in the hashes dictionary of the manifest.
/// For example, this manifest is invalid because "path/to/resource" appears twice:
///
/// ```json
/// {
///     "hashes": {
///         "path/to/resource": "sha256-abc...",
///         "path/to/another/resource": [ "sha256-def...", "sha512-ghi..." ],
///         "path/to/resource": "sha256-jkl..."  // <--- duplicate key
///     }
/// }
/// ```
fn deserialize_hashes_no_duplicates<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, HashValue>, D::Error>
where
    D: Deserializer<'de>,
{
    struct HashesVisitor;

    impl<'de> Visitor<'de> for HashesVisitor {
        type Value = BTreeMap<String, HashValue>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "a map of hashes without duplicate keys")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut out = BTreeMap::<String, HashValue>::new();

            while let Some((k, v)) = map.next_entry::<String, HashValue>()? {
                if out.contains_key(&k) {
                    return Err(de::Error::custom(format!(
                        "duplicate key in hashes: {:?}",
                        k
                    )));
                }
                out.insert(k, v);
            }

            Ok(out)
        }
    }

    deserializer.deserialize_map(HashesVisitor)
}

#[derive(Debug)]
pub enum ManifestParseError {
    /// The manifest text could not be parsed as JSON
    InvalidSyntax { detail: String },

    /// The parsed data does not conform to the manifest schema
    InvalidStructure { detail: String },

    /// The manifest version is not supported by this implementation
    UnsupportedVersion { version: u32 },
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
///     If its value contains "script", append "script" to integrityPolicy's blocked destinations.
///     If its value contains "style", append "style" to integrityPolicy's blocked destinations.
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
/// append "inline" to integrityPolicy's sources.
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
                detail: format!("invalid sources value {v:?} (allowed: inline)"),
            });
        }
    }

    Ok(())
}

/// If dictionary["endpoints"] exists:
///     Set integrityPolicy's endpoints to dictionary['endpoints'].
///
fn validate_endpoints(raw_value: &str) -> Result<(), IntegrityPolicyParseError> {
    parse_value_list(raw_value).map_err(|detail| IntegrityPolicyParseError::InvalidSyntax {
        detail: format!("{detail} (directive \"endpoints\")"),
    })?;
    Ok(())
}

/// Validates the integrity policy string.
///
/// Reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Integrity-Policy
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
            other => {
                return Err(IntegrityPolicyParseError::InvalidSyntax {
                    detail: format!("unknown directive {other:?}"),
                });
            }
        }
    }

    Ok(())
}

/// (Binary Transparency server)
fn validate_bt_server(value: &str) -> Result<(), ManifestParseError> {
    let v = value.trim();

    if v.is_empty() {
        return Err(ManifestParseError::InvalidStructure {
            detail: "bt-server must be non-empty".into(),
        });
    }

    if v.contains(char::is_whitespace) {
        return Err(ManifestParseError::InvalidStructure {
            detail: "bt-server must not contain whitespace".into(),
        });
    }

    Ok(())
}

/// Parses a value list from a directive value.
///
/// Examples:
/// - "(a b c)" -> ["a","b","c"]
/// - "(a)" -> ["a"]
/// - "a" -> ["a"]
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

/// From the discussion here: https://github.com/w3c/webappsec-subresource-integrity/issues/163
/// There are 2 possible ways to represent hash values:
/// 1. As a hex-encoded string of length 64 (representing 32 bytes)
/// For example: fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603
/// 2. As an algorithm-prefix followed by a base64-encoded string
/// For example:
/// sha256-951GGeIr4ebxasLqO1OxZUtNtdoEemmEyhZD5uC1szg="
/// is_valid_hex_sha256 checks for the first representation (sha256 only I believe).
/// is_valid_sri_hash checks for the second representation (sha256, sha384, sha512).
fn is_valid_hex_sha256(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_valid_sri_hash(s: &str) -> bool {
    // Accept sha256-, sha384-, sha512-
    let (alg, b64) = if let Some(rest) = s.strip_prefix("sha256-") {
        ("sha256", rest)
    } else if let Some(rest) = s.strip_prefix("sha384-") {
        ("sha384", rest)
    } else if let Some(rest) = s.strip_prefix("sha512-") {
        ("sha512", rest)
    } else {
        return false;
    };

    let bytes = match base64::decode(b64) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let expected_len = match alg {
        "sha256" => 32,
        "sha384" => 48,
        "sha512" => 64,
        _ => return false,
    };

    bytes.len() == expected_len
}

fn is_valid_hash(s: &str) -> bool {
    is_valid_hex_sha256(s) || is_valid_sri_hash(s)
}

/// Validate that the hashes map is non-empty and that all hash values are valid.
/// A valid hash value is either:
/// - A hex-encoded sha256 string of length 64
/// - A sri-format string with sha256, sha384, or sha512 prefix
/// - A list of the above
/// Currently there is a support of AllowedAnywhere
/// that looks like "" followed by a list of hashes.
/// We also allow it (but the empty string must be present only once).
/// P.S. We enforce that each key appears only once in the map,
/// via the custom deserializer above.
fn validate_hashes(hashes: &BTreeMap<String, HashValue>) -> Result<(), ManifestParseError> {
    if hashes.is_empty() {
        return Err(ManifestParseError::InvalidStructure {
            detail: "hashes must not be empty".into(),
        });
    }

    let mut saw_empty_key = false;

    for (key, hv) in hashes {
        // Disallow whitespace-only keys; "empty" must be exactly "", not "    ".
        if key.trim().is_empty() && key != "" {
            return Err(ManifestParseError::InvalidStructure {
                detail: "hashes key must not be whitespace".into(),
            });
        }

        if key == "" {
            // Empty key: only one allowed.
            if saw_empty_key {
                return Err(ManifestParseError::InvalidStructure {
                    detail: r#"hashes may contain "" key only once"#.into(),
                });
            }
            saw_empty_key = true;

            // It's possible (I believe) that AllowAnywhere can have either a single hash or a list of hashes.
            match hv {
                HashValue::One(h) => {
                    if !is_valid_hash(h) {
                        return Err(ManifestParseError::InvalidStructure {
                            detail: format!(r#"invalid hash for "" key: {h:?}"#),
                        });
                    }
                }
                HashValue::Many(v) => {
                    if v.is_empty() {
                        return Err(ManifestParseError::InvalidStructure {
                            detail: r#"hash list for AllowedAnywhere must not be empty"#.into(),
                        });
                    }
                    for h in v {
                        if !is_valid_hash(h) {
                            return Err(ManifestParseError::InvalidStructure {
                                detail: format!(r#"invalid hash in "" list: {h:?}"#),
                            });
                        }
                    }
                }
            }
        } else {
            // Non-empty key (not AllowAnywhere ones): must be a single hash string.
            match hv {
                HashValue::One(h) => {
                    if !is_valid_hash(h) {
                        return Err(ManifestParseError::InvalidStructure {
                            detail: format!("invalid hash for {key:?}: {h:?}"),
                        });
                    }
                }
                HashValue::Many(_) => {
                    return Err(ManifestParseError::InvalidStructure {
                        detail: format!("{key:?}: value must be a single hash string"),
                    });
                }
            }
        }
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,

    #[serde(rename = "integrity-policy")]
    pub integrity_policy: String,

    #[serde(rename = "bt-server")]
    pub bt_server: String,

    #[serde(deserialize_with = "deserialize_hashes_no_duplicates")]
    pub hashes: BTreeMap<String, HashValue>,

    /// Optional metadata field
    pub metadata: Option<serde_json::Value>,

    // I've figured out that there might be other fields in the manifest in the future,
    // for example, "resource_delimeter": "/* MY_DELIM */"
    // https://github.com/w3c/webappsec-subresource-integrity/issues/163
    // So we can just remove #[serde(deny_unknown_fields)] in this case
}

/// Parses this shape of manifests
///   "manifest": {
///     "version": 1, // format of the manifest
///     "integrity-policy": "blocked-destinations=(script), checked-destinations=(wasm)",
///     "bt-server": "www.mybt.com/com.whatsapp.www ",
///     "hashes": {
///       "/assets/x.html": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
///       "/assets/main.js": "fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603",
///       "": [
///         "3431742b9dbff1751bba9ba47483ed62ae7fdf42d560a480a282af38b6c8de0a"
///       ],
///     },
///     "metadata": "arbitrary data... "
///  },
/// Should be updated if https://github.com/w3c/webappsec-subresource-integrity/issues/158#issuecomment-3639242927
///
pub fn parse_manifest_json5(input: &str) -> Result<Manifest, ManifestParseError> {
    let manifest: Manifest =
        json5::from_str(input).map_err(|e| ManifestParseError::InvalidSyntax {
            detail: e.to_string(),
        })?;

    Ok(manifest)
}

fn is_supported_version(version: u32) -> bool {
    matches!(version, 1)
}

fn validate_manifest_structure(m: &Manifest) -> Result<(), ManifestParseError> {
    // Only version 1 is supported currently.
    if !is_supported_version(m.version) {
        return Err(ManifestParseError::UnsupportedVersion {
            version: m.version,
        });
    }

    validate_integrity_policy(&m.integrity_policy).map_err(|e| {
        ManifestParseError::InvalidStructure {
            detail: format!("invalid integrity-policy: {e:?}"),
        }
    })?;

    validate_bt_server(&m.bt_server)?;
    validate_hashes(&m.hashes)?;

    Ok(())
}

pub struct ManifestHashes {
    // Hashes that are allowed anywhere
    // They don't need to have a key associated with them.
    // Ok, we can do something more complicated like Vec <'a str>
    // but we might have some lifetime issues.
    // The current approach copies a lot of stuff, so it's definitely can be improved.
    //
    // A list of hashes that can be used for any resource.
    pub allowed_anywhere_hash_vec: Vec<String>,
    // Named hashes (kv : <addresse, hash>)
    pub asset_hash_vec: BTreeMap<String, Vec<String>>,
}

impl Manifest {
    /// The hashes are returned only if the manifest is valid.
    pub fn get_hashes_from_manifest(&self) -> Result<ManifestHashes, ManifestParseError> {
        validate_manifest_structure(self)?;

        let mut asset_hash_vec = BTreeMap::new();
        let mut allowed_anywhere_hash_vec = Vec::new();

        for (key, value) in &self.hashes {
            if key.is_empty() {
                match value {
                    // TODO: potentially improve the performance by not cloning here.
                    HashValue::One(h) => allowed_anywhere_hash_vec.push(h.clone()),
                    HashValue::Many(v) => allowed_anywhere_hash_vec.extend(v.iter().cloned()),
                }
            } else {
                // Named resource
                if let HashValue::One(h) = value {
                    asset_hash_vec.insert(key.clone(), vec![h.clone()]);
                }
            }
        }

        // Pay attention, here we sort the hashes
        allowed_anywhere_hash_vec.sort();

        Ok(ManifestHashes {
            asset_hash_vec,
            allowed_anywhere_hash_vec,
        })
    }
}

fn push_unique(vec: &mut Vec<String>, value: String) {
    if !vec.iter().any(|v| v == &value) {
        vec.push(value);
    }
}

fn merge_hashes(mut a: ManifestHashes, b: ManifestHashes) -> ManifestHashes {
    for h in b.allowed_anywhere_hash_vec {
        push_unique(&mut a.allowed_anywhere_hash_vec, h);
    }

    for (key, hashes) in b.asset_hash_vec {
        let entry = a.asset_hash_vec.entry(key).or_default();
        for h in hashes {
            push_unique(entry, h);
        }
    }

    a
}

/// Merges hashes from two manifests, removing duplicates.
pub fn merge_hashes_from_manifests(
    m1: &Manifest,
    m2: &Manifest,
) -> Result<ManifestHashes, ManifestParseError> {
    let h1 = m1.get_hashes_from_manifest()?;
    let h2 = m2.get_hashes_from_manifest()?;
    Ok(merge_hashes(h1, h2))
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
    fn valid_manifest_parse_and_validate_ok() {
        let input = include_str!("../tests/manifests/valid_manifest.json5");
        let manifest = parse_manifest_json5(input).and_then(|m| validate_manifest_structure(&m));
        assert!(
            manifest.is_ok(),
            "expected Ok after parse + validate, got {:?}",
            manifest
        );
    }

    #[test]
    fn valid_manifest_hashes_are_extracted_correctly() {
        let input = include_str!("../tests/manifests/valid_manifest.json5");
        let manifest = parse_manifest_json5(input).expect("manifest should parse");
        let hashes = manifest
            .get_hashes_from_manifest()
            .expect("hashes should be valid");

        assert_eq!(
            hashes
                .asset_hash_vec
                .get("/assets/x.html")
                .map(Vec::as_slice),
            Some(
                &["ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
                    .to_string()][..]
            )
        );

        assert_eq!(
            hashes
                .asset_hash_vec
                .get("/assets/main.js")
                .map(Vec::as_slice),
            Some(
                &["fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603"
                    .to_string()][..]
            )
        );

        // AllowedAnywhere hashes
        assert_eq!(hashes.allowed_anywhere_hash_vec.len(), 1);
        assert_eq!(
            hashes.allowed_anywhere_hash_vec[0],
            "3431742b9dbff1751bba9ba47483ed62ae7fdf42d560a480a282af38b6c8de0a"
        );
    }

    #[test]
    fn valid_manifest_hashes_are_extracted_correctly_merging_two_manifests() {
        let input = include_str!("../tests/manifests/valid_manifest.json5");
        let manifest = parse_manifest_json5(input).expect("manifest should parse");
        let merged_hashes =
            merge_hashes_from_manifests(&manifest, &manifest).expect("merge should succeed");

        let x_html_hashes = merged_hashes
            .asset_hash_vec
            .get("/assets/x.html")
            .expect("expected /assets/x.html to exist");

        assert_eq!(x_html_hashes.len(), 1);
        assert_eq!(
            x_html_hashes,
            &vec!["ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",]
        );
    }

    #[test]
    fn valid_manifest_hashes_are_extracted_correctly_merging_two_different_manifests() {
        let input0 = include_str!("../tests/manifests/valid_manifest.json5");
        let input1 = include_str!("../tests/manifests/valid_manifest1.json5");

        // The manifest0 is "younger" than manifest1, so its hashes should appear first.
        let manifest0 = parse_manifest_json5(input0).expect("manifest should parse");
        let manifest1 = parse_manifest_json5(input1).expect("manifest should parse");
        let merged_hashes =
            merge_hashes_from_manifests(&manifest0, &manifest1).expect("merge should succeed");

        let x_html_hashes = merged_hashes
            .asset_hash_vec
            .get("/assets/x.html")
            .expect("expected /assets/x.html to exist");

        assert_eq!(x_html_hashes.len(), 2);
        assert_eq!(
            x_html_hashes,
            &vec![
                "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
                "fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603",
            ]
        );

        let main_js_hashes = merged_hashes
            .asset_hash_vec
            .get("/assets/main.js")
            .expect("expected /assets/main.js to exist");

        assert_eq!(main_js_hashes.len(), 2);
        assert_eq!(
            main_js_hashes,
            &vec![
                "fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603",
                "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
            ]
        );

        // AllowedAnywhere hashes
        assert_eq!(merged_hashes.allowed_anywhere_hash_vec.len(), 2);
        assert_eq!(
            merged_hashes.allowed_anywhere_hash_vec[0],
            "3431742b9dbff1751bba9ba47483ed62ae7fdf42d560a480a282af38b6c8de0a"
        );
        assert_eq!(
            merged_hashes.allowed_anywhere_hash_vec[1],
            "3ed62ae7fdf42d560a480a282af38b6c8de0a3431742b9dbff1751bba9ba4748"
        );
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
        let input =
            include_str!("../tests/manifests/invalid_manifest_unsupported_version.json5");
        let manifest = parse_manifest_json5(input).and_then(|m| validate_manifest_structure(&m));
        assert!(
            matches!(
                manifest,
                Err(ManifestParseError::UnsupportedVersion { .. })
            ),
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
        let input = include_str!(
            "../tests/manifests/integrity-policy/invalid_manifest_empty_integrity_policy.json5"
        );
        let manifest = parse_manifest_json5(input).and_then(|m| validate_manifest_structure(&m));
        assert!(
            matches!(manifest, Err(ManifestParseError::InvalidStructure { .. })),
            "expected InvalidStructure, got {:?}",
            manifest
        );
    }

    #[test]
    fn invalid_manifest_missing_equals() {
        let input = include_str!(
            "../tests/manifests/integrity-policy/invalid_manifest_missing_equals.json5"
        );
        let manifest = parse_manifest_json5(input).and_then(|m| validate_manifest_structure(&m));
        assert!(
            matches!(manifest, Err(ManifestParseError::InvalidStructure { .. })),
            "expected InvalidStructure, got {:?}",
            manifest
        );
    }

    #[test]
    fn invalid_manifest_sources_bad_value() {
        let input = include_str!(
            "../tests/manifests/integrity-policy/invalid_manifest_sources_bad_value.json5"
        );
        let manifest = parse_manifest_json5(input).and_then(|m| validate_manifest_structure(&m));
        assert!(
            matches!(manifest, Err(ManifestParseError::InvalidStructure { .. })),
            "expected InvalidStructure, got {:?}",
            manifest
        );
    }

    #[test]
    fn invalid_manifest_unknown_directive_integrity() {
        let input = include_str!(
            "../tests/manifests/integrity-policy/invalid_manifest_unknown_directive.json5"
        );
        let manifest = parse_manifest_json5(input).and_then(|m| validate_manifest_structure(&m));
        assert!(
            matches!(manifest, Err(ManifestParseError::InvalidStructure { .. })),
            "expected InvalidStructure, got {:?}",
            manifest
        );
    }

    #[test]
    fn invalid_manifest_incorrect_bt_server() {
        let input = include_str!("../tests/manifests/invalid_manifest_incorrect_bt_server.json5");
        let manifest = parse_manifest_json5(input).and_then(|m| validate_manifest_structure(&m));
        assert!(
            matches!(manifest, Err(ManifestParseError::InvalidStructure { .. })),
            "expected InvalidStructure, got {:?}",
            manifest
        );
    }

    #[test]
    fn valid_sha_hashes() {
        let valid_hex = "fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603";
        let valid_sri_sha256 = "sha256-951GGeIr4ebxasLqO1OxZUtNtdoEemmEyhZD5uC1szg=";
        let valid_sri_sha384 =
            "sha384-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let valid_sri_sha512 = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";

        assert!(is_valid_hex_sha256(valid_hex), "expected valid hex sha256");
        assert!(
            is_valid_sri_hash(valid_sri_sha256),
            "expected valid sri sha256"
        );
        assert!(
            is_valid_sri_hash(valid_sri_sha384),
            "expected valid sri sha384"
        );
        assert!(
            is_valid_sri_hash(valid_sri_sha512),
            "expected valid sri sha512"
        );

        let invalid_hex = "invalidhexstring";
        let invalid_sri = "sha256-invalidbase64===";

        assert!(
            !is_valid_hex_sha256(invalid_hex),
            "expected invalid hex sha256"
        );
        assert!(
            !is_valid_sri_hash(invalid_sri),
            "expected invalid sri sha256"
        );
    }

    #[test]
    fn invalid_manifest_duplicate_hash_key() {
        let input =
            include_str!("../tests/manifests/hashes/invalid_manifest_duplicate_hash_key.json5");
        let manifest = parse_manifest_json5(input).and_then(|m| validate_manifest_structure(&m));
        assert!(
            matches!(manifest, Err(ManifestParseError::InvalidSyntax { .. })),
            "expected InvalidSyntax, got {:?}",
            manifest
        );
    }

    #[test]
    fn invalid_manifest_empty_hash() {
        let input = include_str!("../tests/manifests/hashes/invalid_manifest_empty_hash.json5");
        let manifest = parse_manifest_json5(input).and_then(|m| validate_manifest_structure(&m));
        assert!(
            matches!(manifest, Err(ManifestParseError::InvalidStructure { .. })),
            "expected InvalidStructure, got {:?}",
            manifest
        );
    }

    #[test]
    fn invalid_manifest_spaces_in_key() {
        let input =
            include_str!("../tests/manifests/hashes/invalid_manifest_spaces_in_key.json5");
        let manifest = parse_manifest_json5(input).and_then(|m| validate_manifest_structure(&m));
        assert!(
            matches!(manifest, Err(ManifestParseError::InvalidStructure { .. })),
            "expected InvalidStructure, got {:?}",
            manifest
        );
    }

    #[test]
    fn valid_manifest_metadata_optional() {
        let input = include_str!("../tests/manifests/valid_manifest_metadata_optional.json5");
        let manifest = parse_manifest_json5(input).and_then(|m| validate_manifest_structure(&m));
        assert!(manifest.is_ok(), "expected Ok, got {:?}", manifest);
    }

    #[test]
    fn invalid_manifest_unknown_directive() {
        let input = include_str!(
            "../tests/manifests/integrity-policy/invalid_manifest_unknown_directive.json5"
        );
        let manifest = parse_manifest_json5(input).and_then(|m| validate_manifest_structure(&m));
        assert!(
            matches!(manifest, Err(ManifestParseError::InvalidStructure { .. })),
            "expected InvalidStructure, got {:?}",
            manifest
        );
    }

    #[test]
    fn valid_manifest_sorting_anywhere_hashed(){
        let input = include_str!("../tests/manifests/valid_manifest_sorting_anywhere_hashes.json5");
        let manifest = parse_manifest_json5(input).expect("manifest should parse");
        let hashes = manifest
            .get_hashes_from_manifest()
            .expect("hashes should be valid");

        // AllowedAnywhere hashes should be sorted
        assert_eq!(hashes.allowed_anywhere_hash_vec.len(), 3);

        assert_eq!(
            hashes.allowed_anywhere_hash_vec[0],
            "3431742b9dbff1751bba9ba47483ed62ae7fdf42d560a480a282af38b6c8de0a"
        );

        assert_eq!(
            hashes.allowed_anywhere_hash_vec[1],
            "4431742b9dbff1751bba9ba47483ed62ae7fdf42d560a480a282af38b6c8de0a"
        );

        assert_eq!(
            hashes.allowed_anywhere_hash_vec[2],
            "5431742b9dbff1751bba9ba47483ed62ae7fdf42d560a480a282af38b6c8de0a"
        );
    }
}

#[repr(C)]
pub enum ManifestErrorCode {
    Success = 0,
    InvalidSyntax = 1,
    InvalidStructure = 2,
    UnsupportedVersion = 3,
    NullPointer = 4,
    InvalidEncoding = 5,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn manifest_validate(data: *const c_char, data_len: u32) -> ManifestErrorCode { unsafe {
    if data.is_null() {
        return ManifestErrorCode::NullPointer;
    }

    let manifest_str = if data_len > 0 {
        let slice = std::slice::from_raw_parts(data as *const u8, data_len as usize);
        match std::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => return ManifestErrorCode::InvalidEncoding,
        }
    } else {
        match CStr::from_ptr(data).to_str() {
            Ok(s) => s,
            Err(_) => return ManifestErrorCode::InvalidEncoding,
        }
    };

    // Parse the manifest
    match parse_manifest_json5(manifest_str) {
        Ok(_manifest) => ManifestErrorCode::Success,
        Err(e) => match e {
            ManifestParseError::InvalidSyntax { .. } => ManifestErrorCode::InvalidSyntax,
            ManifestParseError::InvalidStructure { .. } => ManifestErrorCode::InvalidStructure,
            ManifestParseError::UnsupportedVersion { .. } => ManifestErrorCode::UnsupportedVersion,
        },
    }
}}


#[repr(C)]
pub struct AssetHashPair {
    // asset path
    pub path: *const c_char,
    // hash value
    pub hash: *const c_char,
}

#[repr(C)]
pub struct AssetHashPairs {
    /// Number of pairs
    pub count: u32,
    /// Array of AssetHashPair structs
    pub pairs: *const AssetHashPair,
}

/// Flattened structure containing allowed-anywhere hashes
#[repr(C)]
pub struct AllowedAnywhereHashes {
    /// Number of hashes
    pub count: u32,
    /// Array of hashes (null-terminated C strings)
    pub hashes: *const *const c_char,
}
pub struct ManifestHashesHandle {
    // Store (path, hash) pairs as CStrings
    asset_pairs: Vec<(CString, CString)>,
    // Store allowed-anywhere hashes as CStrings
    allowed_anywhere: Vec<CString>,
}

#[unsafe(no_mangle)]
/// Parse a manifest and extract hashes
/// 
/// # Safety
/// - `data` must be a valid pointer to a null-terminated C string
/// - `data_len` is the length of the data in bytes
/// - `out_hashes` must be a valid pointer to write the result
/// - The returned handle must be freed with `manifest_hashes_free`
/// #[unsafe(no_mangle)]
pub unsafe extern "C" fn manifest_parse_and_get_hashes(
    data: *const c_char,
    data_len: u32,
    out_hashes: *mut *mut ManifestHashesHandle,
) -> ManifestErrorCode { unsafe {
    // Check for null pointers
    if data.is_null() || out_hashes.is_null() {
        return ManifestErrorCode::NullPointer;
    }

    // Convert C string to Rust string
    let manifest_str = if data_len > 0 {
        let slice = std::slice::from_raw_parts(data as *const u8, data_len as usize);
        match std::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => return ManifestErrorCode::InvalidEncoding,
        }
    } else {
        match CStr::from_ptr(data).to_str() {
            Ok(s) => s,
            Err(_) => return ManifestErrorCode::InvalidEncoding,
        }
    };

    // Parse the manifest
    let manifest = match parse_manifest_json5(manifest_str) {
        Ok(m) => m,
        Err(e) => {
            use crate::ManifestParseError;
            return match e {
                ManifestParseError::InvalidSyntax { .. } => ManifestErrorCode::InvalidSyntax,
                ManifestParseError::InvalidStructure { .. } => ManifestErrorCode::InvalidStructure,
                ManifestParseError::UnsupportedVersion { .. } => ManifestErrorCode::UnsupportedVersion,
            };
        }
    };

    // Get hashes from manifest
    let hashes = match manifest.get_hashes_from_manifest() {
        Ok(h) => h,
        Err(e) => {
            use crate::ManifestParseError;
            return match e {
                ManifestParseError::InvalidSyntax { .. } => ManifestErrorCode::InvalidSyntax,
                ManifestParseError::InvalidStructure { .. } => ManifestErrorCode::InvalidStructure,
                ManifestParseError::UnsupportedVersion { .. } => ManifestErrorCode::UnsupportedVersion,
            };
        }
    };

    // Convert to CStrings and build pairs
    // Note: Each asset path maps to exactly one hash (takes first hash from vec)
    let mut asset_pairs = Vec::new();

    for (path, hash_vec) in &hashes.asset_hash_vec {
        // Take the first hash - per validation rules, assets should only have one hash
        if let Some(hash) = hash_vec.first() {
            if let (Ok(path_cstr), Ok(hash_cstr)) = (CString::new(path.as_str()), CString::new(hash.as_str())) {
                asset_pairs.push((path_cstr, hash_cstr));
            }
        }
    }

    // Convert allowed-anywhere hashes to CStrings
    let mut allowed_anywhere = Vec::new();

    for hash in &hashes.allowed_anywhere_hash_vec {
        if let Ok(hash_cstr) = CString::new(hash.as_str()) {
            allowed_anywhere.push(hash_cstr);
        }
    }

    // Create handle and return
    let handle = Box::new(ManifestHashesHandle {
        asset_pairs,
        allowed_anywhere,
    });
    *out_hashes = Box::into_raw(handle);
    ManifestErrorCode::Success
}}

/// Get asset hash pairs
///
/// # Safety
/// - `hashes` must be a valid ManifestHashesHandle pointer
/// - The returned structure's pointers are valid as long as the ManifestHashesHandle is alive
/// - Do NOT free individual strings or the array - they're owned by the handle
#[unsafe(no_mangle)]
pub unsafe extern "C" fn manifest_hashes_get_asset_pairs(
    hashes: *const ManifestHashesHandle,
) -> AssetHashPairs { unsafe {
    if hashes.is_null() {
        return AssetHashPairs {
            count: 0,
            pairs: ptr::null(),
        };
    }

    let handle = &*hashes;
    
    // Build array of AssetHashPair structs with pointers into our CStrings
    let mut pairs: Vec<AssetHashPair> = Vec::with_capacity(handle.asset_pairs.len());
    for (path_cstr, hash_cstr) in &handle.asset_pairs {
        pairs.push(AssetHashPair {
            path: path_cstr.as_ptr(),
            hash: hash_cstr.as_ptr(),
        });
    }
    
    // Leak the Vec so the pointers remain valid
    // They'll be cleaned up when the handle is freed
    let pairs_ptr = pairs.as_ptr();
    let count = pairs.len() as u32;
    std::mem::forget(pairs);
    
    AssetHashPairs {
        count,
        pairs: pairs_ptr,
    }
}}

/// Get allowed-anywhere hashes
///
/// # Safety
/// - `hashes` must be a valid ManifestHashesHandle pointer
/// - The returned structure's pointers are valid as long as the ManifestHashesHandle is alive
/// - Do NOT free individual strings or the array - they're owned by the handle
#[unsafe(no_mangle)]
pub unsafe extern "C" fn manifest_hashes_get_allowed_anywhere(
    hashes: *const ManifestHashesHandle,
) -> AllowedAnywhereHashes { unsafe {
    if hashes.is_null() {
        return AllowedAnywhereHashes {
            count: 0,
            hashes: ptr::null(),
        };
    }

    let handle = &*hashes;
    
    // Build array of pointers to our CStrings
    let mut hash_ptrs: Vec<*const c_char> = Vec::with_capacity(handle.allowed_anywhere.len());
    for hash_cstr in &handle.allowed_anywhere {
        hash_ptrs.push(hash_cstr.as_ptr());
    }
    
    // Leak the Vec so the pointers remain valid
    let ptrs = hash_ptrs.as_ptr();
    let count = hash_ptrs.len() as u32;
    std::mem::forget(hash_ptrs);
    
    AllowedAnywhereHashes {
        count,
        hashes: ptrs,
    }
}}

/// Free a manifest hashes handle
///
/// # Safety
/// - `hashes` must be a valid ManifestHashesHandle pointer or null
#[unsafe(no_mangle)]
pub unsafe extern "C" fn manifest_hashes_free(hashes: *mut ManifestHashesHandle) { unsafe {
    if !hashes.is_null() {
        drop(Box::from_raw(hashes));
    }
}}
