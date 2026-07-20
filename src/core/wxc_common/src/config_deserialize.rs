// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fmt;

use serde::{de::DeserializeOwned, Deserialize, Deserializer};
use serde_json::{error::Category, Value};

const SECRET_PATH_MARKERS: &[&str] = &[
    "token",
    "password",
    "secret",
    "credential",
    "apikey",
    "accesskey",
    "privatekey",
    "passphrase",
    "pwd",
    "bearer",
    "saskey",
    "connectionstring",
    // Credential-bearing container: a shape error at the `user` node (e.g. a
    // token supplied where the object is expected) is pathed at `user`, not at
    // `wamToken`, so mark the whole subtree sensitive. Over-redaction here fails
    // safe — it only replaces an error value with a location, never leaks one.
    "user",
];

/// A JSON deserialization failure with the path at which typed policy parsing
/// failed. Syntax errors have no meaningful policy path.
#[derive(Debug)]
pub(crate) struct ConfigDeserializeError {
    path: Option<String>,
    source: serde_json::Error,
}

impl ConfigDeserializeError {
    fn from_path_error(error: serde_path_to_error::Error<serde_json::Error>) -> Self {
        let path = error.path().to_string();
        let path = (path != ".").then_some(path);
        Self {
            path,
            source: error.into_inner(),
        }
    }

    /// Prefix a path produced while deserializing a JSON subtree with its path
    /// in the complete request.
    pub(crate) fn with_prefix(mut self, prefix: &str) -> Self {
        self.path = Some(match self.path.take() {
            None => prefix.to_string(),
            Some(path) if path.starts_with('[') => format!("{prefix}{path}"),
            Some(path) => format!("{prefix}.{path}"),
        });
        self
    }

    #[cfg(test)]
    fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    fn path_contains_secret(&self) -> bool {
        self.path.as_deref().is_some_and(|path| {
            let path = path.to_ascii_lowercase();
            SECRET_PATH_MARKERS
                .iter()
                .any(|marker| path.contains(marker))
        })
    }
}

impl fmt::Display for ConfigDeserializeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let source = if self.path_contains_secret() {
            redact_secret_value(&self.source)
        } else {
            self.source.to_string()
        };
        let source = escape_control_characters(&source);
        match self.source.classify() {
            Category::Syntax | Category::Eof => {
                write!(formatter, "Invalid JSON syntax: {source}")
            }
            Category::Data => match self.path.as_deref() {
                Some(path) => write!(
                    formatter,
                    "Invalid configuration at `{}`: {source}",
                    escape_control_characters(path)
                ),
                None => write!(formatter, "Invalid configuration: {source}"),
            },
            // Current constructors cannot produce reader I/O failures. Keep a
            // defensive message in case a reader-backed constructor is added.
            Category::Io => write!(formatter, "Unable to read JSON configuration: {source}"),
        }
    }
}

fn redact_secret_value(source: &serde_json::Error) -> String {
    let line = source.line();
    let column = source.column();
    if line > 0 {
        return format!("invalid secret value at line {line} column {column}");
    }
    "invalid secret value".to_string()
}

fn escape_control_characters(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            escaped.extend(character.escape_default());
        } else if is_diagnostic_format_character(character) {
            escaped.extend(character.escape_unicode());
        } else {
            escaped.push(character);
        }
    }
    escaped
}

/// Escape control and invisible-format characters in free-form, user-controlled
/// text before it reaches a diagnostic sink. Shared with the manual
/// (non-serde) semantic validators so every user-derived diagnostic honors the
/// same "no raw control/format bytes in diagnostics" guarantee.
pub(crate) fn escape_diagnostic_text(value: &str) -> String {
    escape_control_characters(value)
}

/// Invisible Unicode formatting characters (Unicode general category `Cf` and a
/// few related invisibles) that `char::is_control()` does **not** cover. This
/// table is a deliberate security control, not incidental hardening: escaping
/// bidirectional overrides/isolates (U+202A–U+202E, U+2066–U+2069) defends
/// against "Trojan Source" (CVE-2021-42574) visual-spoofing of diagnostics,
/// escaping the line/paragraph separators (U+2028/U+2029) prevents forging hard
/// line breaks that some terminals/log viewers honor, and escaping zero-width /
/// joiner / interlinear characters prevents concealing or forging log and
/// error-envelope content rendered in a terminal or editor.
fn is_diagnostic_format_character(character: char) -> bool {
    matches!(
        character,
        '\u{00ad}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061c}'
            | '\u{06dd}'
            | '\u{070f}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08e2}'
            | '\u{17b4}'..='\u{17b5}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{2029}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{110bd}'
            | '\u{110cd}'
            | '\u{13430}'..='\u{1343f}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0001}'
            | '\u{e0020}'..='\u{e007f}'
    )
}

impl std::error::Error for ConfigDeserializeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

fn deserialize_with_path<'de, T, D>(deserializer: D) -> Result<T, ConfigDeserializeError>
where
    T: Deserialize<'de>,
    D: Deserializer<'de, Error = serde_json::Error>,
{
    serde_path_to_error::deserialize(deserializer).map_err(ConfigDeserializeError::from_path_error)
}

pub(crate) fn from_str<'de, T>(json: &'de str) -> Result<T, ConfigDeserializeError>
where
    T: Deserialize<'de>,
{
    let mut deserializer = serde_json::Deserializer::from_str(json);
    let value = deserialize_with_path(&mut deserializer)?;
    deserializer
        .end()
        .map_err(|source| ConfigDeserializeError { path: None, source })?;
    Ok(value)
}

pub(crate) fn from_value<T>(value: Value) -> Result<T, ConfigDeserializeError>
where
    T: DeserializeOwned,
{
    deserialize_with_path(value)
}

pub(crate) fn from_value_ref<'de, T>(value: &'de Value) -> Result<T, ConfigDeserializeError>
where
    T: Deserialize<'de>,
{
    deserialize_with_path(value)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct Outer {
        inner: Inner,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct Inner {
        count: u16,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    #[allow(dead_code)]
    struct Secret {
        wam_token: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    #[allow(dead_code)]
    struct NumericSecret {
        api_token: u32,
    }

    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    struct MapOuter {
        items: HashMap<String, Inner>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    #[allow(dead_code)]
    struct UserHolder {
        user: Secret,
    }

    #[test]
    fn redacts_scalar_supplied_where_credential_subtree_is_expected() {
        // A token supplied where the `user` object is expected pathes the error
        // at `user`, not at `wamToken`; the whole credential subtree must still
        // redact so the scalar is never echoed into diagnostics or the envelope.
        let error = from_str::<UserHolder>(r#"{"user": "super-secret-bearer-token"}"#).unwrap_err();
        let message = error.to_string();

        assert!(
            message.contains("Invalid configuration at `user`"),
            "got: {message}"
        );
        assert!(message.contains("invalid secret value"), "got: {message}");
        assert!(
            !message.contains("super-secret-bearer-token"),
            "got: {message}"
        );
    }

    #[test]
    fn data_errors_include_the_nested_path_and_source_location() {
        let error = from_str::<Outer>(
            r#"{
                "inner": {
                    "count": 70000
                }
            }"#,
        )
        .unwrap_err();

        assert_eq!(error.path(), Some("inner.count"));
        let message = error.to_string();
        assert!(message.contains("Invalid configuration at `inner.count`"));
        assert!(message.contains("expected u16"));
        assert!(message.contains("line 3"));
    }

    #[test]
    fn syntax_errors_are_distinguished_from_typed_config_errors() {
        let error = from_str::<Outer>(r#"{"inner": {"count": 1}"#).unwrap_err();
        let message = error.to_string();
        assert!(message.starts_with("Invalid JSON syntax:"));
        assert!(message.contains("line 1"));
    }

    #[test]
    fn trailing_json_data_is_rejected() {
        let error = from_str::<Outer>(r#"{"inner": {"count": 1}} {"second": true}"#).unwrap_err();
        assert!(error.to_string().starts_with("Invalid JSON syntax:"));
    }

    #[test]
    fn subtree_paths_can_be_prefixed_with_their_request_location() {
        let value = serde_json::json!({"count": "many"});
        let error = from_value_ref::<Inner>(&value)
            .unwrap_err()
            .with_prefix("experimental.example.start");

        assert_eq!(error.path(), Some("experimental.example.start.count"));
        assert!(error
            .to_string()
            .contains("experimental.example.start.count"));
    }

    #[test]
    fn root_level_errors_have_no_policy_path_or_rust_type_name() {
        let error = from_str::<crate::wire::MxcConfig>(r#""not an object""#).unwrap_err();
        assert_eq!(error.path(), None);
        let message = error.to_string();
        assert!(message.contains("expected a configuration object"));
        assert!(!message.contains("MxcConfig"));
    }

    #[test]
    fn array_subtree_paths_are_prefixed_without_an_extra_dot() {
        let value = serde_json::json!([{"count": "many"}]);
        let error = from_value_ref::<Vec<Inner>>(&value)
            .unwrap_err()
            .with_prefix("experimental.example.start");

        assert_eq!(error.path(), Some("experimental.example.start[0].count"));
    }

    #[test]
    fn from_value_reports_the_typed_error_path() {
        let value = serde_json::json!({"inner": {"count": "many"}});
        let error = from_value::<Outer>(value).unwrap_err();

        assert_eq!(error.path(), Some("inner.count"));
        assert!(error.to_string().contains("expected u16"));
    }

    #[test]
    fn display_escapes_control_characters_from_paths_and_sources() {
        let json = "{\"items\":{\"forged\\n\\u001b[31mline\":{\"count\":\"value\\n\\u001b[32m\"}}}";
        let error = from_str::<MapOuter>(json).unwrap_err();
        let message = error.to_string();

        assert!(!message.contains('\n'));
        assert!(!message.contains('\u{1b}'));
        assert!(message.contains("\\n"), "got: {message}");
        assert!(message.contains("\\u{1b}"), "got: {message}");
    }

    #[test]
    fn display_escapes_unicode_format_characters_from_paths_and_sources() {
        let json = "{\"items\":{\"forged\u{202e}line\":{\"count\":\"value\u{200b}hidden\"}}}";
        let error = from_str::<MapOuter>(json).unwrap_err();
        let message = error.to_string();

        assert!(!message.contains('\u{202e}'));
        assert!(!message.contains('\u{200b}'));
        assert!(message.contains("\\u{202e}"), "got: {message}");
        assert!(message.contains("\\u{200b}"), "got: {message}");
    }

    #[test]
    fn display_redacts_values_at_secret_bearing_paths() {
        let error = from_str::<Secret>(r#"{"wamToken": 123456789}"#).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Invalid configuration at `wamToken`"));
        assert!(message.contains("invalid secret value"));
        assert!(message.contains("line 1"));
        assert!(!message.contains("123456789"));
    }

    #[test]
    fn secret_redaction_never_parses_attacker_controlled_error_text() {
        let error = from_str::<NumericSecret>(
            r#"{"apiToken": "expected leak-of-secret-data", "other": true}"#,
        )
        .unwrap_err();
        let message = error.to_string();

        assert!(message.contains("Invalid configuration at `apiToken`"));
        assert!(message.contains("invalid secret value at line 1 column"));
        assert!(!message.contains("expected leak-of-secret-data"));
        assert!(!message.contains("leak-of-secret-data"));
    }

    #[test]
    fn secret_markers_are_detected_case_insensitively() {
        for path in [
            "wamToken",
            "adminPassword",
            "clientSecret",
            "serviceCredential",
            "apiKey",
            "accessKey",
            "privateKey",
            "passphrase",
            "pwd",
            "bearer",
            "sasKey",
            "connectionString",
        ] {
            let error = ConfigDeserializeError {
                path: Some(path.to_string()),
                source: serde_json::from_str::<Secret>(r#"{"wamToken": 123456789}"#).unwrap_err(),
            };

            assert!(
                error.to_string().contains("invalid secret value"),
                "path {path} was not treated as sensitive"
            );
        }
    }

    #[test]
    fn ordinary_key_suffixes_are_not_treated_as_secrets() {
        let error = ConfigDeserializeError {
            path: Some("monkey".to_string()),
            source: serde_json::from_str::<Secret>(r#"{"wamToken": 123456789}"#).unwrap_err(),
        };

        assert!(!error.to_string().contains("invalid secret value"));
    }

    #[test]
    fn escapes_line_and_paragraph_separators() {
        // U+2028 (LINE SEPARATOR) and U+2029 (PARAGRAPH SEPARATOR) render as
        // hard line breaks in some terminals/log viewers, so they must be
        // escaped to prevent forged multi-line diagnostics.
        let escaped = escape_diagnostic_text("a\u{2028}b\u{2029}c");

        assert!(!escaped.contains('\u{2028}'));
        assert!(!escaped.contains('\u{2029}'));
        assert!(escaped.contains("\\u{2028}"), "got: {escaped}");
        assert!(escaped.contains("\\u{2029}"), "got: {escaped}");
    }

    #[test]
    fn leaves_plain_text_unchanged() {
        let plain = "plain diagnostic text 123";
        assert_eq!(escape_diagnostic_text(plain), plain);
    }
}
