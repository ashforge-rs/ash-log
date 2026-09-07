//! JSON schema validation for OCSF 1.8.0 events.
//!
//! This module provides [`validate_ocsf_event`] and [`validate_ocsf_event_strict`]
//! which perform structural validation of OCSF event JSON objects against the
//! OCSF 1.8.0 base-event requirements.
//!
//! # Example
//!
//! ```rust
//! use ash_log::ocsf::schema::validate_ocsf_event;
//! use serde_json::json;
//!
//! let event = json!({
//!     "class_uid": 3002,
//!     "category_uid": 3,
//!     "activity_id": "logon",
//!     "type_uid": 300_201_i64,
//!     "time": 1_700_000_000_000_i64,
//!     "severity_id": "informational",
//!     "metadata": {
//!         "version": "1.8.0",
//!         "product": { "name": "MyApp", "vendor_name": "MyOrg" }
//!     }
//! });
//!
//! // Returns Ok(()) for a valid event
//! assert!(validate_ocsf_event(&event).is_ok());
//! ```

use std::fmt;

/// A validation error returned by [`validate_ocsf_event`].
#[derive(Debug)]
pub struct OcsfValidationError {
    /// Human-readable description of every violation found.
    pub details: Vec<String>,
}

impl fmt::Display for OcsfValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OCSF validation failed:")?;
        for d in &self.details {
            write!(f, "\n  - {d}")?;
        }
        Ok(())
    }
}

impl std::error::Error for OcsfValidationError {}

/// The required integer keys that every OCSF event must carry.
const REQUIRED_INT_FIELDS: &[&str] = &["class_uid", "category_uid", "type_uid", "time"];

/// The `severity_id` range accepted by OCSF 1.3.
const VALID_SEVERITY_IDS: &[i64] = &[0, 1, 2, 3, 4, 5, 6, 99];

/// Validate a JSON value as an OCSF event.
///
/// This performs structural validation against the OCSF 1.8.0 base-event
/// requirements:
///
/// * `class_uid`, `category_uid`, `type_uid`, and `time` must be present
///   and numeric.
/// * `severity_id` must be a recognised OCSF severity value if present.
/// * `metadata` must be an object containing `version` (string) and
///   `product` (object with `name` and `vendor_name`).
/// * `activity_id` must be present.
///
/// Additional fields are allowed (OCSF is an open schema).
///
/// Returns `Ok(())` when valid, or [`OcsfValidationError`] listing every
/// problem found.
///
/// # Errors
///
/// Returns [`OcsfValidationError`] when the event fails validation.
pub fn validate_ocsf_event(event: &serde_json::Value) -> Result<(), OcsfValidationError> {
    let mut errors: Vec<String> = Vec::new();

    let Some(obj) = event.as_object() else {
        return Err(OcsfValidationError {
            details: vec!["event must be a JSON object".to_string()],
        });
    };

    // Required numeric fields
    for field in REQUIRED_INT_FIELDS {
        match obj.get(*field) {
            None => errors.push(format!("missing required field '{field}'")),
            Some(v) if !v.is_number() => {
                errors.push(format!("field '{field}' must be a number, got {v}"));
            }
            Some(_) => {}
        }
    }

    // activity_id must be present (string or number, OCSF accepts both)
    if !obj.contains_key("activity_id") {
        errors.push("missing required field 'activity_id'".to_string());
    }

    // severity_id — optional but must be a recognised value when present
    if let Some(sev) = obj.get("severity_id") {
        let valid = match sev {
            serde_json::Value::Number(n) => {
                n.as_i64().is_some_and(|v| VALID_SEVERITY_IDS.contains(&v))
            }
            serde_json::Value::String(s) => matches!(
                s.as_str(),
                "unknown"
                    | "informational"
                    | "low"
                    | "medium"
                    | "high"
                    | "critical"
                    | "fatal"
                    | "other"
            ),
            _ => false,
        };
        if !valid {
            errors.push(format!(
                "field 'severity_id' has unrecognised value {sev}; \
                 valid values: 0-6, 99, or their snake_case names"
            ));
        }
    }

    // metadata object
    match obj.get("metadata") {
        None => errors.push("missing required field 'metadata'".to_string()),
        Some(m) => {
            let Some(meta) = m.as_object() else {
                errors.push("field 'metadata' must be a JSON object".to_string());
                return Err(OcsfValidationError { details: errors });
            };
            match meta.get("version") {
                None => errors.push("metadata.version is required".to_string()),
                Some(v) if !v.is_string() => {
                    errors.push(format!("metadata.version must be a string, got {v}"));
                }
                Some(_) => {}
            }
            match meta.get("product") {
                None => errors.push("metadata.product is required".to_string()),
                Some(p) => match p.as_object() {
                    None => errors.push("metadata.product must be a JSON object".to_string()),
                    Some(prod) => {
                        for key in &["name", "vendor_name"] {
                            match prod.get(*key) {
                                None => errors.push(format!("metadata.product.{key} is required")),
                                Some(v) if !v.is_string() => errors.push(format!(
                                    "metadata.product.{key} must be a string, got {v}"
                                )),
                                Some(_) => {}
                            }
                        }
                    }
                },
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(OcsfValidationError { details: errors })
    }
}

/// Validate a JSON value and additionally verify that `type_uid` equals
/// `class_uid * 100 + activity_id` when `activity_id` is numeric.
///
/// # Errors
///
/// Returns [`OcsfValidationError`] when the event fails validation.
///
/// # Panics
///
/// This function does not panic in practice; the `expect` call is guarded by
/// the preceding [`validate_ocsf_event`] check that ensures the value is an
/// object.
pub fn validate_ocsf_event_strict(event: &serde_json::Value) -> Result<(), OcsfValidationError> {
    validate_ocsf_event(event)?;

    let obj = event.as_object().expect("already validated as object");
    let mut errors: Vec<String> = Vec::new();

    let class_uid = obj
        .get("class_uid")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    let activity_id_opt = obj.get("activity_id").and_then(serde_json::Value::as_i64);
    let type_uid = obj
        .get("type_uid")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);

    if let Some(activity_id) = activity_id_opt {
        let expected = class_uid
            .checked_mul(100)
            .and_then(|v| v.checked_add(activity_id));
        match expected {
            Some(exp) if type_uid != exp => {
                errors.push(format!(
                    "type_uid {type_uid} does not match class_uid({class_uid}) \
                     * 100 + activity_id({activity_id}) = {exp}"
                ));
            }
            None => {
                errors.push(format!(
                    "type_uid derivation overflowed for class_uid({class_uid}) \
                     and activity_id({activity_id})"
                ));
            }
            Some(_) => {}
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(OcsfValidationError { details: errors })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn minimal_event() -> serde_json::Value {
        json!({
            "class_uid": 3002,
            "category_uid": 3,
            "activity_id": "logon",
            "type_uid": 300_201_i64,
            "time": 1_700_000_000_000_i64,
            "severity_id": "informational",
            "metadata": {
                "version": "1.8.0",
                "product": { "name": "TestApp", "vendor_name": "TestOrg" }
            }
        })
    }

    #[test]
    fn test_valid_event_passes() {
        assert!(validate_ocsf_event(&minimal_event()).is_ok());
    }

    #[test]
    fn test_missing_class_uid() {
        let mut e = minimal_event();
        e.as_object_mut().unwrap().remove("class_uid");
        let err = validate_ocsf_event(&e).unwrap_err();
        assert!(err.details.iter().any(|d| d.contains("class_uid")));
    }

    #[test]
    fn test_missing_metadata() {
        let mut e = minimal_event();
        e.as_object_mut().unwrap().remove("metadata");
        let err = validate_ocsf_event(&e).unwrap_err();
        assert!(err.details.iter().any(|d| d.contains("metadata")));
    }

    #[test]
    fn test_missing_metadata_product() {
        let mut e = minimal_event();
        e["metadata"].as_object_mut().unwrap().remove("product");
        let err = validate_ocsf_event(&e).unwrap_err();
        assert!(err.details.iter().any(|d| d.contains("product")));
    }

    #[test]
    fn test_invalid_severity() {
        let mut e = minimal_event();
        e["severity_id"] = json!(99_999);
        let err = validate_ocsf_event(&e).unwrap_err();
        assert!(err.details.iter().any(|d| d.contains("severity_id")));
    }

    #[test]
    fn test_not_an_object() {
        let e = json!("not an object");
        assert!(validate_ocsf_event(&e).is_err());
    }

    #[test]
    fn test_strict_valid_type_uid() {
        // type_uid = 3002 * 100 + 1 = 300201
        let mut e = minimal_event();
        e["activity_id"] = json!(1);
        e["type_uid"] = json!(300_201_i64);
        assert!(validate_ocsf_event_strict(&e).is_ok());
    }

    #[test]
    fn test_strict_wrong_type_uid() {
        let mut e = minimal_event();
        e["activity_id"] = json!(1);
        e["type_uid"] = json!(999_999_i64);
        let err = validate_ocsf_event_strict(&e).unwrap_err();
        assert!(err.details.iter().any(|d| d.contains("type_uid")));
    }

    #[test]
    fn test_error_display() {
        let mut e = minimal_event();
        e.as_object_mut().unwrap().remove("class_uid");
        e.as_object_mut().unwrap().remove("metadata");
        let err = validate_ocsf_event(&e).unwrap_err();
        let display = err.to_string();
        assert!(display.contains("OCSF validation failed"));
    }
}
