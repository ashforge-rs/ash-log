// Shared OCSF code-generation logic.
//
// This file is included via the `include!` macro by both `build.rs` (compile-time
// generation) and `src/bin/ocsf_codegen.rs` (the standalone CLI tool).  It must
// therefore be valid Rust that compiles in both contexts, which means:
//   • no `use` statements that rely on items defined outside this file
//   • every dependency must be available from `std` or be explicitly qualified

use std::collections::HashMap;

// ── Schema data model ──────────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
struct Schema {
    version: String,
    enums: HashMap<String, EnumDef>,
    objects: HashMap<String, ObjectDef>,
    event_classes: HashMap<String, EventClassDef>,
}

#[derive(Debug, serde::Deserialize)]
struct EnumDef {
    description: String,
    values: Vec<EnumValue>,
}

#[derive(Debug, serde::Deserialize)]
struct EnumValue {
    id: i32,
    name: String,
    description: String,
}

#[derive(Debug, serde::Deserialize)]
struct ObjectDef {
    description: String,
    fields: Vec<FieldDef>,
}

#[derive(Debug, serde::Deserialize)]
struct EventClassDef {
    class_uid: i32,
    category_uid: i32,
    description: String,
    activity_enum: String,
    fields: Vec<FieldDef>,
}

#[derive(Debug, serde::Deserialize)]
struct FieldDef {
    name: String,
    #[serde(rename = "type")]
    ty: String,
    #[serde(default)]
    object_ref: Option<String>,
    #[serde(default)]
    enum_ref: Option<String>,
    required: bool,
    description: String,
}

// ── String helpers ──────────────────────────────────────────────────────────────

fn pascal_case(s: &str) -> String {
    s.split('_')
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
            }
        })
        .collect()
}

fn rust_field_name(s: &str) -> &str {
    match s {
        // `type` is a reserved keyword in Rust; rename to `type_` and rely on
        // the serde field name (which stays `"type"` in JSON) being populated
        // from the schema's JSON key, not the Rust field name.
        "type" => "type_",
        other => other,
    }
}

fn rust_primitive(ty: &str) -> &str {
    match ty {
        "string" => "String",
        "i32" => "i32",
        "i64" => "i64",
        "bool" => "bool",
        "string_array" => "Vec<String>",
        _ => "String",
    }
}

// ── Emitters ───────────────────────────────────────────────────────────────────

fn emit_enum(name: &str, def: &EnumDef) -> String {
    let type_name = format!("Ocsf{}", pascal_case(name));
    let mut out = String::new();

    out.push_str(&format!("/// {}\n", def.description));
    out.push_str("#[allow(dead_code, clippy::upper_case_acronyms, clippy::doc_markdown)]\n");
    out.push_str("#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]\n");
    out.push_str("#[repr(i32)]\n");
    out.push_str(&format!("pub enum {} {{\n", type_name));
    for (i, v) in def.values.iter().enumerate() {
        out.push_str(&format!("    /// {}\n", v.description));
        if i == 0 {
            out.push_str("    #[default]\n");
        }
        out.push_str(&format!("    {} = {},\n", pascal_case(&v.name), v.id));
    }
    out.push_str("}\n\n");

    // Serialize as numeric i32 (OCSF uses integer IDs in JSON)
    out.push_str(&format!(
        "impl serde::Serialize for {t} {{\n    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {{\n        s.serialize_i32(*self as i32)\n    }}\n}}\n\n",
        t = type_name
    ));

    // Deserialize from i32
    out.push_str(&format!(
        "impl<'de> serde::Deserialize<'de> for {t} {{\n    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {{\n        let n = <i32 as serde::Deserialize>::deserialize(deserializer)?;\n        match n {{\n",
        t = type_name
    ));
    for v in &def.values {
        out.push_str(&format!(
            "            {} => Ok({}::{}),\n",
            v.id,
            type_name,
            pascal_case(&v.name)
        ));
    }
    out.push_str(&format!(
        "            _ => Err(serde::de::Error::custom(format!(\"unknown {t} variant: {{n}}\"))),\n",
        t = type_name
    ));
    out.push_str("        }\n    }\n}\n\n");

    out
}

fn emit_object(name: &str, def: &ObjectDef, schema: &Schema, schema_version: &str) -> String {
    let type_name = format!("Ocsf{}", pascal_case(name));
    let mut out = String::new();

    out.push_str(&format!("/// {}\n", def.description));
    out.push_str("#[allow(clippy::doc_markdown)]\n");
    out.push_str(
        "#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]\n",
    );
    out.push_str(&format!("pub struct {} {{\n", type_name));
    for f in &def.fields {
        let field_name = rust_field_name(&f.name);
        out.push_str(&format!("    /// {}\n", f.description));
        let rust_ty = object_field_rust_type(f, schema);
        if f.required {
            out.push_str(&format!("    pub {}: {},\n", field_name, rust_ty));
        } else {
            out.push_str("    #[serde(skip_serializing_if = \"Option::is_none\")]\n");
            out.push_str(&format!(
                "    pub {}: Option<{}>,\n",
                field_name, rust_ty
            ));
        }
    }
    out.push_str("}\n\n");

    // Constructor helpers
    out.push_str("#[allow(clippy::must_use_candidate)]\n");
    out.push_str(&format!("impl {} {{\n", type_name));

    // Determine if the struct has a simple 'name' + 'vendor_name' pattern (product)
    let required_fields: Vec<&FieldDef> = def.fields.iter().filter(|f| f.required).collect();
    if required_fields.is_empty() {
        // new() with no args
        out.push_str(&format!(
            "    /// Create a default `{}`.\n    pub fn new() -> Self {{ Self::default() }}\n",
            type_name
        ));
    } else {
        let params: Vec<String> = required_fields
            .iter()
            .map(|f| {
                let rt = object_field_rust_type(f, schema);
                format!("{}: impl Into<{}>", rust_field_name(&f.name), rt)
            })
            .collect();
        let assigns: Vec<String> = required_fields
            .iter()
            .map(|f| {
                let fn_ = rust_field_name(&f.name);
                format!("{}: {}.into()", fn_, fn_)
            })
            .collect();
        out.push_str(&format!(
            "    /// Create a new `{}` with all required fields.\n    pub fn new({}) -> Self {{\n        Self {{ {}, ..Default::default() }}\n    }}\n",
            type_name,
            params.join(", "),
            assigns.join(", "),
        ));
    }

    // special helper for network_endpoint: from_ip
    if name == "network_endpoint" {
        out.push_str(
            "    /// Create an endpoint with only an IP address set.\n    pub fn from_ip(ip: impl Into<String>) -> Self {\n        Self { ip: Some(ip.into()), ..Default::default() }\n    }\n",
        );
    }

    // special helper for user: with_name
    if name == "user" {
        out.push_str(
            "    /// Create a user with only `name` set.\n    pub fn with_name(name: impl Into<String>) -> Self {\n        Self { name: Some(name.into()), ..Default::default() }\n    }\n",
        );
    }

    // special helper for metadata: new convenience without version arg
    if name == "metadata" {
        out.push_str(&format!(
            "    /// Create metadata with schema version `{v}` and the given product.\n    pub fn from_product(product: OcsfProduct) -> Self {{\n        Self {{ version: \"{v}\".into(), product, ..Default::default() }}\n    }}\n",
            v = schema_version
        ));
    }

    out.push_str("}\n\n");

    out
}

fn object_field_rust_type(f: &FieldDef, schema: &Schema) -> String {
    match f.ty.as_str() {
        "object" => {
            let obj_ref = f.object_ref.as_deref().unwrap_or("unknown");
            format!("Ocsf{}", pascal_case(obj_ref))
        }
        "object_array" => {
            let obj_ref = f.object_ref.as_deref().unwrap_or("unknown");
            format!("Vec<Ocsf{}>", pascal_case(obj_ref))
        }
        "enum" => {
            let enum_ref = f.enum_ref.as_deref().unwrap_or("unknown");
            if schema.enums.contains_key(enum_ref) {
                format!("Ocsf{}", pascal_case(enum_ref))
            } else {
                "i32".to_string()
            }
        }
        other => rust_primitive(other).to_string(),
    }
}

fn event_field_rust_type(f: &FieldDef, schema: &Schema) -> String {
    match f.ty.as_str() {
        "object" => {
            let obj_ref = f.object_ref.as_deref().unwrap_or("unknown");
            format!("Ocsf{}", pascal_case(obj_ref))
        }
        "object_array" => {
            let obj_ref = f.object_ref.as_deref().unwrap_or("unknown");
            format!("Vec<Ocsf{}>", pascal_case(obj_ref))
        }
        "enum" => {
            let enum_ref = f.enum_ref.as_deref().unwrap_or("unknown");
            let class_enum_type = format!("Ocsf{}", pascal_case(enum_ref));
            if schema.enums.contains_key(enum_ref) {
                class_enum_type
            } else {
                "i32".to_string()
            }
        }
        other => rust_primitive(other).to_string(),
    }
}

fn emit_event_class(name: &str, def: &EventClassDef, schema: &Schema) -> String {
    let struct_name = format!("Ocsf{}", pascal_case(name));
    let builder_name = format!("{}Builder", struct_name);
    let _activity_enum = format!("Ocsf{}", pascal_case(&def.activity_enum));
    let mut out = String::new();

    // ── Event struct ────────────────────────────────────────────────────────────
    out.push_str(&format!("/// {}\n", def.description));
    out.push_str("#[allow(clippy::doc_markdown)]\n");
    out.push_str("#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]\n");
    out.push_str(&format!("pub struct {} {{\n", struct_name));

    // Fixed base fields
    out.push_str("    /// OCSF class UID.\n    pub class_uid: i32,\n");
    out.push_str("    /// OCSF category UID.\n    pub category_uid: i32,\n");
    out.push_str("    /// Event type UID (class_uid * 100 + activity_id).\n    pub type_uid: i64,\n");
    out.push_str("    /// Event timestamp (Unix epoch ms).\n    pub time: i64,\n");
    out.push_str("    /// Event metadata.\n    pub metadata: OcsfMetadata,\n");
    out.push_str("    /// Normalized event severity.\n    pub severity_id: OcsfSeverityId,\n");
    out.push_str("    /// Human-readable severity label.\n    #[serde(skip_serializing_if = \"Option::is_none\")]\n    pub severity: Option<String>,\n");
    out.push_str("    /// Optional free-text message.\n    #[serde(skip_serializing_if = \"Option::is_none\")]\n    pub message: Option<String>,\n");

    // Class-specific fields
    for f in &def.fields {
        let field_name = rust_field_name(&f.name);
        out.push_str(&format!("    /// {}\n", f.description));
        let rust_ty = event_field_rust_type(f, schema);
        if f.required {
            out.push_str(&format!("    pub {}: {},\n", field_name, rust_ty));
        } else {
            out.push_str("    #[serde(skip_serializing_if = \"Option::is_none\")]\n");
            out.push_str(&format!(
                "    pub {}: Option<{}>,\n",
                field_name, rust_ty
            ));
        }
    }
    out.push_str("}\n\n");

    // ── builder() factory ───────────────────────────────────────────────────────
    out.push_str("#[allow(clippy::must_use_candidate)]\n");
    out.push_str(&format!("impl {} {{\n", struct_name));
    out.push_str(&format!(
        "    /// Create a builder for `{}`.\n    pub fn builder() -> {} {{ {}::default() }}\n",
        struct_name, builder_name, builder_name
    ));
    out.push_str("}\n\n");

    // ── OcsfEvent trait impl ────────────────────────────────────────────────────
    out.push_str(&format!(
        "impl OcsfEvent for {} {{\n    fn class_uid(&self) -> i32 {{ {} }}\n    fn category_uid(&self) -> i32 {{ {} }}\n}}\n\n",
        struct_name, def.class_uid, def.category_uid
    ));

    // ── Builder struct ──────────────────────────────────────────────────────────
    out.push_str(&format!(
        "/// Builder for [`{}`].\n#[must_use]\n#[derive(Debug, Default)]\npub struct {} {{\n",
        struct_name, builder_name
    ));
    // Required base fields
    out.push_str("    time: Option<i64>,\n");
    out.push_str("    metadata: Option<OcsfMetadata>,\n");
    out.push_str("    severity_id: Option<OcsfSeverityId>,\n");
    out.push_str("    severity: Option<String>,\n");
    out.push_str("    message: Option<String>,\n");
    // Class-specific
    for f in &def.fields {
        let field_name = rust_field_name(&f.name);
        let rust_ty = event_field_rust_type(f, schema);
        out.push_str(&format!("    {}: Option<{}>,\n", field_name, rust_ty));
    }
    out.push_str("}\n\n");

    // ── Builder impl ────────────────────────────────────────────────────────────
    out.push_str("#[allow(clippy::must_use_candidate)]\n");
    out.push_str(&format!("impl {} {{\n", builder_name));

    // Base setters
    out.push_str(
        "    /// Set the event timestamp (Unix epoch milliseconds).\n    pub fn time(mut self, v: i64) -> Self { self.time = Some(v); self }\n",
    );
    out.push_str(
        "    /// Set the event metadata.\n    pub fn metadata(mut self, v: OcsfMetadata) -> Self { self.metadata = Some(v); self }\n",
    );
    out.push_str(
        "    /// Set the normalized severity ID.\n    pub fn severity_id(mut self, v: OcsfSeverityId) -> Self { self.severity_id = Some(v); self }\n",
    );
    out.push_str(
        "    /// Set the human-readable severity label.\n    pub fn severity(mut self, v: impl Into<String>) -> Self { self.severity = Some(v.into()); self }\n",
    );
    out.push_str(
        "    /// Set an optional free-text message.\n    pub fn message(mut self, v: impl Into<String>) -> Self { self.message = Some(v.into()); self }\n",
    );

    // Per-field setters
    for f in &def.fields {
        let field_name = rust_field_name(&f.name);
        let rust_ty = event_field_rust_type(f, schema);
        // Use Into<T> for String types, direct T for everything else
        if rust_ty == "String" {
            out.push_str(&format!(
                "    /// Set `{}`.\n    pub fn {}(mut self, v: impl Into<String>) -> Self {{ self.{} = Some(v.into()); self }}\n",
                field_name, field_name, field_name
            ));
        } else {
            out.push_str(&format!(
                "    /// Set `{}`.\n    pub fn {}(mut self, v: {}) -> Self {{ self.{} = Some(v); self }}\n",
                field_name, field_name, rust_ty, field_name
            ));
        }
    }

    // build()
    out.push_str(&format!(
        "    /// Consume the builder and return the constructed `{}`.\n    pub fn build(self) -> {} {{\n",
        struct_name, struct_name
    ));
    out.push_str("        let activity_id = self.activity_id.unwrap_or_default();\n");
    out.push_str(&format!(
        "        let type_uid = i64::from({class_uid}) * 100 + i64::from(activity_id as i32);\n",
        class_uid = def.class_uid
    ));
    out.push_str(&format!("        {} {{\n", struct_name));
    out.push_str(&format!("            class_uid: {},\n", def.class_uid));
    out.push_str(&format!("            category_uid: {},\n", def.category_uid));
    out.push_str("            type_uid,\n");
    out.push_str(
        "            time: self.time.unwrap_or(0),\n",
    );
    out.push_str(
        "            metadata: self.metadata.unwrap_or_default(),\n",
    );
    out.push_str(
        "            severity_id: self.severity_id.unwrap_or_default(),\n",
    );
    out.push_str("            severity: self.severity,\n");
    out.push_str("            message: self.message,\n");

    // Assign each event-class-specific field
    for f in &def.fields {
        let field_name = rust_field_name(&f.name);
        if f.required {
            out.push_str(&format!(
                "            {f}: self.{f}.unwrap_or_default(),\n",
                f = field_name
            ));
        } else {
            out.push_str(&format!("            {f}: self.{f},\n", f = field_name));
        }
    }
    out.push_str("        }\n    }\n}\n\n");

    out
}

// ── Top-level generator ─────────────────────────────────────────────────────────

fn generate_from_schema(schema_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(schema_path)?;
    let schema: Schema = serde_json::from_str(&content)?;

    let mut out = String::new();

    out.push_str("// AUTO-GENERATED from ");
    out.push_str(schema_path);
    out.push_str(" — do not edit by hand.\n");
    out.push_str(&format!("// OCSF schema version: {}\n\n", schema.version));

    // Emit enums in a stable order
    let mut enum_names: Vec<&String> = schema.enums.keys().collect();
    enum_names.sort();
    for name in &enum_names {
        out.push_str(&emit_enum(name, &schema.enums[*name]));
    }

    // Emit objects in a stable order, with dependencies first.
    // Simple two-pass: non-dependent objects first, then those that reference others.
    let mut obj_names: Vec<&String> = schema.objects.keys().collect();
    obj_names.sort();
    // First pass — objects whose fields don't reference other objects
    let mut first_pass: Vec<&String> = obj_names
        .iter()
        .copied()
        .filter(|n| {
            schema.objects[*n]
                .fields
                .iter()
                .all(|f| f.ty != "object" && f.ty != "object_array")
        })
        .collect();
    first_pass.sort();
    // Second pass — everything else
    let mut second_pass: Vec<&String> = obj_names
        .iter()
        .copied()
        .filter(|n| {
            schema.objects[*n]
                .fields
                .iter()
                .any(|f| f.ty == "object" || f.ty == "object_array")
        })
        .collect();
    second_pass.sort();

    for name in first_pass.iter().chain(second_pass.iter()) {
        out.push_str(&emit_object(name, &schema.objects[*name], &schema, &schema.version));
    }

    // Emit event classes
    let mut class_names: Vec<&String> = schema.event_classes.keys().collect();
    class_names.sort();
    for name in &class_names {
        out.push_str(&emit_event_class(
            name,
            &schema.event_classes[*name],
            &schema,
        ));
    }

    Ok(out)
}
