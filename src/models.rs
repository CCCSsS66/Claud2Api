use crate::{
    error::{Fault, Result},
    protocol,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashSet;

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ModelConfig {
    pub enabled: bool,
    pub entries: Vec<ModelEntry>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelEntry {
    pub id: String,
    pub display_name: String,
    pub upstream_model: String,
    pub enabled: bool,
}
pub struct Selection {
    pub upstream: String,
    pub public: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct UpstreamCatalog {
    pub account_id: String,
    pub fetched_at: i64,
    pub models: Vec<String>,
}
impl UpstreamCatalog {
    pub fn defaults(&self) -> Vec<ModelEntry> {
        self.models
            .iter()
            .map(|id| ModelEntry {
                id: id.clone(),
                display_name: id.clone(),
                upstream_model: id.clone(),
                enabled: true,
            })
            .collect()
    }
    pub fn validate(&self) -> Result<()> {
        if self.models.is_empty()
            || self.models.len() > 256
            || self
                .models
                .iter()
                .any(|id| !valid_id(id) || id.starts_with("c2a-"))
        {
            return Err(Fault::upstream());
        }
        Ok(())
    }
}
pub fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 150
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}
impl ModelConfig {
    pub fn validate(&self) -> Result<()> {
        if self.entries.len() > 256 {
            return Err(Fault::invalid("configure at most 256 models"));
        }
        let mut ids = HashSet::new();
        for entry in &self.entries {
            if !valid_id(&entry.id)
                || protocol::resolve_model(&entry.id, "").is_err()
                || !valid_id(&entry.upstream_model)
                || entry.upstream_model.starts_with("c2a-")
                || entry.display_name.trim().is_empty()
                || entry.display_name.chars().count() > 100
                || entry.display_name.chars().any(char::is_control)
                || !ids.insert(&entry.id)
            {
                return Err(Fault::invalid(
                    "model IDs must be unique and valid; upstream model IDs must be native names",
                ));
            }
        }
        Ok(())
    }
    pub fn resolve(&self, requested: &str, fallback: &str) -> Result<Selection> {
        let id = protocol::resolve_model(requested, fallback)?;
        if !self.enabled {
            return Ok(Selection {
                upstream: id.clone(),
                public: id,
            });
        }
        let original = if requested.is_empty() {
            fallback
        } else {
            requested
        };
        let entry = self
            .entries
            .iter()
            .find(|v| v.id == original)
            .or_else(|| self.entries.iter().find(|v| v.id == id))
            .filter(|v| v.enabled)
            .ok_or_else(|| {
                Fault::invalid(
                    "model is not exposed by this gateway; use an ID from GET /v1/models",
                )
            })?;
        Ok(Selection {
            upstream: entry.upstream_model.clone(),
            public: entry.id.clone(),
        })
    }
    pub fn catalog(&self, actual: &[String]) -> Value {
        let rows: Vec<Value> = if self.enabled {
            self.entries
                .iter()
                .filter(|v| v.enabled && actual.contains(&v.upstream_model))
                .map(|v| model_row(&v.id, &v.display_name))
                .collect()
        } else {
            actual.iter().map(|id| model_row(id, id)).collect()
        };
        let first = rows.first().map(|v| v["id"].clone());
        let last = rows.last().map(|v| v["id"].clone());
        json!({"object":"list","data":rows,"has_more":false,"first_id":first,"last_id":last})
    }
}
// The web catalog has no real creation timestamps. Emit a stable epoch so the
// Anthropic (`type`/`display_name`/`created_at`) and OpenAI (`object`/`created`/
// `owned_by`) model schemas are both satisfiable from one payload.
fn model_row(id: &str, display_name: &str) -> Value {
    json!({"id":id,"type":"model","display_name":display_name,"created_at":"1970-01-01T00:00:00Z","object":"model","created":0,"owned_by":"anthropic"})
}
