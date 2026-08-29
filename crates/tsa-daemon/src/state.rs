use crate::http_server::{
    import_bounces_from_sqlite, import_configs_from_sqlite, import_suspensions_from_sqlite,
    open_history_db, regex_list_to_string, toml_to_toml_edit_value, PreferRollup, Sha256Hasher,
    DB_PATH,
};
use anyhow::Context;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use kumo_api_types::shaping::{
    Action, EgressPathConfigAdjustment, EgressPathConfigValue, EgressPathConfigValueUnchecked, Rule,
};
use kumo_api_types::tsa::{ReadyQSuspension, SchedQBounce, SchedQSuspension};
use kumo_log_types::JsonLogRecord;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use throttle::{LimitSpec, ThrottleSpec};

pub static TSA_STATE: OnceLock<TsaState> = OnceLock::new();

/// Represents a specific rule definition.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RuleHash(#[serde(with = "serde_bytes")] [u8; 32]);

impl RuleHash {
    pub fn from_rule(rule: &Rule) -> Self {
        let mut hasher = Sha256Hasher::new();
        rule.hash(&mut hasher);
        Self(hasher.get_binary())
    }
}

impl std::fmt::Display for RuleHash {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        hex::encode(self.0).fmt(fmt)
    }
}

impl std::fmt::Debug for RuleHash {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        fmt.debug_tuple("RuleHash")
            .field(&hex::encode(self.0))
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SiteKey(String);

impl SiteKey {
    pub fn from_record(record: &JsonLogRecord) -> Self {
        Self(record.site.to_string())
    }
}

impl std::fmt::Display for SiteKey {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.0.fmt(fmt)
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActionHash(#[serde(with = "serde_bytes")] [u8; 32], SiteKey);

impl std::fmt::Display for ActionHash {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "{}-{}", self.1 .0, hex::encode(self.0))
    }
}

impl std::fmt::Debug for ActionHash {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        fmt.debug_tuple("ActionHash")
            .field(&hex::encode(self.0))
            .field(&self.1)
            .finish()
    }
}

impl ActionHash {
    pub fn from_rule_and_record(rule: &Rule, action: &Action, record: &JsonLogRecord) -> Self {
        let mut hasher = Sha256Hasher::new();
        rule.hash(&mut hasher);
        action.hash(&mut hasher);
        Self(hasher.get_binary(), SiteKey::from_record(record))
    }

    pub fn from_legacy_hash_and_site(hash: &str, site: &str) -> Self {
        let mut bytes = [0u8; 32];
        if let Err(err) = hex::decode_to_slice(hash, &mut bytes) {
            panic!("invalid action hash ahash={hash} {err:#}");
        }
        Self(bytes, SiteKey(site.to_string()))
    }

    pub fn from_legacy_action_hash_string(full_string: &str) -> Self {
        let Some((site, ahash)) = full_string.rsplit_once('-') else {
            panic!("invalid action hash {full_string}");
        };
        Self::from_legacy_hash_and_site(ahash, site)
    }

    pub fn hash_portion(&self) -> String {
        hex::encode(self.0)
    }

    pub fn site_name(&self) -> &str {
        &self.1 .0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MatchingScope(RuleHash, SiteKey);

impl MatchingScope {
    pub fn from_rule_and_record(rule: &Rule, record: &JsonLogRecord) -> Self {
        Self(RuleHash::from_rule(rule), SiteKey::from_record(record))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct EventData {
    /// Used to determine how to prune
    duration: i64,
    series: Vec<UnixTimeStamp>,
}

type UnixTimeStamp = i64;
fn to_unix_ts(dt: &DateTime<Utc>) -> UnixTimeStamp {
    dt.signed_duration_since(DateTime::<Utc>::UNIX_EPOCH)
        .num_seconds()
}

impl EventData {
    fn insert_and_count(&mut self, record: &JsonLogRecord) -> usize {
        let ts = to_unix_ts(&record.timestamp);
        let idx = match self.series.binary_search(&ts) {
            Ok(idx) | Err(idx) => idx,
        };

        self.series.insert(idx, ts);
        let now = Utc::now();
        let now_ts = to_unix_ts(&now);
        let report_thresh = now_ts - self.duration;
        let oldest_permitted = report_thresh - 300;

        self.series.retain(|&ts| ts > oldest_permitted);
        self.series
            .iter()
            .filter(|&&ts| ts >= report_thresh)
            .count()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigurationOverride {
    pub domain: String,
    pub mx_rollup: bool,
    pub source: String,
    pub reason: String,
    /// Explicitly store unchecked to accommodate version skew
    /// where we might not know about a value yet
    pub option: EgressPathConfigValueUnchecked,
    pub expires: DateTime<Utc>,
}

/// Captures the non-`limit` parts of a scaled EgressPathConfig field's
/// value, so that percentage math can operate purely on `u64` and the
/// TOML value can be reconstructed exactly at export time.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum AdaptiveFieldTemplate {
    Rate {
        period: u64,
        max_burst: Option<u64>,
        force_local: bool,
    },
    Limit {
        force_local: bool,
    },
}

impl AdaptiveFieldTemplate {
    pub fn to_toml_value(&self, limit: u64) -> toml::Value {
        match self {
            Self::Rate {
                period,
                max_burst,
                force_local,
            } => {
                let spec = ThrottleSpec {
                    limit,
                    period: *period,
                    max_burst: *max_burst,
                    force_local: *force_local,
                };
                toml::Value::String(spec.to_string())
            }
            Self::Limit { force_local: true } => toml::Value::String(format!("local:{limit}")),
            Self::Limit { force_local: false } => toml::Value::Integer(limit as i64),
        }
    }
}

/// Parse a raw TOML value for a supported AdjustConfig field into its
/// numeric `limit` and the template needed to reconstruct the full value
/// later. Returns an error for any field not in `ADAPTIVE_SUPPORTED_FIELDS`.
pub fn parse_adaptive_field_value(
    field_name: &str,
    value: &toml::Value,
) -> anyhow::Result<(u64, AdaptiveFieldTemplate)> {
    use kumo_api_types::shaping::ADAPTIVE_SUPPORTED_FIELDS;
    use serde::Deserialize;

    match field_name {
        "max_message_rate" | "max_connection_rate" | "source_selection_rate" => {
            let spec = ThrottleSpec::deserialize(value.clone())
                .with_context(|| format!("parsing {field_name} value {value:?} as ThrottleSpec"))?;
            Ok((
                spec.limit,
                AdaptiveFieldTemplate::Rate {
                    period: spec.period,
                    max_burst: spec.max_burst,
                    force_local: spec.force_local,
                },
            ))
        }
        "connection_limit" => {
            let spec = LimitSpec::deserialize(value.clone())
                .with_context(|| format!("parsing {field_name} value {value:?} as LimitSpec"))?;
            Ok((
                spec.limit,
                AdaptiveFieldTemplate::Limit {
                    force_local: spec.force_local,
                },
            ))
        }
        other => anyhow::bail!(
            "unsupported AdjustConfig field {other:?}; supported fields are: {}",
            ADAPTIVE_SUPPORTED_FIELDS.join(", ")
        ),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveOverride {
    pub domain: String,
    pub mx_rollup: bool,
    pub source: String,
    pub reason: String,
    pub field_name: String,
    pub template: AdaptiveFieldTemplate,
    pub original_limit: u64,
    pub current_limit: u64,
    pub decrease_percent: f64,
    pub floor_percent: f64,
    pub ramp_step_percent: f64,
    pub ramp_up_interval_secs: i64,
    pub safety_duration_secs: i64,
    pub last_activity: DateTime<Utc>,
    pub expires: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct SchedQBounceKey {
    pub action_hash: ActionHash,
    pub domain: String,
    pub tenant: Option<String>,
    pub campaign: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedQBounceEntry {
    pub reason: String,
    pub expires: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadyQSuspensionEntry {
    pub reason: String,
    pub source: String,
    pub expires: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct SchedQSuspensionKey {
    pub action_hash: ActionHash,
    pub domain: String,
    pub tenant: String,
    pub campaign: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedQSuspensionEntry {
    pub reason: String,
    pub expires: DateTime<Utc>,
}

#[derive(Default)]
pub struct TsaState {
    event_history: DashMap<MatchingScope, EventData>,
    config_overrides: DashMap<ActionHash, ConfigurationOverride>,
    adaptive_overrides: DashMap<ActionHash, AdaptiveOverride>,
    schedq_bounces: DashMap<SchedQBounceKey, SchedQBounceEntry>,
    readyq_suspensions: DashMap<ActionHash, ReadyQSuspensionEntry>,
    schedq_suspensions: DashMap<SchedQSuspensionKey, SchedQSuspensionEntry>,
}

#[derive(Serialize, Deserialize)]
struct SerializableState {
    #[serde(default)]
    event_history: HashMap<MatchingScope, EventData>,
    #[serde(default)]
    config_overrides: HashMap<ActionHash, ConfigurationOverride>,
    #[serde(default)]
    adaptive_overrides: HashMap<ActionHash, AdaptiveOverride>,
    #[serde(default)]
    schedq_bounces: HashMap<SchedQBounceKey, SchedQBounceEntry>,
    #[serde(default)]
    readyq_suspensions: HashMap<ActionHash, ReadyQSuspensionEntry>,
    #[serde(default)]
    schedq_suspensions: HashMap<SchedQSuspensionKey, SchedQSuspensionEntry>,
}

impl TsaState {
    /// Record the current event and return the total number
    /// of records in the time period defined by the rule
    pub fn record_event(&self, scope: &MatchingScope, rule: &Rule, record: &JsonLogRecord) -> u64 {
        let mut series = self
            .event_history
            .entry(scope.clone())
            .or_insert_with(|| EventData {
                duration: rule.duration.as_secs() as i64,
                series: vec![],
            });

        series.insert_and_count(record) as u64
    }

    pub fn create_config_override(
        &self,
        scope: &ActionHash,
        rule: &Rule,
        record: &JsonLogRecord,
        config: &EgressPathConfigValue,
        domain: &str,
        source: &str,
        prefer_rollup: PreferRollup,
    ) {
        let reason = format!("automation rule: {}", regex_list_to_string(&rule.regex));
        self.insert_config_override(
            scope.clone(),
            ConfigurationOverride {
                domain: domain.to_string(),
                reason,
                mx_rollup: match prefer_rollup {
                    PreferRollup::Yes => rule.was_rollup,
                    PreferRollup::No => false,
                },
                source: source.to_string(),
                option: config.clone().into(),
                expires: record.timestamp + rule.duration,
            },
        );
    }

    pub fn insert_config_override(&self, scope: ActionHash, over: ConfigurationOverride) {
        if Utc::now() >= over.expires {
            // Skip already expired entry
            return;
        }

        tracing::debug!("new config override {scope:?} = {over:?}");
        self.config_overrides.insert(scope, over);
    }

    /// Apply the down-path of an AdjustConfig/AdjustDomainConfig action:
    /// create the override entry on first trigger (seeding it from
    /// `original_value`), or compound the existing entry's current value
    /// down by `decrease_percent`, clamped at `floor_percent` of the
    /// original value.
    pub fn create_or_update_adaptive_override(
        &self,
        scope: &ActionHash,
        rule: &Rule,
        record: &JsonLogRecord,
        adj: &EgressPathConfigAdjustment,
        domain: &str,
        source: &str,
        prefer_rollup: PreferRollup,
        original_value: &toml::Value,
    ) -> anyhow::Result<()> {
        let now = record.timestamp;
        let expires = now + rule.duration;

        if Utc::now() >= expires {
            // Skip already expired entry, same as the sibling insert_*
            // methods in this file. This is currently redundant with the
            // caller's own pre-filtering in http_server.rs, but the
            // invariant should be enforced locally here too rather than
            // solely relied upon from the caller.
            return Ok(());
        }

        // Parsing `original_value` is only needed to seed a brand new
        // entry: an already-existing entry carries its own
        // original_limit/template, so a parse failure on a later trigger
        // must not abort processing of the rest of this record's other
        // matched actions (consistent with the "log-and-skip" intent
        // documented on the "no base value" branch in
        // http_server.rs::apply_adjust_config).
        if !self.adaptive_overrides.contains_key(scope) {
            let (original_limit, template) = parse_adaptive_field_value(&adj.name, original_value)?;
            self.adaptive_overrides
                .entry(scope.clone())
                .or_insert_with(|| AdaptiveOverride {
                    domain: domain.to_string(),
                    mx_rollup: match prefer_rollup {
                        PreferRollup::Yes => rule.was_rollup,
                        PreferRollup::No => false,
                    },
                    source: source.to_string(),
                    reason: format!("automation rule: {}", regex_list_to_string(&rule.regex)),
                    field_name: adj.name.clone(),
                    template,
                    original_limit,
                    current_limit: original_limit,
                    decrease_percent: adj.decrease_percent,
                    floor_percent: adj.floor_percent,
                    ramp_step_percent: adj.ramp_step_percent,
                    ramp_up_interval_secs: adj.ramp_up_interval.as_secs() as i64,
                    safety_duration_secs: rule.duration.as_secs() as i64,
                    last_activity: now,
                    expires,
                });
        }

        let Some(mut entry) = self.adaptive_overrides.get_mut(scope) else {
            // Extremely narrow race: the entry we just confirmed/inserted
            // was concurrently removed (e.g. by the prune tick) before we
            // could grab it. Nothing further to do for this trigger.
            return Ok(());
        };

        let floor_limit = ((entry.original_limit as f64) * (entry.floor_percent / 100.0))
            .round()
            .max(1.0) as u64;
        let decreased = ((entry.current_limit as f64) * (1.0 - entry.decrease_percent / 100.0))
            .round()
            .max(1.0) as u64;
        entry.current_limit = decreased.max(floor_limit);
        entry.last_activity = now;
        entry.expires = expires;

        tracing::debug!("adaptive override down-step {scope:?} = {:?}", *entry);
        Ok(())
    }

    pub fn insert_schedq_bounce(&self, key: SchedQBounceKey, bounce: SchedQBounceEntry) {
        if Utc::now() >= bounce.expires {
            // Skip already expired entry
            return;
        }

        tracing::debug!("new schedq bounce {key:?} = {bounce:?}");
        self.schedq_bounces.insert(key, bounce);
    }

    pub fn insert_readyq_suspension(&self, key: ActionHash, entry: ReadyQSuspensionEntry) {
        if Utc::now() >= entry.expires {
            // Skip already expired entry
            return;
        }

        tracing::debug!("new readyq suspension {key:?} = {entry:?}");
        self.readyq_suspensions.insert(key, entry);
    }

    pub fn insert_schedq_suspension(&self, key: SchedQSuspensionKey, entry: SchedQSuspensionEntry) {
        if Utc::now() >= entry.expires {
            // Skip already expired entry
            return;
        }

        tracing::debug!("new sched suspension {key:?} = {entry:?}");
        self.schedq_suspensions.insert(key, entry);
    }

    pub fn export_schedq_suspensions(&self) -> Vec<SchedQSuspension> {
        let mut entries = vec![];
        let now = Utc::now();
        for entry in self.schedq_suspensions.iter() {
            let value = entry.value();
            if now >= value.expires {
                continue;
            }
            let key = entry.key();
            entries.push(SchedQSuspension {
                rule_hash: key.action_hash.to_string(),
                domain: key.domain.clone(),
                campaign: key.campaign.clone(),
                tenant: key.tenant.clone(),
                reason: value.reason.clone(),
                expires: value.expires,
            });
        }

        entries.sort_by_key(|over| {
            (
                over.expires,
                over.tenant.clone(),
                over.domain.clone(),
                over.campaign.clone(),
            )
        });

        entries
    }

    pub fn export_readyq_suspensions(&self) -> Vec<ReadyQSuspension> {
        let mut entries = vec![];
        let now = Utc::now();
        for entry in self.readyq_suspensions.iter() {
            let value = entry.value();
            if now >= value.expires {
                continue;
            }
            let key = entry.key();
            entries.push(ReadyQSuspension {
                rule_hash: key.hash_portion(),
                site_name: key.site_name().to_string(),
                source: value.source.clone(),
                reason: value.reason.clone(),
                expires: value.expires,
            });
        }

        entries.sort_by_key(|over| (over.expires, over.source.clone()));

        entries
    }

    pub fn export_schedq_bounces(&self) -> Vec<SchedQBounce> {
        let mut entries = vec![];
        let now = Utc::now();
        for entry in self.schedq_bounces.iter() {
            let value = entry.value();
            if now >= value.expires {
                continue;
            }
            let key = entry.key();
            entries.push(SchedQBounce {
                rule_hash: key.action_hash.to_string(),
                domain: key.domain.clone(),
                tenant: key.tenant.clone(),
                campaign: key.campaign.clone(),
                reason: value.reason.clone(),
                expires: value.expires,
            });
        }

        entries.sort_by_key(|over| {
            (
                over.expires,
                over.tenant.clone(),
                over.domain.clone(),
                over.campaign.clone(),
            )
        });

        entries
    }

    pub fn export_config_override_toml(&self) -> String {
        use toml_edit::{value, Item};
        let mut doc = toml_edit::DocumentMut::new();
        let now = Utc::now();

        let mut entries = vec![];
        for entry in self.config_overrides.iter() {
            let over = entry.value();
            if now >= over.expires {
                continue;
            }
            entries.push(over.clone());
        }

        entries.sort_by_key(|over| {
            (
                over.expires,
                over.domain.clone(),
                over.source.clone(),
                over.option.name.clone(),
            )
        });
        let num_entries = entries.len();

        for over in entries {
            let domain_entry = doc
                .entry(&over.domain)
                .or_insert_with(|| {
                    let mut tbl = toml_edit::Table::new();
                    tbl["mx_rollup"] = value(over.mx_rollup);
                    Item::Table(tbl)
                })
                .as_table_mut()
                .unwrap();
            let sources = domain_entry
                .entry("sources")
                .or_insert_with(|| {
                    let tbl = toml_edit::Table::new();
                    Item::Table(tbl)
                })
                .as_table_mut()
                .unwrap();
            let source_entry = sources
                .entry(&over.source)
                .or_insert_with(|| {
                    let tbl = toml_edit::Table::new();
                    Item::Table(tbl)
                })
                .as_table_mut()
                .unwrap();

            let item = toml_to_toml_edit_value(over.option.value.clone());
            source_entry.insert(&over.option.name, Item::Value(item));

            if let Some(mut key) = source_entry.key_mut(&over.option.name) {
                key.leaf_decor_mut().set_prefix(format!(
                    "# reason: {}\n# expires: {}\n",
                    over.reason,
                    over.expires.to_rfc3339()
                ));
            }
        }

        let mut adaptive_entries = vec![];
        for entry in self.adaptive_overrides.iter() {
            let over = entry.value();
            if now >= over.expires {
                continue;
            }
            adaptive_entries.push(over.clone());
        }

        adaptive_entries.sort_by_key(|over| {
            (
                over.expires,
                over.domain.clone(),
                over.source.clone(),
                over.field_name.clone(),
            )
        });
        let num_adaptive_entries = adaptive_entries.len();

        for over in adaptive_entries {
            let domain_entry = doc
                .entry(&over.domain)
                .or_insert_with(|| {
                    let mut tbl = toml_edit::Table::new();
                    tbl["mx_rollup"] = value(over.mx_rollup);
                    Item::Table(tbl)
                })
                .as_table_mut()
                .unwrap();
            let sources = domain_entry
                .entry("sources")
                .or_insert_with(|| Item::Table(toml_edit::Table::new()))
                .as_table_mut()
                .unwrap();
            let source_entry = sources
                .entry(&over.source)
                .or_insert_with(|| Item::Table(toml_edit::Table::new()))
                .as_table_mut()
                .unwrap();

            let scaled_value = over.template.to_toml_value(over.current_limit);
            let item = toml_to_toml_edit_value(scaled_value);
            source_entry.insert(&over.field_name, Item::Value(item));

            if let Some(mut key) = source_entry.key_mut(&over.field_name) {
                // Guard against dividing by zero: an original_limit of 0
                // would otherwise produce NaN/-inf in the comment below.
                let percent_below = if over.original_limit > 0 {
                    format!(
                        "{:.1}% below original",
                        100.0 * (1.0 - (over.current_limit as f64 / over.original_limit as f64))
                    )
                } else {
                    "N/A".to_string()
                };
                let next_step_at =
                    over.last_activity + chrono::Duration::seconds(over.ramp_up_interval_secs);
                key.leaf_decor_mut().set_prefix(format!(
                    "# reason: {}\n# original: {}, {}\n\
                     # next step eligible at: {}\n",
                    over.reason,
                    over.original_limit,
                    percent_below,
                    next_step_at.to_rfc3339(),
                ));
            }
        }

        format!(
            "# Generated by tsa-daemon\n\
            # Number of entries: {num_entries} (config overrides), {num_adaptive_entries} (adaptive overrides)\n\n\
            {}\n\n\
            # Generated by tsa-daemon\n\
            # Number of entries: {num_entries} (config overrides), {num_adaptive_entries} (adaptive overrides)\n",
            doc
        )
    }

    /// Return a serializable version of the state
    fn serializable(&self) -> SerializableState {
        SerializableState {
            event_history: self
                .event_history
                .iter()
                .map(|entry| (entry.key().clone(), entry.value().clone()))
                .collect(),
            config_overrides: self
                .config_overrides
                .iter()
                .map(|entry| (entry.key().clone(), entry.value().clone()))
                .collect(),
            adaptive_overrides: self
                .adaptive_overrides
                .iter()
                .map(|entry| (entry.key().clone(), entry.value().clone()))
                .collect(),
            schedq_bounces: self
                .schedq_bounces
                .iter()
                .map(|entry| (entry.key().clone(), entry.value().clone()))
                .collect(),
            readyq_suspensions: self
                .readyq_suspensions
                .iter()
                .map(|entry| (entry.key().clone(), entry.value().clone()))
                .collect(),
            schedq_suspensions: self
                .schedq_suspensions
                .iter()
                .map(|entry| (entry.key().clone(), entry.value().clone()))
                .collect(),
        }
    }

    async fn prune(&self, verbose: bool) {
        let now = Utc::now();
        let now_ts = to_unix_ts(&now);
        self.prune_events(now_ts, verbose).await;
        self.prune_config_overrides(&now, verbose).await;
        self.prune_adaptive_overrides(&now, verbose).await;
        self.prune_readyq_suspensions(&now, verbose).await;
        self.prune_schedq_suspensions(&now, verbose).await;
        self.prune_schedq_bounces(&now, verbose).await;
    }

    async fn prune_schedq_bounces(&self, now: &DateTime<Utc>, verbose: bool) {
        let mut visited = 0;
        let start = Instant::now();

        let is_prunable = |entry: &SchedQBounceEntry| *now >= entry.expires;

        let keys_to_prune: Vec<SchedQBounceKey> = self
            .schedq_bounces
            .iter()
            .filter_map(|entry| {
                visited += 1;
                let over = entry.value();
                if is_prunable(over) {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();

        let mut num_pruned = 0;
        for key in keys_to_prune {
            let pruned = self
                .schedq_bounces
                .remove_if(&key, |_key, entry| is_prunable(entry))
                .is_some();
            if pruned {
                num_pruned += 1;
            }
        }
        if verbose && num_pruned > 0 {
            tracing::info!("Pruned {num_pruned} schedq_bounces");
        }
        tracing::debug!(
            "visited {visited} and pruned {num_pruned} \
            schedq_bounces in {:?}",
            start.elapsed()
        );
    }

    async fn prune_schedq_suspensions(&self, now: &DateTime<Utc>, verbose: bool) {
        let mut visited = 0;
        let start = Instant::now();

        let is_prunable = |entry: &SchedQSuspensionEntry| *now >= entry.expires;

        let keys_to_prune: Vec<SchedQSuspensionKey> = self
            .schedq_suspensions
            .iter()
            .filter_map(|entry| {
                visited += 1;
                let over = entry.value();
                if is_prunable(over) {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();

        let mut num_pruned = 0;
        for key in keys_to_prune {
            let pruned = self
                .schedq_suspensions
                .remove_if(&key, |_key, entry| is_prunable(entry))
                .is_some();
            if pruned {
                num_pruned += 1;
            }
        }
        if verbose && num_pruned > 0 {
            tracing::info!("Pruned {num_pruned} schedq_suspensions");
        }
        tracing::debug!(
            "visited {visited} and pruned {num_pruned} \
            scheq_suspensions in {:?}",
            start.elapsed()
        );
    }

    async fn prune_readyq_suspensions(&self, now: &DateTime<Utc>, verbose: bool) {
        let mut visited = 0;
        let start = Instant::now();

        let is_prunable = |entry: &ReadyQSuspensionEntry| *now >= entry.expires;

        let keys_to_prune: Vec<ActionHash> = self
            .readyq_suspensions
            .iter()
            .filter_map(|entry| {
                visited += 1;
                let over = entry.value();
                if is_prunable(over) {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();

        let mut num_pruned = 0;
        for key in keys_to_prune {
            let pruned = self
                .readyq_suspensions
                .remove_if(&key, |_key, entry| is_prunable(entry))
                .is_some();
            if pruned {
                num_pruned += 1;
            }
        }
        if verbose && num_pruned > 0 {
            tracing::info!("Pruned {num_pruned} readyq_suspensions");
        }
        tracing::debug!(
            "visited {visited} and pruned {num_pruned} \
            readyq_suspensions in {:?}",
            start.elapsed()
        );
    }

    async fn prune_config_overrides(&self, now: &DateTime<Utc>, verbose: bool) {
        let mut visited = 0;
        let start = Instant::now();

        let is_prunable = |over: &ConfigurationOverride| *now >= over.expires;

        let keys_to_prune: Vec<ActionHash> = self
            .config_overrides
            .iter()
            .filter_map(|entry| {
                visited += 1;
                let over = entry.value();
                if is_prunable(over) {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();

        let mut num_pruned = 0;
        for key in keys_to_prune {
            let pruned = self
                .config_overrides
                .remove_if(&key, |_key, over| is_prunable(over))
                .is_some();
            if pruned {
                num_pruned += 1;
            }
        }
        if verbose && num_pruned > 0 {
            tracing::info!("Pruned {num_pruned} config_overrides");
        }
        tracing::debug!(
            "visited {visited} and pruned {num_pruned} \
            config_overrides entries in {:?}",
            start.elapsed()
        );
    }

    async fn prune_adaptive_overrides(&self, now: &DateTime<Utc>, verbose: bool) {
        let mut visited = 0;
        let start = Instant::now();
        let now_ts = to_unix_ts(now);

        // Re-evaluated fresh at the moment of each DashMap call below (never
        // from a snapshot captured during the scan), so a concurrent
        // create_or_update_adaptive_override (the down-path) landing on the
        // same key between our scan and our mutate can't be clobbered by a
        // stale step or have its just-refreshed `expires` ignored.
        let is_removable = |over: &AdaptiveOverride| {
            if *now >= over.expires {
                return true;
            }
            if over.current_limit >= over.original_limit {
                return false;
            }
            let last_activity_ts = to_unix_ts(&over.last_activity);
            if now_ts - last_activity_ts < over.ramp_up_interval_secs {
                return false;
            }
            let increased = ((over.current_limit as f64) * (1.0 + over.ramp_step_percent / 100.0))
                .round()
                .max(1.0) as u64;
            // Guarantee monotonic upward progress: on small integer limits
            // (e.g. current_limit=3, ramp_step_percent=10 -> 3*1.10=3.3
            // rounds back down to 3), naive rounding can otherwise leave
            // the value unchanged forever, stalling the ramp-up and
            // leaking this entry (it never reaches original_limit, but
            // the tick still refreshes `expires` every time via the step
            // branch, so the safety-net expiry never fires either).
            let increased = increased.max(over.current_limit + 1);
            increased >= over.original_limit
        };

        let keys: Vec<ActionHash> = self
            .adaptive_overrides
            .iter()
            .map(|entry| {
                visited += 1;
                entry.key().clone()
            })
            .collect();

        let mut num_removed = 0;
        let mut num_stepped = 0;

        for key in keys {
            if self
                .adaptive_overrides
                .remove_if(&key, |_key, over| is_removable(over))
                .is_some()
            {
                num_removed += 1;
                continue;
            }

            // Not removed: re-fetch and recompute the step decision entirely
            // from live state (not the scan snapshot) before mutating.
            if let Some(mut entry) = self.adaptive_overrides.get_mut(&key) {
                if entry.current_limit >= entry.original_limit {
                    continue;
                }
                let last_activity_ts = to_unix_ts(&entry.last_activity);
                if now_ts - last_activity_ts < entry.ramp_up_interval_secs {
                    continue;
                }
                let increased = ((entry.current_limit as f64)
                    * (1.0 + entry.ramp_step_percent / 100.0))
                    .round()
                    .max(1.0) as u64;
                // Keep in lockstep with the identical guard in the
                // `is_removable` closure above: guarantee monotonic
                // upward progress even when naive rounding would
                // otherwise stall on small integer limits.
                let increased = increased.max(entry.current_limit + 1);
                if increased >= entry.original_limit {
                    // Extremely narrow window: became eligible for full
                    // recovery between the remove_if check above and this
                    // get_mut. Leave it for the next tick (60s later) rather
                    // than removing here without an atomic re-check.
                    continue;
                }
                let safety = entry.safety_duration_secs.max(0) as u64;
                entry.current_limit = increased;
                entry.last_activity = *now;
                entry.expires = *now + std::time::Duration::from_secs(safety);
                num_stepped += 1;
            }
        }

        if verbose && (num_removed > 0 || num_stepped > 0) {
            tracing::info!("Adaptive overrides: {num_stepped} stepped up, {num_removed} removed");
        }
        tracing::debug!(
            "visited {visited}, stepped {num_stepped}, removed {num_removed} \
            adaptive_overrides in {:?}",
            start.elapsed()
        );
    }

    async fn prune_events(&self, now_ts: UnixTimeStamp, verbose: bool) {
        let mut visited = 0;
        let start = Instant::now();

        let is_prunable = |event_data: &EventData| {
            event_data
                .series
                .last()
                .map(|&last_ts| {
                    let oldest_permitted = now_ts - event_data.duration - 300;
                    last_ts < oldest_permitted
                })
                .unwrap_or(true)
        };

        let keys_to_prune: Vec<MatchingScope> = self
            .event_history
            .iter()
            .filter_map(|entry| {
                visited += 1;
                let event_data = entry.value();
                if is_prunable(event_data) {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();

        let mut num_pruned = 0;
        for key in keys_to_prune {
            let pruned = self
                .event_history
                .remove_if(&key, |_key, event_data| is_prunable(event_data))
                .is_some();
            if pruned {
                num_pruned += 1;
            }
        }
        if verbose && num_pruned > 0 {
            tracing::info!("Pruned {num_pruned} event_history entries");
        }
        tracing::debug!(
            "visited {visited} and pruned {num_pruned} \
            event_history entries in {:?}",
            start.elapsed()
        );
    }
}

fn state_path() -> String {
    let path = DB_PATH.lock().clone();
    format!("{path}.state")
}

pub async fn load_state() -> anyhow::Result<()> {
    let path = state_path();
    let state = match tokio::fs::read(&path).await {
        Ok(data) => {
            let state = TsaState::default();
            match rmp_serde::from_slice::<SerializableState>(&data) {
                Ok(loaded) => {
                    for (key, value) in loaded.event_history.into_iter() {
                        state.event_history.insert(key, value);
                    }
                    for (key, value) in loaded.config_overrides.into_iter() {
                        state.config_overrides.insert(key, value);
                    }
                    for (key, value) in loaded.adaptive_overrides.into_iter() {
                        state.adaptive_overrides.insert(key, value);
                    }
                    for (key, value) in loaded.schedq_bounces.into_iter() {
                        state.schedq_bounces.insert(key, value);
                    }
                    for (key, value) in loaded.readyq_suspensions.into_iter() {
                        state.readyq_suspensions.insert(key, value);
                    }
                    for (key, value) in loaded.schedq_suspensions.into_iter() {
                        state.schedq_suspensions.insert(key, value);
                    }
                    state.prune(true).await;

                    tracing::info!(
                        "Loaded {} of state data from {path}",
                        humansize::format_size(data.len(), humansize::DECIMAL)
                    );
                }
                Err(err) => {
                    tracing::warn!(
                        "Failed to deserialize {path}: {err:#}, proceeding with fresh state"
                    );
                }
            }
            state
        }
        Err(err) => {
            tracing::warn!(
                "Failed to load state from {path}, proceeding with fresh state. Error was: {err:#}"
            );
            TsaState::default()
        }
    };

    let import_holder = Arc::new(state);

    let need_import = import_holder.config_overrides.is_empty()
        || import_holder.schedq_bounces.is_empty()
        || import_holder.schedq_suspensions.is_empty()
        || import_holder.readyq_suspensions.is_empty();

    if need_import {
        if let Ok(database) = open_history_db() {
            let mut num_config_overrides = 0;
            let mut num_schedq_bounces = 0;
            let mut num_schedq_suspensions = 0;
            let mut num_readyq_suspensions = 0;

            if import_holder.config_overrides.is_empty() {
                // Import configs from the sqlite database
                if let Err(err) = import_configs_from_sqlite(&database, import_holder.clone()).await
                {
                    tracing::warn!(
                        "Failed to import legacy config entries from sqlite: {err:#}. Proceeding without them");
                } else {
                    num_config_overrides += import_holder.config_overrides.len();
                }
            }

            if import_holder.schedq_bounces.is_empty() {
                if let Err(err) = import_bounces_from_sqlite(&database, import_holder.clone()).await
                {
                    tracing::warn!(
                        "Failed to import legacy bounce entries from sqlite: {err:#}. Proceeding without them");
                } else {
                    num_schedq_bounces += import_holder.schedq_bounces.len();
                }
            }

            if import_holder.schedq_suspensions.is_empty()
                && import_holder.readyq_suspensions.is_empty()
            {
                if let Err(err) =
                    import_suspensions_from_sqlite(&database, import_holder.clone()).await
                {
                    tracing::warn!(
                        "Failed to import legacy suspension entries from sqlite: {err:#}. Proceeding without them");
                } else {
                    num_readyq_suspensions += import_holder.readyq_suspensions.len();
                    num_schedq_suspensions += import_holder.schedq_suspensions.len();
                }
            }

            let did_import = num_config_overrides
                + num_schedq_bounces
                + num_schedq_suspensions
                + num_readyq_suspensions
                > 0;

            if did_import {
                tracing::info!(
                    "Imported {num_config_overrides} config overrides, \
                    {num_schedq_bounces} schedq bounces, \
                    {num_schedq_suspensions} schedq suspensions, \
                    {num_readyq_suspensions} readyq suspensions \
                    from sqlite"
                );
            }
        }
    }

    let state = Arc::into_inner(import_holder).expect("only we hold a ref");

    let num_config_overrides = state.config_overrides.len();
    let num_schedq_bounces = state.schedq_bounces.len();
    let num_schedq_suspensions = state.schedq_suspensions.len();
    let num_readyq_suspensions = state.readyq_suspensions.len();
    let num_events = state.event_history.len();

    tracing::info!(
        "State has {num_config_overrides} config overrides, \
        {num_schedq_bounces} schedq bounces, {num_schedq_suspensions} schedq suspensions, \
        {num_readyq_suspensions} readyq suspensions, {num_events} events."
    );

    TSA_STATE.set(state).ok();
    Ok(())
}

pub async fn save_state(background: bool) -> anyhow::Result<()> {
    let start = Instant::now();
    let state = TSA_STATE
        .get()
        .expect("state not initialized")
        .serializable();
    let extract = start.elapsed();

    let data = rmp_serde::to_vec_named(&state).context("failed to serialize state")?;
    let path = state_path();

    let start = Instant::now();
    tokio::fs::write(&path, &data)
        .await
        .with_context(|| format!("failed to write to {path}"))?;
    let write = start.elapsed();

    let num_config_overrides = state.config_overrides.len();
    let num_schedq_bounces = state.schedq_bounces.len();
    let num_schedq_suspensions = state.schedq_suspensions.len();
    let num_readyq_suspensions = state.readyq_suspensions.len();
    let num_events = state.event_history.len();

    let message = format!(
        "stored {} of data to {path}. State has {num_config_overrides} config overrides, \
        {num_schedq_bounces} schedq bounces, {num_schedq_suspensions} schedq suspensions, \
        {num_readyq_suspensions} readyq suspensions, {num_events} events. \
        (Extract took {extract:?}, write took {write:?})",
        humansize::format_size(data.len(), humansize::DECIMAL)
    );

    if background {
        tracing::debug!("{message}");
    } else {
        tracing::info!("{message}");
    }

    Ok(())
}

pub async fn state_pruner() -> anyhow::Result<()> {
    let mut last_save = Instant::now();

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        if let Some(state) = TSA_STATE.get() {
            state.prune(false).await;
        }

        if last_save.elapsed() > std::time::Duration::from_secs(300) {
            if let Err(err) = save_state(true).await {
                tracing::error!("{err:#} saving state file");
            }
            last_save = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kumo_api_types::shaping::{
        EgressPathConfigAdjustment, EgressPathConfigAdjustmentUnchecked,
    };
    use kumo_log_types::{JsonLogRecord, RecordType};
    use rfc5321::Response;
    use uuid::Uuid;

    fn adj(
        name: &str,
        decrease_percent: f64,
        floor_percent: f64,
        ramp_step_percent: f64,
    ) -> EgressPathConfigAdjustment {
        EgressPathConfigAdjustment::try_from(EgressPathConfigAdjustmentUnchecked {
            name: name.to_string(),
            decrease_percent,
            floor_percent,
            ramp_step_percent: Some(ramp_step_percent),
            ramp_up_interval: std::time::Duration::from_secs(900),
        })
        .unwrap()
    }

    fn make_record(timestamp: DateTime<Utc>) -> JsonLogRecord {
        JsonLogRecord {
            kind: RecordType::TransientFailure,
            id: String::new(),
            sender: String::new(),
            recipient: vec!["user@example.com".to_string()],
            queue: String::new(),
            site: "mx.example.com@smtp_client".to_string(),
            size: 0,
            response: Response {
                code: 421,
                command: None,
                enhanced_code: None,
                content: String::new(),
            },
            peer_address: None,
            timestamp,
            created: timestamp,
            num_attempts: 1,
            bounce_classification: Default::default(),
            egress_pool: None,
            egress_source: None,
            source_address: None,
            feedback_report: None,
            meta: Default::default(),
            headers: Default::default(),
            delivery_protocol: None,
            reception_protocol: None,
            nodeid: Uuid::default(),
            tls_cipher: None,
            tls_protocol_version: None,
            tls_peer_subject_name: None,
            provider_name: None,
            session_id: None,
        }
    }

    fn simple_rule() -> Rule {
        toml::from_str(
            r#"
            regex = ["^4\\.7\\.0"]
            trigger = "Immediate"
            duration = "30m"
            action = "Suspend"
            "#,
        )
        .unwrap()
    }

    #[test]
    fn test_parse_adaptive_field_value_rate() {
        let (limit, template) = parse_adaptive_field_value(
            "max_message_rate",
            &toml::Value::String("1000/s".to_string()),
        )
        .unwrap();
        assert_eq!(limit, 1000);
        assert_eq!(
            template,
            AdaptiveFieldTemplate::Rate {
                period: 1,
                max_burst: None,
                force_local: false
            }
        );
        assert_eq!(
            template.to_toml_value(900),
            toml::Value::String("900/s".to_string())
        );
    }

    #[test]
    fn test_parse_adaptive_field_value_limit() {
        let (limit, template) =
            parse_adaptive_field_value("connection_limit", &toml::Value::Integer(32)).unwrap();
        assert_eq!(limit, 32);
        assert_eq!(
            template,
            AdaptiveFieldTemplate::Limit { force_local: false }
        );
        assert_eq!(template.to_toml_value(28), toml::Value::Integer(28));
    }

    #[test]
    fn test_parse_adaptive_field_value_limit_force_local() {
        let (limit, template) = parse_adaptive_field_value(
            "connection_limit",
            &toml::Value::String("local:32".to_string()),
        )
        .unwrap();
        assert_eq!(limit, 32);
        assert_eq!(template, AdaptiveFieldTemplate::Limit { force_local: true });
        assert_eq!(
            template.to_toml_value(28),
            toml::Value::String("local:28".to_string())
        );
    }

    #[test]
    fn test_parse_adaptive_field_value_rejects_unsupported_field() {
        let err =
            parse_adaptive_field_value("enable_tls", &toml::Value::Boolean(true)).unwrap_err();
        assert!(err.to_string().contains("unsupported"), "{err}");
    }

    #[test]
    fn test_down_path_compounds_and_clamps_to_floor() {
        let state = TsaState::default();
        let scope = ActionHash::from_rule_and_record(
            &simple_rule(),
            &Action::AdjustConfig(adj("max_message_rate", 10.0, 25.0, 10.0)),
            &make_record(Utc::now()),
        );
        let rule = simple_rule();
        let a = adj("max_message_rate", 10.0, 25.0, 10.0);
        let original = toml::Value::String("1000/s".to_string());

        // First trigger: 1000 -> 900
        let record = make_record(Utc::now());
        state
            .create_or_update_adaptive_override(
                &scope,
                &rule,
                &record,
                &a,
                "example.com",
                "unspecified",
                PreferRollup::Yes,
                &original,
            )
            .unwrap();
        assert_eq!(
            state.adaptive_overrides.get(&scope).unwrap().current_limit,
            900
        );

        // Second trigger: 900 -> 810
        let record = make_record(Utc::now());
        state
            .create_or_update_adaptive_override(
                &scope,
                &rule,
                &record,
                &a,
                "example.com",
                "unspecified",
                PreferRollup::Yes,
                &original,
            )
            .unwrap();
        assert_eq!(
            state.adaptive_overrides.get(&scope).unwrap().current_limit,
            810
        );

        // Floor is 25% of 1000 = 250. Trigger repeatedly until it clamps.
        for _ in 0..20 {
            let record = make_record(Utc::now());
            state
                .create_or_update_adaptive_override(
                    &scope,
                    &rule,
                    &record,
                    &a,
                    "example.com",
                    "unspecified",
                    PreferRollup::Yes,
                    &original,
                )
                .unwrap();
        }
        assert_eq!(
            state.adaptive_overrides.get(&scope).unwrap().current_limit,
            250
        );
    }

    #[tokio::test]
    async fn test_up_path_steps_and_resets_last_activity() {
        let state = TsaState::default();
        let record = make_record(Utc::now());
        let rule = simple_rule();
        let a = adj("connection_limit", 20.0, 25.0, 10.0);
        let original = toml::Value::Integer(100);
        let scope =
            ActionHash::from_rule_and_record(&rule, &Action::AdjustConfig(a.clone()), &record);

        state
            .create_or_update_adaptive_override(
                &scope,
                &rule,
                &record,
                &a,
                "example.com",
                "unspecified",
                PreferRollup::Yes,
                &original,
            )
            .unwrap();
        assert_eq!(
            state.adaptive_overrides.get(&scope).unwrap().current_limit,
            80
        );

        // Not enough time has passed yet: no step.
        let soon = Utc::now();
        state.prune_adaptive_overrides(&soon, false).await;
        assert_eq!(
            state.adaptive_overrides.get(&scope).unwrap().current_limit,
            80
        );

        // Simulate the ramp_up_interval (900s) having elapsed by directly
        // rewinding last_activity, exactly as a real 15-minute quiet period would.
        {
            let mut entry = state.adaptive_overrides.get_mut(&scope).unwrap();
            entry.last_activity = Utc::now() - chrono::Duration::seconds(1000);
        }
        let now = Utc::now();
        state.prune_adaptive_overrides(&now, false).await;
        // 80 * 1.10 = 88
        assert_eq!(
            state.adaptive_overrides.get(&scope).unwrap().current_limit,
            88
        );
        // last_activity was reset by the step, so a second immediate call does nothing yet.
        state.prune_adaptive_overrides(&now, false).await;
        assert_eq!(
            state.adaptive_overrides.get(&scope).unwrap().current_limit,
            88
        );
    }

    /// Regression test for a stall bug on small integer limits: with
    /// original_limit=10, floor_percent=25 (floor=3) and
    /// ramp_step_percent=10, naive rounding of `3 * 1.10 = 3.3` rounds
    /// back down to 3, so the ramp-up step made no progress and the
    /// entry never reached original_limit -- nor got pruned by the
    /// safety-net expiry, since the step branch kept refreshing
    /// `expires` on every tick even though nothing actually changed. The
    /// fix forces each step to be strictly greater than the prior
    /// current_limit, guaranteeing forward progress every tick.
    #[tokio::test]
    async fn test_up_path_progresses_on_small_integer_limits() {
        let state = TsaState::default();
        let record = make_record(Utc::now());
        let rule = simple_rule();
        // decrease_percent=100 so a single down-step trigger drives
        // current_limit straight to the floor.
        let a = adj("connection_limit", 100.0, 25.0, 10.0);
        let original = toml::Value::Integer(10);
        let scope =
            ActionHash::from_rule_and_record(&rule, &Action::AdjustConfig(a.clone()), &record);

        state
            .create_or_update_adaptive_override(
                &scope,
                &rule,
                &record,
                &a,
                "example.com",
                "unspecified",
                PreferRollup::Yes,
                &original,
            )
            .unwrap();
        // floor = round(10 * 0.25) = 3
        assert_eq!(
            state.adaptive_overrides.get(&scope).unwrap().current_limit,
            3
        );

        let mut last_seen = 3u64;
        for _ in 0..40 {
            if state.adaptive_overrides.get(&scope).is_none() {
                break;
            }
            {
                let mut entry = state.adaptive_overrides.get_mut(&scope).unwrap();
                entry.last_activity = Utc::now() - chrono::Duration::seconds(1000);
            }
            let now = Utc::now();
            state.prune_adaptive_overrides(&now, false).await;

            if let Some(entry) = state.adaptive_overrides.get(&scope) {
                assert!(
                    entry.current_limit > last_seen,
                    "ramp-up stalled at {last_seen}: made no progress on this tick"
                );
                last_seen = entry.current_limit;
            }
        }

        assert!(
            state.adaptive_overrides.get(&scope).is_none(),
            "entry should have fully recovered to original_limit and been removed, \
             but is stuck at current_limit={last_seen}"
        );
    }

    #[tokio::test]
    async fn test_up_path_removes_entry_on_full_recovery() {
        let state = TsaState::default();
        let record = make_record(Utc::now());
        let rule = simple_rule();
        let a = adj("connection_limit", 20.0, 25.0, 50.0);
        let original = toml::Value::Integer(100);
        let scope =
            ActionHash::from_rule_and_record(&rule, &Action::AdjustConfig(a.clone()), &record);

        state
            .create_or_update_adaptive_override(
                &scope,
                &rule,
                &record,
                &a,
                "example.com",
                "unspecified",
                PreferRollup::Yes,
                &original,
            )
            .unwrap();
        assert_eq!(
            state.adaptive_overrides.get(&scope).unwrap().current_limit,
            80
        );

        {
            let mut entry = state.adaptive_overrides.get_mut(&scope).unwrap();
            entry.last_activity = Utc::now() - chrono::Duration::seconds(1000);
        }
        // 80 * 1.5 = 120 >= original (100) -> fully recovered, entry removed.
        let now = Utc::now();
        state.prune_adaptive_overrides(&now, false).await;
        assert!(state.adaptive_overrides.get(&scope).is_none());
    }

    #[tokio::test]
    async fn test_up_path_safety_expiry_removes_stuck_entry() {
        let state = TsaState::default();
        let record = make_record(Utc::now());
        let rule = simple_rule(); // duration = 30m
        let a = adj("connection_limit", 20.0, 25.0, 10.0);
        let original = toml::Value::Integer(100);
        let scope =
            ActionHash::from_rule_and_record(&rule, &Action::AdjustConfig(a.clone()), &record);

        state
            .create_or_update_adaptive_override(
                &scope,
                &rule,
                &record,
                &a,
                "example.com",
                "unspecified",
                PreferRollup::Yes,
                &original,
            )
            .unwrap();

        let far_future = Utc::now() + chrono::Duration::hours(1);
        state.prune_adaptive_overrides(&far_future, false).await;
        assert!(state.adaptive_overrides.get(&scope).is_none());
    }

    #[test]
    fn test_export_includes_adaptive_overrides() {
        let state = TsaState::default();
        let record = make_record(Utc::now());
        let rule = simple_rule();
        let a = adj("connection_limit", 20.0, 25.0, 10.0);
        let original = toml::Value::Integer(100);
        let scope = ActionHash::from_rule_and_record(
            &rule,
            &Action::AdjustConfig(a.clone()),
            &record,
        );

        state
            .create_or_update_adaptive_override(
                &scope, &rule, &record, &a, "example.com", "unspecified", PreferRollup::Yes, &original,
            )
            .unwrap();

        let toml_text = state.export_config_override_toml();
        assert!(toml_text.contains("connection_limit = 80"), "{toml_text}");
        assert!(toml_text.contains("example.com"), "{toml_text}");
    }
}
