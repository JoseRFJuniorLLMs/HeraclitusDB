//! Deterministic behavioural baselines for Sentinel Fase 2.
//!
//! This module intentionally has no dependency on a vector index or on the
//! runtime worker.  It provides bounded, replayable statistics plus a small
//! canonical L2 adapter fed by [`SecurityEvent`](crate::SecurityEvent) values.
//! A new entity starts in a shadow profile; suspicious observations
//! never mutate an active baseline unless an explicit trusted-feedback call is
//! made.

use crate::event::{EntityRef, Outcome, SecurityEvent};
use heraclitus_core::Lsn;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use thiserror::Error;

const MAX_FEATURES_PER_OBSERVATION: usize = 256;
const MAX_FEATURE_ID_LEN: usize = 128;

/// Stable name for one scalar behavioural feature.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FeatureId(String);

impl FeatureId {
    pub fn new(value: impl Into<String>) -> Result<Self, BehaviorError> {
        let value = value.into();
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(BehaviorError::InvalidFeatureId(
                "feature id não pode ser vazio".into(),
            ));
        }
        if trimmed.len() > MAX_FEATURE_ID_LEN {
            return Err(BehaviorError::InvalidFeatureId(format!(
                "feature id excede {MAX_FEATURE_ID_LEN} bytes"
            )));
        }
        if trimmed.chars().any(|character| character.is_control()) {
            return Err(BehaviorError::InvalidFeatureId(
                "feature id não pode conter caracteres de controle".into(),
            ));
        }
        Ok(Self(trimmed.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FeatureId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl TryFrom<&str> for FeatureId {
    type Error = BehaviorError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// One finite scalar observation.  The alias keeps the public API compact and
/// leaves room for a richer value type in a future L2 revision.
pub type FeatureValue = f64;

/// Exponential moving average with a fixed, validated decay parameter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EwmaState {
    pub value: f64,
    pub alpha: f64,
    pub observations: u64,
    pub last_update_lsn: Lsn,
}

impl EwmaState {
    pub fn new(alpha: f64) -> Result<Self, BehaviorError> {
        validate_unit_interval("decay", alpha)?;
        Ok(Self {
            value: 0.0,
            alpha,
            observations: 0,
            last_update_lsn: 0,
        })
    }

    pub fn update(&mut self, lsn: Lsn, sample: f64) -> Result<(), BehaviorError> {
        self.update_weighted(lsn, sample, 1.0)
    }

    /// Update with a trusted-feedback weight.  A weight below one reduces the
    /// EWMA's influence without allowing a non-finite value through.
    pub fn update_weighted(
        &mut self,
        lsn: Lsn,
        sample: f64,
        weight: f64,
    ) -> Result<(), BehaviorError> {
        validate_sample(sample)?;
        validate_weight(weight)?;
        if self.observations == 0 {
            self.value = sample;
        } else {
            let effective_alpha = (self.alpha * weight).clamp(f64::MIN_POSITIVE, 1.0);
            self.value += effective_alpha * (sample - self.value);
        }
        self.observations = self.observations.saturating_add(1);
        self.last_update_lsn = lsn;
        Ok(())
    }
}

/// Welford's online mean/variance state.  `weight_sum` permits explicit
/// trusted feedback to have a smaller influence while `count` remains the
/// number of source observations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MomentState {
    pub count: u64,
    pub weight_sum: f64,
    pub mean: f64,
    pub m2: f64,
    pub last_update_lsn: Lsn,
}

impl Default for MomentState {
    fn default() -> Self {
        Self {
            count: 0,
            weight_sum: 0.0,
            mean: 0.0,
            m2: 0.0,
            last_update_lsn: 0,
        }
    }
}

impl MomentState {
    pub fn update(&mut self, lsn: Lsn, sample: f64) -> Result<(), BehaviorError> {
        self.update_weighted(lsn, sample, 1.0)
    }

    pub fn update_weighted(
        &mut self,
        lsn: Lsn,
        sample: f64,
        weight: f64,
    ) -> Result<(), BehaviorError> {
        validate_sample(sample)?;
        validate_weight(weight)?;
        if self.weight_sum == 0.0 {
            self.mean = sample;
            self.weight_sum = weight;
        } else {
            let new_weight_sum = self.weight_sum + weight;
            let delta = sample - self.mean;
            self.mean += (weight / new_weight_sum) * delta;
            self.m2 += weight * delta * (sample - self.mean);
            self.weight_sum = new_weight_sum;
        }
        self.count = self.count.saturating_add(1);
        self.last_update_lsn = lsn;
        Ok(())
    }

    pub fn variance(&self) -> Option<f64> {
        (self.weight_sum > 1.0).then(|| (self.m2 / (self.weight_sum - 1.0)).max(0.0))
    }

    pub fn stddev(&self) -> Option<f64> {
        self.variance().map(f64::sqrt)
    }

    /// Desvio absoluto em unidades de desvio-padrao.
    ///
    /// Auditoria 2026-09-05, A29: numa baseline sem dispersao alguma
    /// (`stddev == 0`) qualquer amostra diferente da media devolve
    /// `f64::INFINITY` de proposito — o desvio nao e exprimivel na escala do
    /// perfil.  Quem pontua TEM de limitar esse valor (ver `score_profile`);
    /// propaga-lo sem tecto satura a severidade a jusante.
    pub fn z_score(&self, sample: f64) -> Option<f64> {
        if !sample.is_finite() {
            return None;
        }
        let stddev = self.stddev()?;
        if stddev <= f64::EPSILON {
            return Some(if (sample - self.mean).abs() <= f64::EPSILON {
                0.0
            } else {
                f64::INFINITY
            });
        }
        Some((sample - self.mean).abs() / stddev)
    }
}

/// Bounded deterministic quantile sketch implemented as a deterministic
/// reservoir.  Replay of the same sequence produces the same checkpoint,
/// while memory remains bounded and samples stay representative of the stream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuantileState {
    pub samples: Vec<f64>,
    pub capacity: usize,
    pub observations: u64,
    pub last_update_lsn: Lsn,
}

impl QuantileState {
    pub fn new(capacity: usize) -> Result<Self, BehaviorError> {
        if !(2..=4096).contains(&capacity) {
            return Err(BehaviorError::InvalidPolicy(
                "quantile_capacity deve estar entre 2 e 4096".into(),
            ));
        }
        Ok(Self {
            samples: Vec::new(),
            capacity,
            observations: 0,
            last_update_lsn: 0,
        })
    }

    pub fn update(&mut self, lsn: Lsn, sample: f64) -> Result<(), BehaviorError> {
        validate_sample(sample)?;
        let next_observation = self.observations.saturating_add(1);
        if self.samples.len() < self.capacity {
            self.samples.push(sample);
        } else {
            // A pseudo-random, but deterministic, reservoir replacement keeps
            // the sketch representative without using a process-global RNG.
            let candidate = splitmix64(next_observation) % next_observation;
            if candidate < self.capacity as u64 {
                self.samples[candidate as usize] = sample;
            }
        }
        self.samples.sort_by(f64::total_cmp);
        self.observations = next_observation;
        self.last_update_lsn = lsn;
        Ok(())
    }

    pub fn quantile(&self, fraction: f64) -> Option<f64> {
        if self.samples.is_empty() || !fraction.is_finite() || !(0.0..=1.0).contains(&fraction) {
            return None;
        }
        let rank = (fraction * self.samples.len() as f64).ceil().max(1.0) as usize;
        self.samples.get(rank.saturating_sub(1)).copied()
    }
}

/// Whether a profile is still learning, trusted for scoring, or quarantined
/// after an outlier/suspicious observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileTrustState {
    Shadow,
    Trusted,
    Quarantined,
}

/// Incremental profile required by SPEC-0045 §19.  The maps are ordered to
/// make snapshots and replay byte-for-byte stable for the same observations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BehavioralProfile {
    pub entity: EntityRef,
    pub profile_version: u32,
    pub observation_count: u64,
    pub ewma: BTreeMap<FeatureId, EwmaState>,
    pub moments: BTreeMap<FeatureId, MomentState>,
    pub quantiles: BTreeMap<FeatureId, QuantileState>,
    pub last_update_lsn: Lsn,
    pub trust_state: ProfileTrustState,
}

impl BehavioralProfile {
    pub fn new(entity: EntityRef, trust_state: ProfileTrustState) -> Self {
        Self {
            entity,
            profile_version: 1,
            observation_count: 0,
            ewma: BTreeMap::new(),
            moments: BTreeMap::new(),
            quantiles: BTreeMap::new(),
            last_update_lsn: 0,
            trust_state,
        }
    }

    pub fn update(
        &mut self,
        lsn: Lsn,
        features: &BTreeMap<FeatureId, FeatureValue>,
        policy: &BaselinePolicy,
        weight: f64,
    ) -> Result<(), BehaviorError> {
        if features.is_empty() {
            return Err(BehaviorError::EmptyFeatures);
        }
        for (feature, value) in features {
            self.ewma
                .entry(feature.clone())
                .or_insert(EwmaState::new(policy.decay)?)
                .update_weighted(lsn, *value, weight)?;
            self.moments
                .entry(feature.clone())
                .or_default()
                .update_weighted(lsn, *value, weight)?;
            // Quantiles are an unweighted reservoir.  Do not let a reduced
            // trusted-feedback sample enter it at full influence; EWMA and
            // Welford still receive the policy weight above.
            if weight >= 1.0 {
                self.quantiles
                    .entry(feature.clone())
                    .or_insert(QuantileState::new(policy.quantile_capacity)?)
                    .update(lsn, *value)?;
            }
        }
        self.observation_count = self.observation_count.saturating_add(1);
        self.last_update_lsn = lsn;
        Ok(())
    }
}

/// Poisoning-resistant baseline controls.  Defaults are conservative and
/// leave the engine in shadow-only mode until an operator explicitly opts in.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct BaselinePolicy {
    pub minimum_support: u64,
    pub learning_delay_events: u64,
    pub quarantine_period: u64,
    pub decay: f64,
    pub max_update_rate: u64,
    pub outlier_exclusion: bool,
    pub trusted_feedback_weight: f64,
    pub outlier_z: f64,
    pub quantile_capacity: usize,
    pub rate_window_lsns: u64,
    pub shadow_only: bool,
}

impl Default for BaselinePolicy {
    fn default() -> Self {
        Self {
            minimum_support: 20,
            learning_delay_events: 10,
            quarantine_period: 5,
            decay: 0.1,
            max_update_rate: 100,
            outlier_exclusion: true,
            trusted_feedback_weight: 0.25,
            outlier_z: 4.0,
            quantile_capacity: 128,
            rate_window_lsns: 1_024,
            shadow_only: true,
        }
    }
}

impl BaselinePolicy {
    pub fn validate(&self) -> Result<(), BehaviorError> {
        if self.minimum_support == 0 {
            return Err(BehaviorError::InvalidPolicy(
                "minimum_support deve ser maior que zero".into(),
            ));
        }
        if self.learning_delay_events == 0 {
            return Err(BehaviorError::InvalidPolicy(
                "learning_delay_events deve ser maior que zero".into(),
            ));
        }
        if self.quarantine_period == 0 {
            return Err(BehaviorError::InvalidPolicy(
                "quarantine_period deve ser maior que zero".into(),
            ));
        }
        validate_unit_interval("decay", self.decay)?;
        if self.max_update_rate == 0 || self.rate_window_lsns == 0 {
            return Err(BehaviorError::InvalidPolicy(
                "max_update_rate e rate_window_lsns devem ser maiores que zero".into(),
            ));
        }
        validate_feedback_weight(self.trusted_feedback_weight)?;
        if !self.outlier_z.is_finite() || self.outlier_z <= 0.0 {
            return Err(BehaviorError::InvalidPolicy(
                "outlier_z deve ser finito e maior que zero".into(),
            ));
        }
        if !(2..=4096).contains(&self.quantile_capacity) {
            return Err(BehaviorError::InvalidPolicy(
                "quantile_capacity deve estar entre 2 e 4096".into(),
            ));
        }
        Ok(())
    }
}

/// Per-feature and aggregate score before an observation is applied.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct BehavioralScore {
    pub score: f64,
    pub anomalous: bool,
    pub support: u64,
    pub feature_scores: BTreeMap<FeatureId, f64>,
}

/// Outcome of an observation, including the explicit reason an update was or
/// was not incorporated into an active baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationDisposition {
    Warmup,
    Updated,
    Promoted,
    Suspicious,
    TrustedFeedback,
    OutlierExcluded,
    Quarantined,
    RateLimited,
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BehavioralObservation {
    pub entity: EntityRef,
    pub lsn: Lsn,
    pub score: BehavioralScore,
    pub disposition: ObservationDisposition,
    pub active_trust_state: Option<ProfileTrustState>,
    pub shadow_support: u64,
}

/// One deterministic entity/feature projection from a canonical event.  The
/// adapter deliberately exposes only bounded scalar features; raw strings and
/// free-form payloads never become model dimensions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BehavioralInput {
    pub entity: EntityRef,
    pub features: BTreeMap<FeatureId, FeatureValue>,
    pub suspicious: bool,
}

/// Project a canonical event into one observation per distinct entity.  Every
/// observation carries the same fixed feature schema so a missing port/byte
/// value is represented by zero instead of silently changing the model shape.
pub fn security_event_inputs(
    event: &SecurityEvent,
    suspicious_severity: u8,
) -> Result<Vec<BehavioralInput>, BehaviorError> {
    let mut entities = BTreeMap::new();
    for entity in [
        event.principal.clone(),
        event.user.clone(),
        event.host.clone(),
        event.process.clone(),
        endpoint_entity(event.src.as_ref()),
        endpoint_entity(event.dst.as_ref()),
        attribute_entity(event, "session"),
        attribute_entity(event, "resource"),
    ]
    .into_iter()
    .flatten()
    {
        if !entity.kind.trim().is_empty() && !entity.id.trim().is_empty() {
            entities.insert(entity_key(&entity), entity);
        }
    }

    let failure = matches!(event.outcome, Outcome::Failure | Outcome::Error);
    let blocked = matches!(event.outcome, Outcome::Blocked);
    let bytes = [
        "bytes",
        "bytes_transferred",
        "network.bytes",
        "event.bytes",
        "event.bytes_transferred",
        "event.network.bytes",
    ]
    .iter()
    .find_map(|key| event.attributes.get(*key))
    .and_then(|value| value.parse::<f64>().ok())
    .filter(|value| value.is_finite() && *value >= 0.0)
    .unwrap_or(0.0);
    let hour = if event.observed_at == 0 {
        0.0
    } else {
        ((event.observed_at / 3_600_000) % 24) as f64
    };
    let pairs = [
        ("event.severity", f64::from(event.severity)),
        ("event.failure", if failure { 1.0 } else { 0.0 }),
        ("event.blocked", if blocked { 1.0 } else { 0.0 }),
        (
            "network.src_port",
            event
                .src
                .as_ref()
                .and_then(|value| value.port)
                .map_or(0.0, f64::from),
        ),
        (
            "network.dst_port",
            event
                .dst
                .as_ref()
                .and_then(|value| value.port)
                .map_or(0.0, f64::from),
        ),
        ("event.bytes", bytes),
        ("event.observed_hour", hour),
    ];
    let mut features = BTreeMap::new();
    for (name, value) in pairs {
        features.insert(FeatureId::new(name)?, value);
    }
    let suspicious =
        event.severity >= suspicious_severity || blocked || matches!(event.outcome, Outcome::Error);
    Ok(entities
        .into_values()
        .map(|entity| BehavioralInput {
            entity,
            features: features.clone(),
            suspicious,
        })
        .collect())
}

#[derive(Debug, Error, Clone, PartialEq)]
pub enum BehaviorError {
    #[error("política comportamental inválida: {0}")]
    InvalidPolicy(String),
    #[error("feature id inválido: {0}")]
    InvalidFeatureId(String),
    #[error("feature value deve ser finito")]
    NonFiniteValue,
    #[error("peso de confiança deve estar entre 0 e 1")]
    InvalidWeight,
    #[error("observação sem features")]
    EmptyFeatures,
    #[error("observação para {entity} voltou de LSN {last} para {current}")]
    OutOfOrder {
        entity: String,
        last: Lsn,
        current: Lsn,
    },
    #[error("snapshot comportamental inválido: {0}")]
    InvalidSnapshot(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct RateState {
    window_start_lsn: Lsn,
    updates: u64,
}

/// Serializable engine state, suitable for a cursor/checkpoint owned by a
/// future runtime adapter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BehavioralSnapshot {
    pub policy: BaselinePolicy,
    pub profiles: BTreeMap<String, BehavioralProfile>,
    pub shadow_profiles: BTreeMap<String, BehavioralProfile>,
    shadow_started_lsn: BTreeMap<String, Lsn>,
    last_seen_lsn: BTreeMap<String, Lsn>,
    rate: BTreeMap<String, RateState>,
    quarantine_remaining: BTreeMap<String, u64>,
}

/// In-memory L2 baseline engine. It is deterministic and bounded by policy;
/// the Sentinel runtime uses it only when the opt-in L2 configuration is enabled.
#[derive(Debug, Clone, PartialEq)]
pub struct BehavioralEngine {
    policy: BaselinePolicy,
    profiles: BTreeMap<String, BehavioralProfile>,
    shadow_profiles: BTreeMap<String, BehavioralProfile>,
    shadow_started_lsn: BTreeMap<String, Lsn>,
    last_seen_lsn: BTreeMap<String, Lsn>,
    rate: BTreeMap<String, RateState>,
    quarantine_remaining: BTreeMap<String, u64>,
}

impl BehavioralEngine {
    pub fn new(policy: BaselinePolicy) -> Result<Self, BehaviorError> {
        policy.validate()?;
        Ok(Self {
            policy,
            profiles: BTreeMap::new(),
            shadow_profiles: BTreeMap::new(),
            shadow_started_lsn: BTreeMap::new(),
            last_seen_lsn: BTreeMap::new(),
            rate: BTreeMap::new(),
            quarantine_remaining: BTreeMap::new(),
        })
    }

    pub fn policy(&self) -> &BaselinePolicy {
        &self.policy
    }

    pub fn profile(&self, entity: &EntityRef) -> Option<&BehavioralProfile> {
        self.profiles.get(&entity_key(entity))
    }

    pub fn shadow_profile(&self, entity: &EntityRef) -> Option<&BehavioralProfile> {
        self.shadow_profiles.get(&entity_key(entity))
    }

    pub fn score(
        &self,
        entity: &EntityRef,
        features: &BTreeMap<FeatureId, FeatureValue>,
    ) -> BehavioralScore {
        self.profiles
            .get(&entity_key(entity))
            .map(|profile| score_profile(profile, features, &self.policy))
            .unwrap_or_default()
    }

    /// Observe untrusted data.  Suspicious events are scored but never mutate
    /// a baseline.
    pub fn observe(
        &mut self,
        lsn: Lsn,
        entity: EntityRef,
        features: BTreeMap<FeatureId, FeatureValue>,
        suspicious: bool,
    ) -> Result<BehavioralObservation, BehaviorError> {
        self.observe_internal(lsn, entity, features, suspicious, false)
    }

    /// Apply an explicitly trusted feedback observation with the policy's
    /// reduced influence.  This is the only path that can incorporate a
    /// suspicious event.
    pub fn observe_trusted_feedback(
        &mut self,
        lsn: Lsn,
        entity: EntityRef,
        features: BTreeMap<FeatureId, FeatureValue>,
        suspicious: bool,
    ) -> Result<BehavioralObservation, BehaviorError> {
        self.observe_internal(lsn, entity, features, suspicious, true)
    }

    pub fn snapshot(&self) -> BehavioralSnapshot {
        BehavioralSnapshot {
            policy: self.policy.clone(),
            profiles: self.profiles.clone(),
            shadow_profiles: self.shadow_profiles.clone(),
            shadow_started_lsn: self.shadow_started_lsn.clone(),
            last_seen_lsn: self.last_seen_lsn.clone(),
            rate: self.rate.clone(),
            quarantine_remaining: self.quarantine_remaining.clone(),
        }
    }

    pub fn from_snapshot(snapshot: BehavioralSnapshot) -> Result<Self, BehaviorError> {
        snapshot.policy.validate()?;
        for (key, profile) in snapshot
            .profiles
            .iter()
            .chain(snapshot.shadow_profiles.iter())
        {
            if *key != entity_key(&profile.entity) {
                return Err(BehaviorError::InvalidSnapshot(format!(
                    "chave de entidade divergente para {key}"
                )));
            }
            validate_profile(profile)?;
        }
        Ok(Self {
            policy: snapshot.policy,
            profiles: snapshot.profiles,
            shadow_profiles: snapshot.shadow_profiles,
            shadow_started_lsn: snapshot.shadow_started_lsn,
            last_seen_lsn: snapshot.last_seen_lsn,
            rate: snapshot.rate,
            quarantine_remaining: snapshot.quarantine_remaining,
        })
    }

    /// Auditoria 2026-09-05, A20 — um motor com SÓ as entidades pedidas.
    ///
    /// `evaluate_l2` trabalha sobre uma cópia para que os sinais duráveis saiam
    /// antes de o estado vivo avançar. A atomicidade que isso exige é POR
    /// ENTIDADE, não global: os seis mapas são todos indexados por
    /// `entity_key`, `policy` é imutável, e nada em `observe_internal` liga
    /// entidades distintas — `score`, `allow_rate` e `result` lêem só a chave
    /// que estão a tratar. Um evento toca no máximo oito entidades
    /// (`security_event_inputs`), mas o `clone()` do motor inteiro copiava um
    /// perfil por entidade JÁ VISTA, e não há evicção de perfis: o custo crescia
    /// sem tecto com a cardinalidade do tráfego.
    pub(crate) fn extrair_entidades(&self, chaves: &BTreeSet<String>) -> Self {
        Self {
            policy: self.policy.clone(),
            profiles: recortar(&self.profiles, chaves),
            shadow_profiles: recortar(&self.shadow_profiles, chaves),
            shadow_started_lsn: recortar(&self.shadow_started_lsn, chaves),
            last_seen_lsn: recortar(&self.last_seen_lsn, chaves),
            rate: recortar(&self.rate, chaves),
            quarantine_remaining: recortar(&self.quarantine_remaining, chaves),
        }
    }

    /// Auditoria 2026-09-05, A20 — escreve de volta as entidades trabalhadas.
    ///
    /// Só as `chaves` são tocadas; tudo o resto do motor vivo fica como estava.
    /// O ramo de REMOÇÃO não é opcional: `observe_internal` apaga de
    /// `shadow_profiles`/`shadow_started_lsn` quando promove um perfil, e de
    /// `quarantine_remaining` quando a quarentena acaba. Uma fusão só de
    /// inserção deixava perfis fantasma em shadow e quarentenas eternas — a
    /// baseline corrompia-se em silêncio e os scores mudavam.
    pub(crate) fn fundir_entidades(&mut self, chaves: &BTreeSet<String>, parcial: Self) {
        let mut parcial = parcial;
        fundir(&mut self.profiles, chaves, &mut parcial.profiles);
        fundir(
            &mut self.shadow_profiles,
            chaves,
            &mut parcial.shadow_profiles,
        );
        fundir(
            &mut self.shadow_started_lsn,
            chaves,
            &mut parcial.shadow_started_lsn,
        );
        fundir(&mut self.last_seen_lsn, chaves, &mut parcial.last_seen_lsn);
        fundir(&mut self.rate, chaves, &mut parcial.rate);
        fundir(
            &mut self.quarantine_remaining,
            chaves,
            &mut parcial.quarantine_remaining,
        );
    }

    /// Auditoria 2026-09-05, A20 — quantos perfis este motor carrega.
    ///
    /// É a medida do que uma cópia custa. Serve `l2_profiles_copied_total`:
    /// sem um número, a diferença entre copiar oito entidades e copiar a base
    /// inteira não aparece em lado nenhum senão no relógio.
    pub(crate) fn numero_de_perfis(&self) -> usize {
        self.profiles.len() + self.shadow_profiles.len()
    }

    fn observe_internal(
        &mut self,
        lsn: Lsn,
        entity: EntityRef,
        features: BTreeMap<FeatureId, FeatureValue>,
        suspicious: bool,
        trusted_feedback: bool,
    ) -> Result<BehavioralObservation, BehaviorError> {
        if features.is_empty() {
            return Err(BehaviorError::EmptyFeatures);
        }
        if features.len() > MAX_FEATURES_PER_OBSERVATION {
            return Err(BehaviorError::InvalidPolicy(format!(
                "observação excede {MAX_FEATURES_PER_OBSERVATION} features"
            )));
        }
        for (feature, value) in &features {
            if feature.0.is_empty() {
                return Err(BehaviorError::InvalidFeatureId(
                    "feature id não pode ser vazio".into(),
                ));
            }
            validate_sample(*value)?;
        }

        let key = entity_key(&entity);
        if let Some(last) = self.last_seen_lsn.get(&key).copied() {
            if lsn < last {
                return Err(BehaviorError::OutOfOrder {
                    entity: key,
                    last,
                    current: lsn,
                });
            }
            if lsn == last {
                let score = self.score(&entity, &features);
                return Ok(self.result(entity, lsn, score, ObservationDisposition::Duplicate));
            }
        }
        self.last_seen_lsn.insert(key.clone(), lsn);

        let score = self.score(&entity, &features);
        if suspicious && !trusted_feedback {
            if self.profiles.contains_key(&key) {
                self.quarantine_remaining
                    .insert(key.clone(), self.policy.quarantine_period);
                if let Some(profile) = self.profiles.get_mut(&key) {
                    profile.trust_state = ProfileTrustState::Quarantined;
                }
            }
            return Ok(self.result(entity, lsn, score, ObservationDisposition::Suspicious));
        }

        if !self.allow_rate(&key, lsn) {
            return Ok(self.result(entity, lsn, score, ObservationDisposition::RateLimited));
        }

        let weight = if trusted_feedback {
            self.policy.trusted_feedback_weight
        } else {
            1.0
        };
        if trusted_feedback && weight <= 0.0 {
            return Ok(self.result(entity, lsn, score, ObservationDisposition::Suspicious));
        }

        if self.profiles.contains_key(&key) {
            let remaining = self.quarantine_remaining.get(&key).copied().unwrap_or(0);
            if remaining > 0 && !trusted_feedback {
                self.quarantine_remaining.insert(key.clone(), remaining - 1);
                return Ok(self.result(entity, lsn, score, ObservationDisposition::Quarantined));
            }
            if remaining > 0 {
                self.quarantine_remaining.remove(&key);
            }
            let is_outlier = score.anomalous && self.policy.outlier_exclusion && !trusted_feedback;
            if is_outlier {
                self.quarantine_remaining
                    .insert(key.clone(), self.policy.quarantine_period);
                if let Some(profile) = self.profiles.get_mut(&key) {
                    profile.trust_state = ProfileTrustState::Quarantined;
                }
                return Ok(self.result(
                    entity,
                    lsn,
                    score,
                    ObservationDisposition::OutlierExcluded,
                ));
            }
            let profile = self
                .profiles
                .get_mut(&key)
                .expect("profile presence checked above");
            profile.update(lsn, &features, &self.policy, weight)?;
            profile.trust_state = ProfileTrustState::Trusted;
            return Ok(self.result(
                entity,
                lsn,
                score,
                if trusted_feedback {
                    ObservationDisposition::TrustedFeedback
                } else {
                    ObservationDisposition::Updated
                },
            ));
        }

        let shadow = self.shadow_profiles.entry(key.clone()).or_insert_with(|| {
            self.shadow_started_lsn.insert(key.clone(), lsn);
            BehavioralProfile::new(entity.clone(), ProfileTrustState::Shadow)
        });
        shadow.update(lsn, &features, &self.policy, weight)?;
        let support = shadow.observation_count;
        let promotion_support = self
            .policy
            .minimum_support
            .saturating_add(self.policy.learning_delay_events);
        if !self.policy.shadow_only && support >= promotion_support {
            let mut promoted = self
                .shadow_profiles
                .remove(&key)
                .expect("shadow presence checked above");
            promoted.trust_state = ProfileTrustState::Trusted;
            self.profiles.insert(key.clone(), promoted);
            self.shadow_started_lsn.remove(&key);
            return Ok(self.result(entity, lsn, score, ObservationDisposition::Promoted));
        }
        Ok(self.result(
            entity,
            lsn,
            score,
            if trusted_feedback {
                ObservationDisposition::TrustedFeedback
            } else {
                ObservationDisposition::Warmup
            },
        ))
    }

    fn allow_rate(&mut self, key: &str, lsn: Lsn) -> bool {
        let state = self.rate.entry(key.to_owned()).or_insert(RateState {
            window_start_lsn: lsn,
            updates: 0,
        });
        if lsn.saturating_sub(state.window_start_lsn) >= self.policy.rate_window_lsns {
            state.window_start_lsn = lsn;
            state.updates = 0;
        }
        if state.updates >= self.policy.max_update_rate {
            return false;
        }
        state.updates = state.updates.saturating_add(1);
        true
    }

    fn result(
        &self,
        entity: EntityRef,
        lsn: Lsn,
        score: BehavioralScore,
        disposition: ObservationDisposition,
    ) -> BehavioralObservation {
        let key = entity_key(&entity);
        BehavioralObservation {
            entity,
            lsn,
            score,
            disposition,
            active_trust_state: self.profiles.get(&key).map(|profile| profile.trust_state),
            shadow_support: self
                .shadow_profiles
                .get(&key)
                .map_or(0, |profile| profile.observation_count),
        }
    }
}

fn score_profile(
    profile: &BehavioralProfile,
    features: &BTreeMap<FeatureId, FeatureValue>,
    policy: &BaselinePolicy,
) -> BehavioralScore {
    if profile.observation_count < policy.minimum_support {
        return BehavioralScore {
            support: profile.observation_count,
            ..Default::default()
        };
    }
    let mut feature_scores = BTreeMap::new();
    let mut score: f64 = 0.0;
    for (feature, value) in features {
        let z = profile
            .moments
            .get(feature)
            .and_then(|state| state.z_score(*value))
            .unwrap_or(0.0);
        // Auditoria 2026-09-05, A29: variancia exactamente zero (feature
        // constante na baseline, ex.: `event.failure` = 0.0 em todos os
        // logins bem sucedidos) faz `z_score` devolver `f64::INFINITY`.  Isso
        // nao e evidencia infinita: e o mesmo caso degenerado que o ramo IQR
        // logo abaixo limita a `policy.outlier_z + 1.0`.  Sem este tecto o
        // `z.max(robust)` so propaga o infinito e o primeiro desvio numa
        // feature homogenea sai sempre com a severidade maxima da escala.  O
        // tecto toca apenas no ramo nao-finito; qualquer z legitimo passa
        // intacto.
        let z = if z.is_finite() {
            z
        } else {
            policy.outlier_z + 1.0
        };
        let robust = profile.quantiles.get(feature).map_or(0.0, |state| {
            let q1 = state.quantile(0.25).unwrap_or(*value);
            let median = state.quantile(0.5).unwrap_or(*value);
            let q3 = state.quantile(0.75).unwrap_or(*value);
            let iqr = q3 - q1;
            if iqr.abs() <= f64::EPSILON {
                if (*value - median).abs() <= f64::EPSILON {
                    0.0
                } else {
                    policy.outlier_z + 1.0
                }
            } else {
                ((*value - median).abs() / (iqr / 1.349)).max(0.0)
            }
        });
        let feature_score = z.max(robust);
        score = score.max(feature_score);
        feature_scores.insert(feature.clone(), feature_score);
    }
    BehavioralScore {
        score,
        anomalous: score >= policy.outlier_z,
        support: profile.observation_count,
        feature_scores,
    }
}

fn validate_profile(profile: &BehavioralProfile) -> Result<(), BehaviorError> {
    if profile.entity.kind.trim().is_empty() || profile.entity.id.trim().is_empty() {
        return Err(BehaviorError::InvalidSnapshot(
            "perfil contém entidade vazia".into(),
        ));
    }
    if profile.profile_version == 0 {
        return Err(BehaviorError::InvalidSnapshot(
            "profile_version deve ser maior que zero".into(),
        ));
    }
    if profile.ewma.keys().any(|feature| feature.0.is_empty())
        || profile.moments.keys().any(|feature| feature.0.is_empty())
        || profile.quantiles.keys().any(|feature| feature.0.is_empty())
    {
        return Err(BehaviorError::InvalidSnapshot(
            "perfil contém feature vazia".into(),
        ));
    }
    if profile.ewma.values().any(|state| {
        !state.value.is_finite()
            || !state.alpha.is_finite()
            || !(0.0..=1.0).contains(&state.alpha)
            || state.alpha == 0.0
    }) {
        return Err(BehaviorError::InvalidSnapshot(
            "perfil contém EWMA inválido".into(),
        ));
    }
    if profile.moments.values().any(|state| {
        !state.weight_sum.is_finite()
            || state.weight_sum < 0.0
            || !state.mean.is_finite()
            || !state.m2.is_finite()
            || state.m2 < 0.0
    }) {
        return Err(BehaviorError::InvalidSnapshot(
            "perfil contém momentos inválidos".into(),
        ));
    }
    if profile.quantiles.values().any(|state| {
        state.samples.len() > state.capacity
            || !(2..=4096).contains(&state.capacity)
            || state.samples.iter().any(|sample| !sample.is_finite())
    }) {
        return Err(BehaviorError::InvalidSnapshot(
            "perfil contém quantis inválidos".into(),
        ));
    }
    Ok(())
}

fn attribute_entity(event: &SecurityEvent, prefix: &str) -> Option<EntityRef> {
    let id = event
        .attributes
        .get(&format!("{prefix}.id"))
        .or_else(|| event.attributes.get(&format!("{prefix}_id")))?;
    if id.trim().is_empty() {
        return None;
    }
    let kind = event
        .attributes
        .get(&format!("{prefix}.kind"))
        .map(String::as_str)
        .unwrap_or(prefix);
    Some(EntityRef::new(kind, id.trim()))
}

fn endpoint_entity(endpoint: Option<&crate::NetworkEndpoint>) -> Option<EntityRef> {
    let endpoint = endpoint?;
    endpoint
        .ip
        .as_ref()
        .map(|ip| EntityRef::new("IP", ip))
        .or_else(|| {
            endpoint
                .hostname
                .as_ref()
                .map(|host| EntityRef::new("Domain", host))
        })
}

fn entity_key(entity: &EntityRef) -> String {
    format!(
        "{}:{}:{}:{}",
        entity.kind.len(),
        entity.kind,
        entity.id.len(),
        entity.id
    )
}

/// Auditoria 2026-09-05, A20 — as chaves que um conjunto de entidades toca.
///
/// É a unidade de atomicidade do L2, e sai daqui para que `entity_key` — a
/// identidade de que todos os seis mapas dependem — continue privada a este
/// módulo. Duas entidades com a mesma chave contam uma vez, exactamente como
/// `security_event_inputs` já as deduplica.
pub(crate) fn chaves_de_entidades<'a>(
    entidades: impl IntoIterator<Item = &'a EntityRef>,
) -> BTreeSet<String> {
    entidades.into_iter().map(entity_key).collect()
}

/// Copia de `mapa` apenas as entradas cujas chaves estão em `chaves`.
fn recortar<V: Clone>(
    mapa: &BTreeMap<String, V>,
    chaves: &BTreeSet<String>,
) -> BTreeMap<String, V> {
    chaves
        .iter()
        .filter_map(|chave| mapa.get(chave).map(|valor| (chave.clone(), valor.clone())))
        .collect()
}

/// Escreve `parcial` de volta em `mapa`, para as `chaves` e só para elas.
///
/// Uma chave AUSENTE do parcial significa que a operação a apagou de propósito
/// (promoção de shadow, fim de quarentena), e por isso tem de sair também do
/// mapa vivo. Isto é o oposto de um merge tolerante, e é intencional.
fn fundir<V>(
    mapa: &mut BTreeMap<String, V>,
    chaves: &BTreeSet<String>,
    parcial: &mut BTreeMap<String, V>,
) {
    for chave in chaves {
        match parcial.remove(chave) {
            Some(valor) => {
                mapa.insert(chave.clone(), valor);
            }
            None => {
                mapa.remove(chave);
            }
        }
    }
}

fn splitmix64(value: u64) -> u64 {
    let mut z = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn validate_sample(sample: f64) -> Result<(), BehaviorError> {
    sample
        .is_finite()
        .then_some(())
        .ok_or(BehaviorError::NonFiniteValue)
}

fn validate_weight(weight: f64) -> Result<(), BehaviorError> {
    if weight.is_finite() && (0.0..=1.0).contains(&weight) && weight > 0.0 {
        Ok(())
    } else {
        Err(BehaviorError::InvalidWeight)
    }
}

fn validate_feedback_weight(weight: f64) -> Result<(), BehaviorError> {
    if weight.is_finite() && (0.0..=1.0).contains(&weight) {
        Ok(())
    } else {
        Err(BehaviorError::InvalidPolicy(
            "trusted_feedback_weight deve estar entre 0 e 1".into(),
        ))
    }
}

fn validate_unit_interval(name: &str, value: f64) -> Result<(), BehaviorError> {
    if value.is_finite() && (0.0..=1.0).contains(&value) && value > 0.0 {
        Ok(())
    } else {
        Err(BehaviorError::InvalidPolicy(format!(
            "{name} deve estar entre 0 e 1"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feature(name: &str, value: f64) -> BTreeMap<FeatureId, f64> {
        BTreeMap::from([(FeatureId::new(name).unwrap(), value)])
    }

    fn entity() -> EntityRef {
        EntityRef::new("user", "alice")
    }

    #[test]
    fn security_event_adapter_is_bounded_deduplicated_and_marks_suspicious() {
        let mut event = SecurityEvent::unmapped(
            heraclitus_core::EventId::new(),
            crate::SecuritySource::Auditd,
        );
        event.user = Some(EntityRef::new("User", "alice"));
        event.principal = event.user.clone();
        event.host = Some(EntityRef::new("Host", "db01"));
        event.severity = 8;
        event.outcome = Outcome::Failure;
        event
            .attributes
            .insert("bytes_transferred".into(), "4096".into());

        let inputs = security_event_inputs(&event, 7).unwrap();
        assert_eq!(inputs.len(), 2, "principal/user must be deduplicated");
        assert!(inputs.iter().all(|input| input.suspicious));
        assert!(inputs.iter().all(|input| input.features.len() == 7));
        assert!(inputs
            .iter()
            .all(|input| { input.features[&FeatureId::new("event.bytes").unwrap()] == 4096.0 }));
    }

    #[test]
    fn welford_tracks_mean_variance_and_is_order_stable() {
        let mut left = MomentState::default();
        let mut right = MomentState::default();
        for (lsn, value) in [1.0, 2.0, 3.0, 4.0].into_iter().enumerate() {
            left.update(lsn as u64 + 1, value).unwrap();
        }
        for (lsn, value) in [4.0, 3.0, 2.0, 1.0].into_iter().enumerate() {
            right.update(lsn as u64 + 1, value).unwrap();
        }
        assert!((left.mean - 2.5).abs() < 1e-12);
        assert!((left.variance().unwrap() - 1.666_666_666_666_666_7).abs() < 1e-12);
        assert!((left.mean - right.mean).abs() < 1e-12);
        assert!((left.m2 - right.m2).abs() < 1e-12);
    }

    #[test]
    fn quantiles_are_bounded_and_use_nearest_rank() {
        let mut exact = QuantileState::new(4).unwrap();
        for value in 1..=4 {
            exact.update(value, value as f64).unwrap();
        }
        assert_eq!(exact.quantile(0.5), Some(2.0));

        let mut state = QuantileState::new(4).unwrap();
        for value in 1..=100 {
            state.update(value, value as f64).unwrap();
        }
        assert_eq!(state.samples.len(), 4);
        assert!(state
            .quantile(0.0)
            .is_some_and(|value| (1.0..=100.0).contains(&value)));
        assert!((1.0..=100.0).contains(&state.quantile(0.5).unwrap()));
        assert!(state
            .quantile(1.0)
            .is_some_and(|value| (1.0..=100.0).contains(&value)));
    }

    #[test]
    fn suspicious_events_do_not_poison_shadow_or_active_profiles() {
        let policy = BaselinePolicy {
            minimum_support: 2,
            learning_delay_events: 1,
            shadow_only: false,
            ..Default::default()
        };
        let mut engine = BehavioralEngine::new(policy).unwrap();
        engine
            .observe(1, entity(), feature("logins_per_minute", 1.0), false)
            .unwrap();
        engine
            .observe(2, entity(), feature("logins_per_minute", 1.0), false)
            .unwrap();
        engine
            .observe(3, entity(), feature("logins_per_minute", 1.0), false)
            .unwrap();
        assert!(engine.profile(&entity()).is_some());
        let before = engine.profile(&entity()).unwrap().clone();
        let result = engine
            .observe(4, entity(), feature("logins_per_minute", 1000.0), true)
            .unwrap();
        assert_eq!(result.disposition, ObservationDisposition::Suspicious);
        assert_eq!(
            engine.profile(&entity()).unwrap().observation_count,
            before.observation_count
        );
        assert_eq!(engine.profile(&entity()).unwrap().moments, before.moments);
    }

    #[test]
    fn outliers_are_excluded_and_quarantine_is_bounded() {
        let policy = BaselinePolicy {
            minimum_support: 2,
            learning_delay_events: 1,
            quarantine_period: 2,
            shadow_only: false,
            outlier_z: 2.0,
            ..Default::default()
        };
        let mut engine = BehavioralEngine::new(policy).unwrap();
        for lsn in 1..=3 {
            engine
                .observe(lsn, entity(), feature("requests", 1.0), false)
                .unwrap();
        }
        let outlier = engine
            .observe(4, entity(), feature("requests", 100.0), false)
            .unwrap();
        assert_eq!(outlier.disposition, ObservationDisposition::OutlierExcluded);
        assert_eq!(
            engine.profile(&entity()).unwrap().trust_state,
            ProfileTrustState::Quarantined
        );
        assert_eq!(
            engine
                .observe(5, entity(), feature("requests", 1.0), false)
                .unwrap()
                .disposition,
            ObservationDisposition::Quarantined
        );
        assert_eq!(
            engine
                .observe(6, entity(), feature("requests", 1.0), false)
                .unwrap()
                .disposition,
            ObservationDisposition::Quarantined
        );
        assert_eq!(
            engine
                .observe(7, entity(), feature("requests", 1.0), false)
                .unwrap()
                .disposition,
            ObservationDisposition::Updated
        );
    }

    #[test]
    fn trusted_feedback_is_the_only_suspicious_update_path() {
        let policy = BaselinePolicy {
            minimum_support: 1,
            learning_delay_events: 1,
            shadow_only: false,
            ..Default::default()
        };
        let mut engine = BehavioralEngine::new(policy).unwrap();
        engine
            .observe(1, entity(), feature("failures", 1.0), false)
            .unwrap();
        engine
            .observe(2, entity(), feature("failures", 1.0), false)
            .unwrap();
        let before = engine.profile(&entity()).unwrap().observation_count;
        assert_eq!(
            engine
                .observe(3, entity(), feature("failures", 9.0), true)
                .unwrap()
                .disposition,
            ObservationDisposition::Suspicious
        );
        assert_eq!(engine.profile(&entity()).unwrap().observation_count, before);
        assert_eq!(
            engine
                .observe_trusted_feedback(4, entity(), feature("failures", 9.0), true)
                .unwrap()
                .disposition,
            ObservationDisposition::TrustedFeedback
        );
        assert_eq!(
            engine.profile(&entity()).unwrap().observation_count,
            before + 1
        );
    }

    #[test]
    fn update_rate_limit_bounds_a_burst_without_losing_lsn_order() {
        let policy = BaselinePolicy {
            minimum_support: 1,
            learning_delay_events: 1,
            max_update_rate: 2,
            rate_window_lsns: 10,
            shadow_only: true,
            ..Default::default()
        };
        let mut engine = BehavioralEngine::new(policy).unwrap();
        assert_eq!(
            engine
                .observe(1, entity(), feature("requests", 1.0), false)
                .unwrap()
                .disposition,
            ObservationDisposition::Warmup
        );
        assert_eq!(
            engine
                .observe(2, entity(), feature("requests", 1.0), false)
                .unwrap()
                .disposition,
            ObservationDisposition::Warmup
        );
        assert_eq!(
            engine
                .observe(3, entity(), feature("requests", 1.0), false)
                .unwrap()
                .disposition,
            ObservationDisposition::RateLimited
        );
        assert_eq!(
            engine
                .observe(11, entity(), feature("requests", 1.0), false)
                .unwrap()
                .disposition,
            ObservationDisposition::Warmup
        );
    }

    #[test]
    fn snapshot_roundtrip_replays_identically_and_rejects_stale_lsn() {
        let policy = BaselinePolicy {
            minimum_support: 2,
            learning_delay_events: 1,
            shadow_only: false,
            ..Default::default()
        };
        let mut first = BehavioralEngine::new(policy.clone()).unwrap();
        for (lsn, value) in [(1, 1.0), (2, 2.0), (3, 2.0)] {
            first
                .observe(lsn, entity(), feature("bytes", value), false)
                .unwrap();
        }
        let snapshot = first.snapshot();
        let json = serde_json::to_vec(&snapshot).unwrap();
        let mut second =
            BehavioralEngine::from_snapshot(serde_json::from_slice(&json).unwrap()).unwrap();
        assert_eq!(first.snapshot(), second.snapshot());
        let next = feature("bytes", 2.0);
        let left = first.observe(4, entity(), next.clone(), false).unwrap();
        let right = second.observe(4, entity(), next, false).unwrap();
        assert_eq!(left, right);
        assert!(matches!(
            second.observe(3, entity(), feature("bytes", 2.0), false),
            Err(BehaviorError::OutOfOrder { .. })
        ));
    }

    #[test]
    fn policy_and_values_fail_closed() {
        assert!(BehavioralEngine::new(BaselinePolicy {
            decay: 0.0,
            ..Default::default()
        })
        .is_err());
        let mut engine = BehavioralEngine::new(BaselinePolicy::default()).unwrap();
        assert!(matches!(
            engine.observe(1, entity(), feature("bad", f64::NAN), false),
            Err(BehaviorError::NonFiniteValue)
        ));
        assert!(FeatureId::new("\n").is_err());
    }

    /// Auditoria 2026-09-05, A29: uma feature constante na baseline (ex.:
    /// `event.failure` = 0.0 em todos os logins bem sucedidos) deixa
    /// `m2 = 0.0` exacto, logo `stddev = 0.0` e `z_score` devolve
    /// `f64::INFINITY` para o primeiro desvio.  O caso degenerado tem de
    /// ficar limitado — como ja acontece no ramo IQR — em vez de saltar
    /// directamente para o topo da escala de severidade.
    #[test]
    fn feature_constante_nao_produz_score_infinito() {
        let policy = BaselinePolicy::default();
        let mut profile = BehavioralProfile::new(entity(), ProfileTrustState::Trusted);
        for lsn in 1..=30 {
            profile
                .update(lsn, &feature("event.failure", 0.0), &policy, 1.0)
                .unwrap();
        }
        let moments = profile
            .moments
            .get(&FeatureId::new("event.failure").unwrap())
            .unwrap();
        assert_eq!(
            moments.stddev(),
            Some(0.0),
            "a baseline tem de ficar degenerada"
        );

        let score = score_profile(&profile, &feature("event.failure", 1.0), &policy);
        assert!(
            score.score.is_finite(),
            "z degenerado escapou sem tecto: {}",
            score.score
        );
        assert_eq!(
            score.score,
            policy.outlier_z + 1.0,
            "o ramo dos momentos tem de dar o mesmo valor limitado que o ramo IQR"
        );
        assert!(score.anomalous, "o desvio continua a ter de ser anomalo");
    }

    /// Auditoria 2026-09-05, A29: o tecto do caso degenerado nao pode achatar
    /// um outlier legitimo — so o ramo nao-finito muda de valor.
    #[test]
    fn tecto_degenerado_nao_achata_outlier_legitimo() {
        let policy = BaselinePolicy::default();
        let mut profile = BehavioralProfile::new(entity(), ProfileTrustState::Trusted);
        let alvo = FeatureId::new("event.bytes").unwrap();
        for lsn in 1..=30 {
            // Peso < 1.0 deixa o reservatorio de quantis vazio (ver
            // `BehavioralProfile::update`), portanto o ramo robusto vale 0.0 e
            // quem decide o score e exclusivamente o z — sem esta condicao o
            // `z.max(robust)` mascara qualquer achatamento do z.  Dispersao
            // real: alterna 0.0/1.0.
            profile
                .update(lsn, &feature("event.bytes", (lsn % 2) as f64), &policy, 0.5)
                .unwrap();
        }
        assert!(
            !profile.quantiles.contains_key(&alvo),
            "o ramo robusto tem de estar fora de jogo neste teste"
        );

        let esperado = profile.moments.get(&alvo).unwrap().z_score(50.0).unwrap();
        assert!(
            esperado > policy.outlier_z + 1.0,
            "o z de referencia tem de exceder o tecto: {esperado}"
        );
        let score = score_profile(&profile, &feature("event.bytes", 50.0), &policy);
        assert_eq!(
            score.score, esperado,
            "z legitimo tem de passar intacto pelo tecto"
        );
    }

    /// Auditoria 2026-09-05, A20 — trabalhar sobre um RECORTE das entidades
    /// tocadas e fundi-lo de volta tem de dar exactamente o mesmo motor que
    /// trabalhar sobre um clone completo.
    ///
    /// As duas fases não são decorativas: são os dois sítios onde
    /// `observe_internal` REMOVE entradas. A promoção de um shadow apaga de
    /// `shadow_profiles` e de `shadow_started_lsn`; a saída de quarentena por
    /// feedback confiável apaga de `quarantine_remaining`. Uma fusão só de
    /// inserção passaria em tudo o resto e deixava perfis fantasma e
    /// quarentenas eternas — em silêncio, e a mudar scores.
    #[test]
    fn o_recorte_por_entidade_equivale_ao_clone_completo() {
        let politica = BaselinePolicy {
            minimum_support: 2,
            learning_delay_events: 1,
            quarantine_period: 3,
            shadow_only: false,
            ..BaselinePolicy::default()
        };
        let mut motor = BehavioralEngine::new(politica).unwrap();

        // Ruído: entidades que o evento NÃO toca. Se a fusão lhes mexesse — ou
        // se o recorte as levasse e as trouxesse de volta alteradas — o
        // `assert_eq!` do motor inteiro apanhava-o.
        let mut lsn = 0u64;
        for i in 0..20u64 {
            lsn += 1;
            motor
                .observe(
                    lsn,
                    EntityRef::new("user", format!("ruido-{i}")),
                    feature("bytes", i as f64),
                    false,
                )
                .unwrap();
        }

        // FASE 1 — promoção. `promotion_support` = 2 + 1 = 3, portanto duas
        // observações deixam-no em shadow e a terceira promove-o.
        let promovido = EntityRef::new("user", "promovido");
        let acompanhante = EntityRef::new("host", "acompanhante");
        for _ in 0..2 {
            lsn += 1;
            motor
                .observe(lsn, promovido.clone(), feature("bytes", 10.0), false)
                .unwrap();
        }
        lsn += 1;
        motor
            .observe(lsn, acompanhante.clone(), feature("bytes", 1.0), false)
            .unwrap();

        let chaves = chaves_de_entidades([&promovido, &acompanhante]);
        lsn += 1;
        let observar = |motor: &mut BehavioralEngine, lsn: u64| {
            motor
                .observe(lsn, promovido.clone(), feature("bytes", 11.0), false)
                .unwrap();
            motor
                .observe(lsn, acompanhante.clone(), feature("bytes", 2.0), false)
                .unwrap();
        };

        // Referência: o caminho anterior, clone completo e substituição.
        let mut esperado = motor.clone();
        observar(&mut esperado, lsn);

        let mut parcial = motor.extrair_entidades(&chaves);
        assert_eq!(
            parcial.numero_de_perfis(),
            2,
            "o recorte leva as DUAS entidades pedidas, nao as 22 que o motor tem"
        );
        observar(&mut parcial, lsn);
        let mut obtido = motor.clone();
        obtido.fundir_entidades(&chaves, parcial);

        assert!(
            esperado.profile(&promovido).is_some() && esperado.shadow_profile(&promovido).is_none(),
            "a montagem tem de exercitar mesmo a promoção, senão o teste é vácuo"
        );
        assert!(
            obtido == esperado,
            "depois da promoção o motor fundido tem de ser igual ao do clone completo"
        );

        // FASE 2 — saída de quarentena, que é o outro `remove`.
        let mut motor = obtido;
        lsn += 1;
        motor
            .observe(lsn, promovido.clone(), feature("bytes", 12.0), true)
            .unwrap();
        assert!(
            motor
                .quarantine_remaining
                .get(&entity_key(&promovido))
                .copied()
                .unwrap_or(0)
                > 0,
            "a montagem tem de deixar mesmo o perfil em quarentena"
        );

        let chaves = chaves_de_entidades([&promovido]);
        lsn += 1;
        let mut esperado = motor.clone();
        esperado
            .observe_trusted_feedback(lsn, promovido.clone(), feature("bytes", 13.0), false)
            .unwrap();

        let mut parcial = motor.extrair_entidades(&chaves);
        parcial
            .observe_trusted_feedback(lsn, promovido.clone(), feature("bytes", 13.0), false)
            .unwrap();
        let mut obtido = motor.clone();
        obtido.fundir_entidades(&chaves, parcial);

        assert_eq!(
            esperado
                .quarantine_remaining
                .get(&entity_key(&promovido))
                .copied()
                .unwrap_or(0),
            0,
            "a montagem tem de exercitar mesmo a saída de quarentena"
        );
        assert!(
            obtido == esperado,
            "depois da saída de quarentena o motor fundido tem de ser igual ao do clone completo"
        );
    }

    /// Auditoria 2026-09-05, A20 — o recorte tem de levar os SEIS mapas
    /// indexados por entidade, não cinco.
    ///
    /// Esta verificação é estrutural de propósito. Esquecer um mapa não dá erro
    /// de compilação (os campos que faltam vinham a zero num `Default`) e a
    /// consequência de comportamento é indirecta: sem `last_seen_lsn` a guarda
    /// de ordem deixa de ver o último LSN e um replay volta a ser incorporado;
    /// sem `rate` o limitador reinicia a janela; sem `quarantine_remaining` um
    /// perfil em quarentena volta a actualizar a baseline. Um teste de
    /// comportamento só apanha cada um desses casos com a montagem exacta que
    /// os provoca; a comparação directa apanha-os todos.
    #[test]
    fn o_recorte_leva_os_seis_mapas_da_entidade() {
        let politica = BaselinePolicy {
            minimum_support: 2,
            learning_delay_events: 1,
            quarantine_period: 3,
            shadow_only: false,
            ..BaselinePolicy::default()
        };
        let mut motor = BehavioralEngine::new(politica).unwrap();

        // Duas entidades porque uma só não chega: depois de promovido, um perfil
        // está em `profiles` OU em `shadow_profiles`, nunca nos dois.
        let promovido = EntityRef::new("user", "promovido");
        let em_shadow = EntityRef::new("host", "em-shadow");
        let mut lsn = 0;
        for _ in 0..3 {
            lsn += 1;
            motor
                .observe(lsn, promovido.clone(), feature("bytes", 10.0), false)
                .unwrap();
        }
        lsn += 1;
        // Suspeito sobre um perfil já activo: é o que põe a entidade em
        // quarentena, e portanto o que enche `quarantine_remaining`.
        motor
            .observe(lsn, promovido.clone(), feature("bytes", 99.0), true)
            .unwrap();
        lsn += 1;
        motor
            .observe(lsn, em_shadow.clone(), feature("bytes", 1.0), false)
            .unwrap();

        // Ruído, para que a igualdade abaixo não passe por os mapas estarem
        // todos completos.
        for i in 0..10u64 {
            lsn += 1;
            motor
                .observe(
                    lsn,
                    EntityRef::new("user", format!("ruido-{i}")),
                    feature("bytes", i as f64),
                    false,
                )
                .unwrap();
        }

        let chaves = chaves_de_entidades([&promovido, &em_shadow]);
        let parcial = motor.extrair_entidades(&chaves);

        // Cada mapa é comparado com a sua própria restrição às chaves, e
        // exige-se que nenhum esteja vazio — senão a comparação era vácua.
        let mapas: [(&str, bool, bool); 6] = [
            (
                "profiles",
                parcial.profiles == recortar(&motor.profiles, &chaves),
                parcial.profiles.is_empty(),
            ),
            (
                "shadow_profiles",
                parcial.shadow_profiles == recortar(&motor.shadow_profiles, &chaves),
                parcial.shadow_profiles.is_empty(),
            ),
            (
                "shadow_started_lsn",
                parcial.shadow_started_lsn == recortar(&motor.shadow_started_lsn, &chaves),
                parcial.shadow_started_lsn.is_empty(),
            ),
            (
                "last_seen_lsn",
                parcial.last_seen_lsn == recortar(&motor.last_seen_lsn, &chaves),
                parcial.last_seen_lsn.is_empty(),
            ),
            (
                "rate",
                parcial.rate == recortar(&motor.rate, &chaves),
                parcial.rate.is_empty(),
            ),
            (
                "quarantine_remaining",
                parcial.quarantine_remaining == recortar(&motor.quarantine_remaining, &chaves),
                parcial.quarantine_remaining.is_empty(),
            ),
        ];
        for (nome, igual, vazio) in mapas {
            assert!(igual, "o recorte perdeu o mapa `{nome}`");
            assert!(
                !vazio,
                "a montagem tem de encher `{nome}`, senao a comparacao era vacua"
            );
        }
        assert_eq!(
            parcial.policy, motor.policy,
            "a política é imutável e partilhada: o recorte tem de a levar intacta"
        );
    }
}
