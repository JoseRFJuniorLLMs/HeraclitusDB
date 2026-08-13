//! SPEC-025 — engine extensibility (plugin contract).
//!
//! Third-party index types, compressors and operators register through a
//! stable trait without touching core source. A `PluginHost` checks binary
//! version compatibility, then lets each plugin advertise its capabilities into
//! a shared `RegistryCatalog`.
//!
//! Note: SPEC-035 asks for WASM (`wasmtime`) isolation of plugin *execution*.
//! That is a heavy, feature-gated follow-up (and sits in tension with the
//! "intelligence lives in the agent, not the DB" thesis); this module defines
//! the in-process contract that a WASM host would later implement.
//!
//! Wiring status (P4, 2026-07-16): **reference contract, not wired**. The
//! `PluginHost` only *catalogs* capability names — nothing in the query path
//! invokes a registered operator, and the only implementor
//! (`heraclitus-wasm`) is an orphan crate. See
//! `docs/md/DECISAO-P4-plugins-wasm.md`.

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ExtensionCapabilities {
    pub provides_index_type: Option<String>,
    pub provides_compression: Option<String>,
    pub provides_operator: Option<String>,
}

#[derive(Debug, Default, PartialEq)]
pub struct RegistryCatalog {
    pub index_types: Vec<String>,
    pub compressors: Vec<String>,
    pub operators: Vec<String>,
}

pub trait HeraclitusPlugin: Send + Sync {
    fn capabilities(&self) -> ExtensionCapabilities;
    fn register(&mut self, catalog: &mut RegistryCatalog) -> Result<(), String>;
    /// `(major, minor)` for binary-compatibility negotiation.
    fn version_handshake(&self) -> (u32, u32);
}

/// Loads plugins, rejecting any whose major version does not match the host.
pub struct PluginHost {
    host_major: u32,
    catalog: RegistryCatalog,
}

impl PluginHost {
    pub fn new(host_major: u32) -> Self {
        Self { host_major, catalog: RegistryCatalog::default() }
    }

    pub fn load(&mut self, mut plugin: Box<dyn HeraclitusPlugin>) -> Result<(), String> {
        let (major, _minor) = plugin.version_handshake();
        if major != self.host_major {
            return Err(format!(
                "plugin ABI major {major} incompatible with host {}",
                self.host_major
            ));
        }
        plugin.register(&mut self.catalog)
    }

    pub fn catalog(&self) -> &RegistryCatalog {
        &self.catalog
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ZstdPlugin;
    impl HeraclitusPlugin for ZstdPlugin {
        fn capabilities(&self) -> ExtensionCapabilities {
            ExtensionCapabilities { provides_compression: Some("zstd-adaptive".into()), ..Default::default() }
        }
        fn register(&mut self, catalog: &mut RegistryCatalog) -> Result<(), String> {
            catalog.compressors.push("zstd-adaptive".into());
            Ok(())
        }
        fn version_handshake(&self) -> (u32, u32) {
            (1, 3)
        }
    }

    #[test]
    fn compatible_plugin_registers_capability() {
        let mut host = PluginHost::new(1);
        host.load(Box::new(ZstdPlugin)).unwrap();
        assert_eq!(host.catalog().compressors, vec!["zstd-adaptive".to_string()]);
    }

    #[test]
    fn incompatible_major_is_rejected() {
        let mut host = PluginHost::new(2);
        let err = host.load(Box::new(ZstdPlugin)).unwrap_err();
        assert!(err.contains("incompatible"));
        assert!(host.catalog().compressors.is_empty());
    }
}
