//! SPEC-025/035 — sandbox WASM real (wasmtime) para extensões.
//!
//! > **ESTADO: REFERÊNCIA DE I&D — NÃO LIGADO AO CAMINHO VIVO** (decisão P4,
//! > 2026-07-16 — `docs/md/DECISAO-P4-plugins-wasm.md`). Nenhum crate depende
//! > deste. O isolamento aqui (memória/fuel/traps) é real e testado **em
//! > unidade**, mas não há sítio no query/executor que **invoque** um operador
//! > `wasm:<nome>`: o `PluginHost` só cataloga nomes, e a ABI de UDF é o
//! > `(i64,i64)->i64` de brinquedo abaixo. Ligar plugins a sério = uma feature
//! > (superfície GQL para UDF + dispatch no executor + ABI real) mais uma
//! > decisão sobre a invariante I2 ("inteligência no agente, não no banco"),
//! > que o próprio `core::plugin` admite. Fica como referência; não promover
//! > sem reabrir a P4.
//!
//! Um plugin de terceiros NUNCA pode derrubar o banco. Aqui isso é garantido
//! por construção, não por disciplina:
//!
//! - **Isolamento de memória:** o módulo WASM só vê a sua memória linear —
//!   zero ponteiros para o heap do host (garantia do runtime).
//! - **Fuel metering:** cada chamada recebe um orçamento de instruções; um
//!   loop infinito esgota o fuel e vira um `Err` tratado — o processo segue
//!   vivo (testado).
//! - **Traps contidos:** divisão por zero, OOB, unreachable → `Err`, nunca
//!   pânico no host.
//!
//! Integração: [`WasmPlugin`] executa; [`WasmPluginAdapter`] regista a
//! capacidade no `PluginHost` do core (SPEC-025). Crate separado = dependência
//! opt-in (a tese "inteligência no agente, não no banco" mantém-se: isto só
//! entra em quem explicitamente o puxa).

use heraclitus_core::plugin::{ExtensionCapabilities, HeraclitusPlugin, RegistryCatalog};
use wasmtime::{Config, Engine, Instance, Module, Store};

/// Um módulo WASM carregado, pronto a executar funções exportadas em sandbox.
pub struct WasmPlugin {
    engine: Engine,
    module: Module,
    name: String,
}

impl WasmPlugin {
    /// Carrega de texto WAT ou binário .wasm. O módulo é validado/compilado
    /// aqui (Cranelift); erros de módulo malicioso/inválido ficam contidos.
    pub fn load(name: impl Into<String>, wat_or_wasm: &[u8]) -> Result<Self, String> {
        let mut cfg = Config::new();
        cfg.consume_fuel(true); // SPEC-035: orçamento de instruções obrigatório
        let engine = Engine::new(&cfg).map_err(|e| format!("engine: {e}"))?;
        let module = Module::new(&engine, wat_or_wasm).map_err(|e| format!("module: {e}"))?;
        Ok(Self { engine, module, name: name.into() })
    }

    /// Executa `func(i64, i64) -> i64` exportada, com `fuel` como teto de
    /// instruções. Loop infinito / trap / função errada → `Err` tratado.
    pub fn call2_i64(&self, func: &str, a: i64, b: i64, fuel: u64) -> Result<i64, String> {
        // Store novo por chamada: estado do plugin não vaza entre execuções.
        // Fuel limita CPU mas NÃO memória — sem um ResourceLimiter, um módulo
        // válido podia declarar/crescer memória linear até esgotar a RAM do
        // host logo na instanciação. 64 MiB chegam de sobra para operadores.
        let limits = wasmtime::StoreLimitsBuilder::new()
            .memory_size(64 << 20)
            .memories(2)
            .tables(4)
            .instances(4)
            .build();
        let mut store = Store::new(&self.engine, limits);
        store.limiter(|l| l);
        store.set_fuel(fuel).map_err(|e| format!("fuel: {e}"))?;
        let instance = Instance::new(&mut store, &self.module, &[])
            .map_err(|e| format!("instantiate: {e}"))?;
        let f = instance
            .get_typed_func::<(i64, i64), i64>(&mut store, func)
            .map_err(|e| format!("export '{func}': {e}"))?;
        f.call(&mut store, (a, b))
            .map_err(|e| format!("sandboxed call '{func}' faulted: {e}"))
    }
}

/// Adapter SPEC-025: expõe um [`WasmPlugin`] como `HeraclitusPlugin`, para o
/// `PluginHost` do core o registar como operador (`wasm:<nome>`).
pub struct WasmPluginAdapter {
    pub plugin: WasmPlugin,
}

impl HeraclitusPlugin for WasmPluginAdapter {
    fn capabilities(&self) -> ExtensionCapabilities {
        ExtensionCapabilities {
            provides_operator: Some(format!("wasm:{}", self.plugin.name)),
            ..Default::default()
        }
    }
    fn register(&mut self, catalog: &mut RegistryCatalog) -> Result<(), String> {
        catalog.operators.push(format!("wasm:{}", self.plugin.name));
        Ok(())
    }
    fn version_handshake(&self) -> (u32, u32) {
        (1, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heraclitus_core::plugin::PluginHost;

    const ADD: &str = r#"(module
      (func (export "add") (param i64 i64) (result i64)
        local.get 0
        local.get 1
        i64.add))"#;

    // Loop infinito: sem fuel metering, isto penduraria o processo para sempre.
    const SPIN: &str = r#"(module
      (func (export "spin") (param i64 i64) (result i64)
        (loop br 0)
        i64.const 0))"#;

    // Trap determinístico (unreachable).
    const BOOM: &str = r#"(module
      (func (export "boom") (param i64 i64) (result i64)
        unreachable))"#;

    #[test]
    fn udf_executes_in_sandbox() {
        let p = WasmPlugin::load("adder", ADD.as_bytes()).unwrap();
        assert_eq!(p.call2_i64("add", 2, 3, 100_000).unwrap(), 5);
        // Função inexistente = erro tratado, não pânico.
        assert!(p.call2_i64("nope", 1, 1, 100_000).is_err());
    }

    #[test]
    fn infinite_loop_is_stopped_by_fuel_and_host_survives() {
        // SPEC-035, a garantia central: um plugin malicioso com loop infinito
        // esgota o fuel, vira Err, e o host continua a executar chamadas.
        let p = WasmPlugin::load("evil", SPIN.as_bytes()).unwrap();
        let err = p.call2_i64("spin", 0, 0, 10_000).unwrap_err();
        assert!(err.contains("fuel") || err.contains("faulted"), "got: {err}");

        // O host está vivo: uma chamada legítima a seguir funciona.
        let ok = WasmPlugin::load("adder", ADD.as_bytes()).unwrap();
        assert_eq!(ok.call2_i64("add", 40, 2, 100_000).unwrap(), 42);
    }

    #[test]
    fn traps_are_contained_errors() {
        let p = WasmPlugin::load("boom", BOOM.as_bytes()).unwrap();
        let err = p.call2_i64("boom", 0, 0, 100_000).unwrap_err();
        assert!(err.contains("faulted"), "trap contido como Err: {err}");
    }

    #[test]
    fn spec025_wasm_plugin_registers_in_plugin_host() {
        // Fecha o loop 025→035: o PluginHost do core carrega um plugin cuja
        // EXECUÇÃO vive na sandbox WASM.
        let plugin = WasmPlugin::load("scorer", ADD.as_bytes()).unwrap();
        let mut host = PluginHost::new(1);
        host.load(Box::new(WasmPluginAdapter { plugin })).unwrap();
        assert_eq!(host.catalog().operators, vec!["wasm:scorer".to_string()]);
    }

    #[test]
    fn malformed_module_is_rejected_at_load() {
        assert!(WasmPlugin::load("junk", b"isto nao e wasm").is_err());
    }
}
