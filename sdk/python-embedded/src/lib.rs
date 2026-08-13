//! heraclitusdb-embedded — HeraclitusDB embutido para Python (PyO3).
//!
//! O motor completo in-process, sem servidor gRPC: append, GQL (incl.
//! `AS OF` / `VALID AT` / `SIMULATE` / `FUSE` / `DIST_*`), verify e
//! introspecção — a mesma durabilidade do servidor (log append-only + Merkle),
//! sem a camada de rede. Pensado para agentes de IA locais e notebooks.
//!
//! ```python
//! import heraclitusdb_embedded as h
//! db = h.Embedded("./data")
//! db.append("Observation", "empresa X trocou de sócio", attrs={"caso": "1"})
//! rows = db.query("MATCH (n) RETURN n")          # -> list[dict]
//! db.verify()                                     # prova criptográfica
//! db.checkpoint()                                 # fast boot para o próximo open
//! ```
//!
//! Build da wheel (stable ABI, CPython 3.8+): `maturin build --release`
//! dentro de `sdk/python-embedded`.

use heraclitus_core::{Episode, EventKind};
use heraclitus_server::Embedded as CoreEmbedded;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::collections::BTreeMap;

fn err<E: std::fmt::Display>(e: E) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

/// Converte `serde_json::Value` para um objeto Python nativo (dict/list/
/// escalares) — para que `query()` devolva estruturas idiomáticas, não strings.
fn json_to_py(py: Python<'_>, v: &serde_json::Value) -> PyResult<PyObject> {
    use serde_json::Value as J;
    Ok(match v {
        J::Null => py.None(),
        J::Bool(b) => b.into_pyobject(py)?.to_owned().unbind().into_any(),
        J::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.into_pyobject(py)?.into_any().unbind()
            } else if let Some(u) = n.as_u64() {
                u.into_pyobject(py)?.into_any().unbind()
            } else {
                n.as_f64().unwrap_or(0.0).into_pyobject(py)?.into_any().unbind()
            }
        }
        J::String(s) => s.into_pyobject(py)?.into_any().unbind(),
        J::Array(a) => {
            let list = PyList::empty(py);
            for item in a {
                list.append(json_to_py(py, item)?)?;
            }
            list.into_any().unbind()
        }
        J::Object(o) => {
            let dict = PyDict::new(py);
            for (k, val) in o {
                dict.set_item(k, json_to_py(py, val)?)?;
            }
            dict.into_any().unbind()
        }
    })
}

/// HeraclitusDB embutido.
#[pyclass]
struct Embedded {
    inner: CoreEmbedded,
}

#[pymethods]
impl Embedded {
    /// Abre (ou cria) a base em `data_dir`.
    #[new]
    fn new(data_dir: &str) -> PyResult<Self> {
        Ok(Self { inner: CoreEmbedded::open(data_dir).map_err(err)? })
    }

    /// Grava um episódio. `kind`: Observation/Action/Message/... `attrs`:
    /// dict opcional; `valid_from`/`valid_to`: valid time nativo (mundo real).
    /// Devolve o LSN atribuído.
    #[pyo3(signature = (kind, content, attrs=None, valid_from=None, valid_to=None))]
    fn append(
        &self,
        kind: &str,
        content: &str,
        attrs: Option<BTreeMap<String, String>>,
        valid_from: Option<u64>,
        valid_to: Option<u64>,
    ) -> PyResult<u64> {
        let ek = match kind {
            "Observation" => EventKind::Observation,
            "Action" => EventKind::Action,
            "Message" => EventKind::Message,
            other => EventKind::Custom(other.to_string()),
        };
        let mut e = Episode::new("python", ek, content.as_bytes().to_vec());
        if let Some(a) = attrs {
            e.attrs = a.into_iter().collect();
        }
        e.valid_from = valid_from;
        e.valid_to = valid_to;
        self.inner.append(e).map_err(err)
    }

    /// Executa GQL. Devolve `list[dict]` (ou o valor idiomático da query).
    fn query(&self, py: Python<'_>, gql: &str) -> PyResult<PyObject> {
        let v = self.inner.query(gql).map_err(err)?;
        json_to_py(py, &v)
    }

    /// Verificação criptográfica (Merkle) do log inteiro — devolve um dict.
    fn verify(&self, py: Python<'_>) -> PyResult<PyObject> {
        let v = self.inner.verify().map_err(err)?;
        json_to_py(py, &v)
    }

    /// Introspecção `heraclitus_state()` — head, segmentos, watermarks.
    fn state(&self, py: Python<'_>) -> PyResult<PyObject> {
        json_to_py(py, &self.inner.state())
    }

    /// Fast boot: persiste os snapshots das views (o próximo `Embedded(...)`
    /// restaura e replaya só a cauda).
    fn checkpoint(&self) -> PyResult<()> {
        self.inner.checkpoint().map_err(err)
    }
}

#[pymodule]
fn heraclitusdb_embedded(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Embedded>()?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
