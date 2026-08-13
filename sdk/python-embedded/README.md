# heraclitusdb-embedded

The full HeraclitusDB engine **in-process for Python** — no gRPC server. Same
durability as the server (append-only log + blake3 Merkle), same GQL dialect
(`AS OF`, `VALID AT`, `SIMULATE`, `FUSE`, `DIST_*`, numeric range). Built for
local AI agents and notebooks.

## Build

Needs [maturin](https://www.maturin.rs) and a Rust toolchain:

```bash
cd sdk/python-embedded
maturin develop --release      # builds and installs into the current venv
# or: maturin build --release   # produces a wheel in target/wheels/
```

The wheel targets the stable ABI (`abi3-py38`), so one build works on
CPython 3.8+.

## Use

```python
import heraclitusdb_embedded as h

db = h.Embedded("./data")

# append (native bi-temporal valid time is first-class)
lsn = db.append("Observation", "company X changed partners",
                attrs={"case": "1"}, valid_from=1000, valid_to=2000)

# query returns list[dict] (not strings)
rows = db.query("MATCH (n) RETURN n")
now  = db.query("MATCH (n) VALID AT 1500 RETURN n")   # when the fact was TRUE

# integrity + introspection
db.verify()        # cryptographic Merkle proof of the whole log
db.state()         # head_lsn, segments, view watermarks
db.checkpoint()    # fast boot: next Embedded(...) restores + replays only the tail
```

## API

| Method | Returns | Notes |
| --- | --- | --- |
| `Embedded(data_dir)` | — | opens/creates the store |
| `append(kind, content, attrs=None, valid_from=None, valid_to=None)` | `int` (LSN) | |
| `query(gql)` | `list[dict]` \| `dict` \| `None` | full GQL surface |
| `verify()` | `dict` | Merkle verification |
| `state()` | `dict` | `heraclitus_state()` |
| `checkpoint()` | `None` | persist view snapshots |

> This crate is excluded from the Cargo workspace (it needs a Python
> interpreter at build time); build it standalone with maturin.
