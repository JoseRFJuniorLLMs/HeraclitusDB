"""Verify the reference models, without claiming refinement of Rust code."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--out", type=Path, required=True)
args = parser.parse_args()
sources = sorted((root / "lean").rglob("*.lean"))
sources = [p for p in sources if ".lake" not in p.parts]
for path in sources:
    if re.search(r"^\s*(?:axiom|sorry|admit)\b", path.read_text(encoding="utf-8"), re.M):
        raise SystemExit(f"unproved declaration: {path}")
subprocess.run(["lake", "build"], cwd=root / "lean", check=True)
audit = subprocess.check_output(["lake", "env", "lean", "AxiomAudit.lean"],
                                cwd=root / "lean", text=True)
print(audit)
if "sorryAx" in audit:
    raise SystemExit("admitted proof in dependency closure")
allowed = {"propext", "Classical.choice", "Quot.sound"}
for names in re.findall(r"depends on axioms:\s*\[([^]]*)\]", audit):
    unknown = set(re.findall(r"[A-Za-z_][\w.]*", names)) - allowed
    if unknown:
        raise SystemExit(f"non-kernel axioms: {sorted(unknown)}")
commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
digest = hashlib.sha256()
for path in sources:
    digest.update(path.relative_to(root).as_posix().encode() + b"\0" + path.read_bytes())
proofs = ["ProofAppendOnly", "ProofMerkleTree", "ProofDeterministicReplay", "ProofDenseMap",
          "ProofHLC", "ProofApprovalIdempotence", "ProofToolCallIsolation"]
report = {"schema": "heraclitus.proof-status.v1", "commit": commit,
          "source_sha256": digest.hexdigest(), "lean": "4.15.0",
          "scope": "reference_models_only; Rust refinement is not established",
          "proofs": {p: {"status": "NOT_VERIFIED", "model_status": "CHECKED"} for p in proofs}}
args.out.parent.mkdir(parents=True, exist_ok=True)
args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
