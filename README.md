# MCP-Native Identity-Bound Governance — Paper 9

**Agent Governance Series · Paper 9**

Transparent APB enforcement at the Model Context Protocol layer.
Any MCP-compatible LLM agent can be brought under the governance stack
of Papers 0–8 without a single line of agent-code modification.

[![arXiv](https://img.shields.io/badge/arXiv-pending-orange)](https://arxiv.org)
[![Zenodo](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.20162878-blue)](https://doi.org/10.5281/zenodo.20162878)
[![Series](https://img.shields.io/badge/Series-P0--P9-lightgrey)](https://agentcontrolprotocol.xyz/research.html)
[![Tests](https://img.shields.io/badge/tests-92%2F92-brightgreen)](#test-coverage)

---

## What this paper does

**Central question:** how do you deploy the Accountability Proof Block of
Paper 8 to agents you do not control or cannot modify (Claude Code, Cursor,
Cline, custom MCP-speaking systems)?

**Central answer:** intercept at the MCP protocol layer. A governance
proxy sits between the agent and any MCP server, runs the P0–P8 stack on
the tool-call trace, and emits an APB-required protocol message when a
persistent halt is reached. The agent's principal signs an APB and the
proxy resumes, denies, or recalibrates per the signed decision.

**Three theorems:**

| # | Theorem | Result |
|---|---------|--------|
| T9.1 | Transparency Invariance — non-halt path observationally equivalent to direct connection | Windowed P95 = 51.8 µs << 10 ms gate ✓ |
| T9.2 | Halt Latency Bound — governance event propagates within Δ_net + Δ_verify + Δ_policy | HALT pipeline mean = 57 µs (Δ_net = 0) ✓ |
| T9.3 | Multi-Hop Authority Propagation — originator binding in A2A chains | 334 HALTs across depths 1–5, 100% originator=chain[0] ✓ |

---

## Experimental results

| Exp | Scope | Key result |
|-----|-------|------------|
| **E1 — Latency overhead** | 10,000 ADMIT + 1,000 HALT calls | Windowed O(1) P95 = 51.8 µs; HALT mean = 57 µs |
| **E2 — Real-agent APB** | 5 seeds × 200 steps (MockLLM) | 310 HALT / 21 DENY / 100% APB validity; T9.1 HOLD |
| **E3 — Multi-hop A2A** | Depths 1–5, 5 runs/depth × 30 steps | 334 HALTs, 100% originator binding; T9.3 HOLD |
| **E4 — Concurrency stress** | N∈{1,4,16,64} threads; N∈{1,4,8,16} processes | 0 exceptions, 100% APB validity across all N |
| **E5 — Security adversarial suite** | 5 attack vectors | 0% adversary success rate; all 5 attacks rejected |

**APB verification gate**: 100% of all 344 APBs issued across E2+E3 pass V1–V5 (signature, principal, active, temporal, event-uniqueness).

---

## Security adversarial suite (E5)

| Attack | Target | Rejection predicate |
|--------|--------|-------------------|
| A1 — Wrong-key signing | V1 (signature validity) | `INVALID_SIGNATURE` |
| A2 — Evidence tampering | Evidence integrity check | `does not match issued evidence` |
| A3 — APB replay | V5 (event uniqueness) | `unknown evidence_id` |
| A4 — Revoked principal | V3 (principal active) | `PRINCIPAL_REVOKED` |
| A5 — Authority substitution (A2A) | P9 §4.7 authority confinement | `authority confinement violation` |

---

## Repository structure

```
proxy/                        ← P9 NEW: MCP-aware governance proxy
  mcp_interceptor.py          JSON-RPC middleware (IML→RAM→Recovery→APBRequired)
  governed_server.py          Wraps any MCP server with P7+P8 governance stack
  protocol_extension.py       p9/apbRequired, p9/apbResponse, p9/apbRejected
  transport/{stdio,sse}.py    Async JSON-RPC helpers
  toy_server.py               5-tool deterministic MCP server
client/                       ← P9 NEW: in-process MCP agent session driver
  mcp_agent_client.py         Handles ADMIT/APBRequired→sign→RESUME/DENY paths
agent/                        ← Frozen baseline from P7+P8
  principal.py                Principal Set P, ed25519 keypairs, PrincipalRegistry
  mock_llm.py                 Deterministic LLM (escalating tool selection)
  live_llm.py / orchestrator.py
stack/                        ← Frozen baseline from P7+P8
  apb.py / apb_verifier.py    APB construction + V1–V5 verification
  governance_layer.py         GovernanceLayer orchestrator
  iml_monitor.py              O(n) IML drift estimator (E_t, E_c, E_l + EMA)
  iml_monitor_windowed.py     ← P9 NEW: O(1) WindowedIMLMonitor (W=100)
  ram_gate.py / recovery_loop.py / acp_gate.py
iml/, baselines/              ← Frozen baseline from P7
experiments/
  smoke_test_mcp.py           Sprint 0 gate (PASSED)
  exp_e1_overhead.py          Latency overhead: passthrough vs governed (O(n) and O(1))
  exp_e2_real_agent.py        Real-agent APB: 5 seeds × 200 steps
  exp_e3_a2a.py               Multi-hop A2A: depths 1–5, originator binding
  exp_e4_stress.py            Concurrency: threads + processes
  exp_e5_adversarial.py       Security adversarial suite: 5 attack vectors
tests/
  test_apb.py / test_apb_verifier.py / test_governance_layer.py
  test_principal.py           ← 61 inherited from P8
  test_proxy_interceptor.py   ← 31 new P9 proxy tests
results/
  exp_e1/ exp_e2/ exp_e3/ exp_e4/ exp_e5/   ← JSON + LaTeX tables
paper/
  main.tex                    20-page paper (0 LaTeX errors)
  main.pdf                    Compiled PDF
  references.bib
```

---

## Test coverage

```bash
pytest tests/ -q
# 92 passed in ~8s
# 61 inherited from P8 (APB, verifier, governance layer, principal)
# 31 new P9 tests (protocol extension, interceptor ADMIT/HALT/DENY, APB response, A2A)
```

---

## Reproducing the results

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Smoke test (verifies MCP SDK + toy server)
python experiments/smoke_test_mcp.py

# 3. Run unit tests (92/92 expected)
pytest tests/ -v

# 4. Run all experiments
python experiments/exp_e1_overhead.py       # ~30s
python experiments/exp_e2_real_agent.py     # ~15s (E2.B skipped if Ollama absent)
python experiments/exp_e3_a2a.py            # ~45s
python experiments/exp_e4_stress.py         # ~60s
python experiments/exp_e5_adversarial.py    # ~10s

# 5. Build paper PDF
cd paper
pdflatex main && bibtex main && pdflatex main && pdflatex main
# Output: main.pdf (20 pages, 0 errors)
```

**Optional (E2.B and live LLM):**
```bash
ollama pull mistral:7b
python experiments/exp_e2_real_agent.py     # E2.B will run if Ollama is available
```

---

## Independence from prior work

This repository reproduces the entire P9 contribution end-to-end without
external dependencies on the P7 or P8 repositories. The frozen-baseline
modules (`agent/`, `stack/{acp,iml,ram,recovery,apb,apb_verifier,governance_layer}`,
`iml/`, `baselines/`) are duplicated here from the P7 and P8 implementations
and are not modified. New code lives under `proxy/`, `client/`, `stack/iml_monitor_windowed.py`,
and the `experiments/` orchestrators.

All five P9 experiments (`exp_e1`–`exp_e5`) generate fresh evidence; no
data is reused from P7 or P8.

---

## Citation

```bibtex
@misc{fernandez2026mcp,
  author       = {Marcelo Fernandez},
  title        = {{MCP}-Native Identity-Bound Governance: Zero-Modification
                  Agent Oversight via Protocol-Layer Interception and
                  Multi-Hop Authority Propagation},
  year         = {2026},
  howpublished = {arXiv preprint},
}
```

## License

MIT — see `LICENSE`.
