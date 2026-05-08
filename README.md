# MCP-Native Identity-Bound Governance — Paper 9

**Agent Governance Series · Paper 9**

Transparent APB enforcement at the Model Context Protocol layer.
Any MCP-compatible LLM agent can be brought under the governance stack
of Papers 0–8 without a single line of agent-code modification.

[![arXiv](https://img.shields.io/badge/arXiv-pending-orange)](https://arxiv.org)
[![Series](https://img.shields.io/badge/Series-P0--P9-lightgrey)](https://agentcontrolprotocol.xyz/research.html)

---

## What this paper does

**Central question:** how do you deploy the Accountability Proof Block of
Paper 8 to agents you do not control or cannot modify (Claude Code, Cursor,
Cline, custom MCP-speaking systems)?

**Central answer:** intercept at the MCP protocol layer. A governance
proxy sits between the agent and any MCP server, runs the P0--P8 stack on
the tool-call trace, and emits an APB-required protocol message when a
persistent halt is reached. The agent's principal signs an APB and the
proxy resumes, denies, or recalibrates per the signed decision.

**Three theorems:**

| # | Theorem | Verified by |
|---|---------|-------------|
| T9.1 | Transparency Invariance | Exp E1: identical traces when no halt occurs |
| T9.2 | Halt Latency Bound | Exp E1: per-call overhead measured |
| T9.3 | Multi-Hop Authority Propagation | Exp E3: A2A delegation with originator binding |

---

## Repository structure

```
proxy/                  ← P9 NEW: MCP-aware governance proxy
  mcp_interceptor.py    JSON-RPC middleware for tools/call
  governed_server.py    Wraps any MCP server with P7+P8 stack
  protocol_extension.py APB-required, APB-response, APB-rejected messages
  transport/{stdio,sse}.py
  toy_server.py         5-tool deterministic MCP server (for tests + Exp E1)
client/                 ← P9 NEW: own MCP client (Ollama-backed) for Exp E2
agent/                  ← Frozen baseline from P7+P8
  principal.py          Principal Set P, ed25519 keypairs, registry
  mock_llm.py / live_llm.py / orchestrator.py
stack/                  ← Frozen baseline from P7+P8
  apb.py / apb_verifier.py / governance_layer.py   (P8 modules)
  acp_gate.py / iml_monitor.py / ram_gate.py / recovery_loop.py   (P7 modules)
iml/, baselines/        ← Frozen baseline from P7
experiments/
  smoke_test_mcp.py     Sprint 0 gate
  exp_e1_overhead.py    Latency overhead under proxy
  exp_e2_real_agent.py  Ollama agent with custom MCP client
  exp_e3_a2a.py         Multi-hop delegation with APB
  exp_e4_stress.py      Concurrency stress
tests/                  61 inherited unit tests + new proxy tests
results/                Experimental outputs (committed)
paper/                  main.tex, references.bib, tables, main.pdf
```

---

## Reproducing the results

```bash
# 1. Install
pip install -r requirements.txt
ollama pull mistral:7b deepseek-r1:8b gemma4:latest qwen2.5:7b llama3.2:3b

# 2. Smoke test (verifies MCP SDK + toy server)
python experiments/smoke_test_mcp.py

# 3. Run unit tests
pytest tests/ -v

# 4. Experiments (when implemented)
python experiments/exp_e1_overhead.py
python experiments/exp_e2_real_agent.py
python experiments/exp_e3_a2a.py
python experiments/exp_e4_stress.py

# 5. Build paper
cd paper && pdflatex main && bibtex main && pdflatex main && pdflatex main
```

---

## Independence from prior work

This repository reproduces the entire P9 contribution end-to-end without
external dependencies on the P7 or P8 repositories. The frozen-baseline
modules (`agent/`, `stack/{acp,iml,ram,recovery,apb,apb_verifier,governance_layer}`,
`iml/`, `baselines/`) are duplicated here from the P7 and P8 implementations
and are not modified. New code lives under `proxy/`, `client/`, and the
`experiments/` orchestrators.

The four P9 experiments (`exp_e1`–`exp_e4`) generate fresh evidence; no
data is reused from P7 or P8.

---

## Citation

```bibtex
@misc{fernandez2026mcp,
  author       = {Marcelo Fernandez},
  title        = {{MCP}-Native Identity-Bound Governance: Transparent {APB}
                  Enforcement at the Protocol Layer for {LLM} Agents},
  year         = {2026},
  howpublished = {arXiv preprint},
}
```

## License

MIT — see `LICENSE`.
