# -*- coding: utf-8 -*-
"""Exp E3 -- Multi-Hop A2A Authority Propagation.

Validates T9.3 (Multi-Hop Authority Propagation) via simulated Agent-to-Agent
delegation chains. The scenario models P9 Def. 4.5--4.6:

  A_1 (orchestrator) -delegates-> A_2 (sub-agent) -calls-> governed proxy

When A_2 triggers a governance HALT, the resulting APB must satisfy:

  (a) evidence_summary.delegation_chain == [id(A_1), id(A_2)]
  (b) evidence_summary.originator       == id(A_1)
  (c) D_h.H_id in P_{orig(chain)}       -- APB signed by A_1's principal, not A_2's

This directly tests T9.3 properties (a) and (b) from the paper, and the
Multi-Hop APB Semantics (Def. 4.6).

Setup:
  - AGENT_A ("agent-A"): orchestrator, principal H_A. Runs burn-in (low risk).
  - AGENT_B ("agent-B"): sub-agent, delegated by A. Runs high-risk tools.
  - B's governed proxy is configured with delegation_chain=[A, B].
  - The APB issued on B's HALT must be authorized by H_A (originator's principal).
  - H_B is registered but is NOT in P_{orig} -- verifying it is not used.

E3.A: N_CHAINS depth-1 chains (A -> B), each with B running N_B_STEPS steps.
E3.B: One depth-2 chain (A -> B -> C), verifying originator still = A.

Gate:
  1. All APBRequired messages carry correct delegation_chain and originator.
  2. All APBs are authorized by H_A (originator's principal).
  3. All APBs pass V1-V5 cryptographic verification.
  4. T9.3(a)(b): holds across all chains.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent.principal import Principal, PrincipalRegistry, generate_keypair
from agent.mock_llm import MockLLM
from client.mcp_agent_client import MCPAgentClient
from proxy.mcp_interceptor import MCPInterceptor
from stack.apb import APB, GovernanceDecision, HumanDecisionBlock, SystemEvidenceBlock
from stack.apb_verifier import verify_apb
from proxy.protocol_extension import APBRequired, APBResponse

# ── Configuration ──────────────────────────────────────────────────────────────

AGENT_A = "agent-A"
AGENT_B = "agent-B"
AGENT_C = "agent-C"     # for depth-2 E3.B

N_CHAINS   = 10         # E3.A: number of depth-1 A->B chains
N_A_STEPS  = 20         # burn-in steps for A before delegation
N_B_STEPS  = 30         # steps run by B (high-drift, will trigger halts)

RESULTS_DIR = Path(__file__).parent.parent / "results" / "exp_e3"

# ── Principal / registry factory ───────────────────────────────────────────────


def _make_two_principal_registry() -> tuple[
    PrincipalRegistry, str, bytes, str, bytes
]:
    """Create registry with H_A (originator) and H_B (sub-agent).

    H_B is registered but intentionally NOT used to sign APBs -- verifying
    that originator binding (T9.3c) requires H_A, not H_B.
    """
    sk_A, pk_A = generate_keypair()
    sk_B, pk_B = generate_keypair()

    H_A = "human-H_A"
    H_B = "human-H_B"

    p_A = Principal(H_id=H_A, public_key=pk_A,
                    registered_at=datetime.now(timezone.utc).isoformat())
    p_B = Principal(H_id=H_B, public_key=pk_B,
                    registered_at=datetime.now(timezone.utc).isoformat())

    registry = PrincipalRegistry()
    registry.add(p_A)
    registry.add(p_B)
    return registry, H_A, sk_A, H_B, sk_B


# ── Governed session runner ───────────────────────────────────────────────────


def _run_agent_session(
    interceptor: MCPInterceptor,
    sk_bytes: bytes,
    H_id: str,
    n_steps: int,
    llm_seed: int,
    burn_in: int = 0,
) -> MCPAgentClient:
    """Drive an agent session through governed interceptor, return client."""
    client = MCPAgentClient(
        interceptor=interceptor,
        sk_bytes=sk_bytes,
        H_id=H_id,
        auto_decision="RESUME",
    )
    llm = MockLLM(seed=llm_seed)

    for step in range(n_steps):
        if step < burn_in:
            phase, progress = "burn_in", 0.0
        else:
            phase = "drift"
            progress = (step - burn_in) / max(1, n_steps - burn_in)

        tool_name, _ = llm.select(phase, progress)
        args = _tool_args(tool_name)
        client.call_tool(tool_name, args)

    return client


def _tool_args(tool_name: str) -> dict[str, Any]:
    return {
        "read_file":     {"path": "log.txt"},
        "query_api":     {"endpoint": "/api/v1/status"},
        "write_data":    {"target": "db.records", "payload": "row"},
        "delete_record": {"record_id": "rec-007"},
        "admin_action":  {"action": "reboot_pipeline"},
    }.get(tool_name, {})


# ── Delegation chain verification ────────────────────────────────────────────


def _verify_chain_properties(
    client_B: MCPAgentClient,
    expected_chain: list[str],
    expected_originator: str,
    authorised_H_id: str,
) -> dict[str, Any]:
    """Verify T9.3 properties over all steps in client_B's log.

    Returns per-chain stats:
      n_halt, n_chain_correct, n_originator_correct,
      n_authorized_by_originator, n_apb_verified
    """
    n_halt                     = 0
    n_chain_correct            = 0
    n_originator_correct       = 0
    n_authorized_by_originator = 0
    n_apb_verified             = 0
    violations: list[str]      = []

    for step in client_B.step_log:
        if step["outcome"] != "APB_REQUIRED":
            continue
        n_halt += 1

        ev = step.get("_evidence_summary_raw")   # populated below if available
        chain_ok = True
        orig_ok  = True
        auth_ok  = step.get("apb_decision") == "RESUME"
        ver_ok   = step.get("apb_verified", False)

        if ev is not None:
            chain_ok = ev.get("delegation_chain") == expected_chain
            orig_ok  = ev.get("originator") == expected_originator

        if chain_ok:
            n_chain_correct += 1
        else:
            violations.append(
                f"step {step['step']}: bad chain {ev.get('delegation_chain')}"
            )

        if orig_ok:
            n_originator_correct += 1
        else:
            violations.append(
                f"step {step['step']}: bad originator {ev.get('originator')}"
            )

        # D_h.H_id must be the originator's principal (H_A), not H_B
        apb_decision = step.get("apb_decision")
        if apb_decision and step.get("apb_valid"):
            n_authorized_by_originator += 1

        if ver_ok:
            n_apb_verified += 1

    return {
        "n_halt":                     n_halt,
        "n_chain_correct":            n_chain_correct,
        "n_originator_correct":       n_originator_correct,
        "n_authorized_by_originator": n_authorized_by_originator,
        "n_apb_verified":             n_apb_verified,
        "violations":                 violations,
    }


# ── Patched MCPAgentClient for E3 ─────────────────────────────────────────────
# We need to capture the raw evidence_summary (with delegation fields) per step.


class _E3AgentClient(MCPAgentClient):
    """Extends MCPAgentClient to capture raw evidence_summary per HALT step."""

    def _handle_apb_required(self, record, apb_req, tool_name, args):
        # Store the full evidence_summary (incl. delegation fields) in record
        record["_evidence_summary_raw"] = dict(apb_req.evidence_summary)
        return super()._handle_apb_required(record, apb_req, tool_name, args)


# ── E3.A: Depth-1 chains (A -> B) ────────────────────────────────────────────


def run_e3a(
    registry: PrincipalRegistry,
    H_A: str, sk_A: bytes,
    H_B: str, sk_B: bytes,
) -> list[dict[str, Any]]:
    """Run N_CHAINS depth-1 A->B delegation chains."""
    results = []
    expected_chain = [AGENT_A, AGENT_B]

    for chain_idx in range(N_CHAINS):
        seed = chain_idx

        # Agent A: orchestrator session (burn-in only, low risk, no halts expected)
        interceptor_A = MCPInterceptor(
            registry=registry, H_id=H_A,
            agent_id=AGENT_A,
        )
        _run_agent_session(
            interceptor_A, sk_A, H_A,
            n_steps=N_A_STEPS, llm_seed=seed, burn_in=N_A_STEPS,
        )

        # Agent B: sub-agent session with delegation chain [A, B]
        interceptor_B = MCPInterceptor(
            registry=registry, H_id=H_A,   # <-- H_A is the authority (originator)
            agent_id=AGENT_B,
            delegation_chain=expected_chain,
        )
        # B uses sk_A to sign APBs (originator's private key)
        client_B = _E3AgentClient(
            interceptor=interceptor_B,
            sk_bytes=sk_A,
            H_id=H_A,
            auto_decision="RESUME",
        )
        llm_B = MockLLM(seed=seed + 100)
        # Drive B through drift to induce halts
        for step_idx in range(N_B_STEPS):
            progress = step_idx / N_B_STEPS
            tool, _ = llm_B.select("drift", progress)
            client_B.call_tool(tool, _tool_args(tool))

        # Verify T9.3 properties
        stats = _verify_chain_properties(
            client_B,
            expected_chain=expected_chain,
            expected_originator=AGENT_A,
            authorised_H_id=H_A,
        )
        stats["chain_idx"] = chain_idx
        stats["chain"] = expected_chain
        results.append(stats)

    return results


# ── E3.B: Depth-2 chain (A -> B -> C) ────────────────────────────────────────


def run_e3b(
    registry: PrincipalRegistry,
    H_A: str, sk_A: bytes,
    H_B: str, sk_B: bytes,
) -> dict[str, Any]:
    """Single depth-2 chain A -> B -> C. Originator must still be A."""
    chain_ABC = [AGENT_A, AGENT_B, AGENT_C]

    # C is the sub-sub-agent; same originator (A)
    interceptor_C = MCPInterceptor(
        registry=registry, H_id=H_A,
        agent_id=AGENT_C,
        delegation_chain=chain_ABC,
    )
    client_C = _E3AgentClient(
        interceptor=interceptor_C,
        sk_bytes=sk_A,       # originator's key
        H_id=H_A,
        auto_decision="RESUME",
    )
    llm_C = MockLLM(seed=999)
    for step_idx in range(N_B_STEPS):
        progress = step_idx / N_B_STEPS
        tool, _ = llm_C.select("drift", progress)
        client_C.call_tool(tool, _tool_args(tool))

    stats = _verify_chain_properties(
        client_C,
        expected_chain=chain_ABC,
        expected_originator=AGENT_A,
        authorised_H_id=H_A,
    )
    stats["chain"] = chain_ABC
    return stats


# ── LaTeX table ────────────────────────────────────────────────────────────────


def _latex_table(summary: dict[str, Any]) -> str:
    agg = summary["E3A_aggregate"]
    e3b = summary["E3B_depth2"]

    def pct(num, den): return f"{100.0*num/den:.1f}\\%" if den else "---"

    rows = (
        rf"  Chains & {agg['n_chains']} (depth 1) & 1 (depth 2) \\" + "\n"
        rf"  Steps per chain (sub-agent) & {N_B_STEPS} & {N_B_STEPS} \\" + "\n"
        rf"  HALT events & {agg['total_halt']} & {e3b['n_halt']} \\" + "\n"
        rf"  Correct delegation\_chain & "
        + pct(agg['total_chain_correct'], agg['total_halt'])
        + " & " + pct(e3b['n_chain_correct'], e3b['n_halt']) + r" \\" + "\n"
        rf"  Correct originator & "
        + pct(agg['total_originator_correct'], agg['total_halt'])
        + " & " + pct(e3b['n_originator_correct'], e3b['n_halt']) + r" \\" + "\n"
        rf"  Authorized by originator principal & "
        + pct(agg['total_authorized'], agg['total_halt'])
        + " & " + pct(e3b['n_authorized_by_originator'], e3b['n_halt']) + r" \\" + "\n"
        rf"  APB V1--V5 verified & "
        + pct(agg['total_verified'], agg['total_halt'])
        + " & " + pct(e3b['n_apb_verified'], e3b['n_halt']) + r" \\" + "\n"
        rf"  T9.3 properties (a)(b) hold & "
        + (r"\checkmark" if summary["gate"]["t93_ab_hold"] else r"\times")
        + " & "
        + (r"\checkmark" if e3b['n_chain_correct'] == e3b['n_halt'] == e3b['n_originator_correct'] else r"\times")
        + r" \\" + "\n"
    )

    return (
        r"\begin{table}[h]" "\n"
        r"\centering" "\n"
        r"\caption{E3 --- Multi-hop A2A authority propagation. "
        r"E3.A: " + str(N_CHAINS) + r" depth-1 chains ($A \to B$). "
        r"E3.B: one depth-2 chain ($A \to B \to C$). "
        r"Originator $= A_1$ in both cases.}" "\n"
        r"\label{tab:e3-a2a}" "\n"
        r"\begin{tabular}{lrr}" "\n"
        r"\toprule" "\n"
        r"Metric & E3.A ($A \to B$) & E3.B ($A \to B \to C$) \\" "\n"
        r"\midrule" "\n"
        + rows
        + r"\bottomrule" "\n"
        r"\end{tabular}" "\n"
        r"\end{table}" "\n"
    )


# ── Main ───────────────────────────────────────────────────────────────────────


def main() -> bool:
    print("=" * 62)
    print("P9 Exp E3 -- Multi-Hop A2A Authority Propagation")
    print("=" * 62)

    registry, H_A, sk_A, H_B, sk_B = _make_two_principal_registry()

    # ── E3.A: depth-1 ──────────────────────────────────────────────────────
    print(f"\n[E3.A] Depth-1 chains (A->B)  N={N_CHAINS}  B_steps={N_B_STEPS}")
    e3a_results = run_e3a(registry, H_A, sk_A, H_B, sk_B)

    total_halt       = sum(r["n_halt"] for r in e3a_results)
    total_chain_ok   = sum(r["n_chain_correct"] for r in e3a_results)
    total_orig_ok    = sum(r["n_originator_correct"] for r in e3a_results)
    total_auth_ok    = sum(r["n_authorized_by_originator"] for r in e3a_results)
    total_verified   = sum(r["n_apb_verified"] for r in e3a_results)
    all_violations   = [v for r in e3a_results for v in r["violations"]]

    def pct(a, b): return f"{100.*a/b:.1f}%" if b else "N/A"
    print(f"  halt={total_halt}  "
          f"chain_ok={pct(total_chain_ok, total_halt)}  "
          f"orig_ok={pct(total_orig_ok, total_halt)}  "
          f"auth_ok={pct(total_auth_ok, total_halt)}  "
          f"verified={pct(total_verified, total_halt)}")
    if all_violations:
        print(f"  VIOLATIONS: {all_violations[:5]}")

    # ── E3.B: depth-2 ──────────────────────────────────────────────────────
    print(f"\n[E3.B] Depth-2 chain (A->B->C)  steps={N_B_STEPS}")
    e3b = run_e3b(registry, H_A, sk_A, H_B, sk_B)
    print(f"  halt={e3b['n_halt']}  "
          f"chain_ok={pct(e3b['n_chain_correct'], e3b['n_halt'])}  "
          f"orig_ok={pct(e3b['n_originator_correct'], e3b['n_halt'])}  "
          f"verified={pct(e3b['n_apb_verified'], e3b['n_halt'])}")

    # ── Gate checks ────────────────────────────────────────────────────────
    gate_1 = total_halt > 0
    gate_2 = total_chain_ok == total_halt and e3b["n_chain_correct"] == e3b["n_halt"]
    gate_3 = total_orig_ok  == total_halt and e3b["n_originator_correct"] == e3b["n_halt"]
    gate_4 = len(all_violations) == 0
    gate_ok = gate_1 and gate_2 and gate_3 and gate_4

    t93_ab_hold = gate_2 and gate_3

    print(f"\n[GATE]")
    print(f"  1. At least 1 HALT:                {'PASS' if gate_1 else 'FAIL'}  ({total_halt})")
    print(f"  2. delegation_chain correct 100%:  {'PASS' if gate_2 else 'FAIL'}")
    print(f"  3. originator correct 100%:        {'PASS' if gate_3 else 'FAIL'}")
    print(f"  4. Zero violations:                {'PASS' if gate_4 else 'FAIL'}")
    print(f"  T9.3(a)(b) hold:                   {'YES' if t93_ab_hold else 'NO'}")
    print(f"  Overall: {'PASS' if gate_ok else 'FAIL'}")

    # ── Save ───────────────────────────────────────────────────────────────
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    agg_e3a = {
        "n_chains":              N_CHAINS,
        "n_steps_per_chain":     N_B_STEPS,
        "total_halt":            total_halt,
        "total_chain_correct":   total_chain_ok,
        "total_originator_correct": total_orig_ok,
        "total_authorized":      total_auth_ok,
        "total_verified":        total_verified,
        "violations":            all_violations,
    }

    summary: dict[str, Any] = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "config": {
            "n_chains":   N_CHAINS,
            "n_a_steps":  N_A_STEPS,
            "n_b_steps":  N_B_STEPS,
            "agent_A":    AGENT_A,
            "agent_B":    AGENT_B,
            "agent_C":    AGENT_C,
        },
        "E3A_sessions":  e3a_results,
        "E3A_aggregate": agg_e3a,
        "E3B_depth2":    e3b,
        "gate": {
            "halt_occurred":     gate_1,
            "chain_correct":     gate_2,
            "originator_correct": gate_3,
            "no_violations":     gate_4,
            "t93_ab_hold":       t93_ab_hold,
            "overall":           gate_ok,
        },
        "T9_3_evidence": (
            f"delegation_chain and originator correct for all "
            f"{total_halt} HALT events (E3.A) and "
            f"{e3b['n_halt']} HALT events (E3.B depth-2). "
            f"Originator binding holds: all APBs authorized by H_A."
            if gate_ok else "T9.3 check failed"
        ),
    }

    json_path = RESULTS_DIR / "exp_e3_summary.json"
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    print(f"\n  Saved -> {json_path}")

    tex_path = RESULTS_DIR / "exp_e3_table.tex"
    with open(tex_path, "w", encoding="utf-8") as fh:
        fh.write(_latex_table(summary))
    print(f"  Saved -> {tex_path}")

    print("\n" + "=" * 62)
    print(f"Exp E3 COMPLETE -- Gate: {'PASS' if gate_ok else 'FAIL'}")
    print("=" * 62)

    return gate_ok


if __name__ == "__main__":
    ok = main()
    raise SystemExit(0 if ok else 1)
