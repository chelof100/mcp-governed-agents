# -*- coding: utf-8 -*-
"""Exp E2 -- Real-Agent APB End-to-End Validation.

Runs a full governed agent session (burn-in + drift) through MCPAgentClient,
which drives MCPInterceptor in-process. The agent is backed by MockLLM
(deterministic, reproducible) with an optional LiveLLM (Ollama) mode.

Two sub-experiments:

  E2.A -- MockLLM (deterministic, N_SEEDS seeds)
    Validates that:
      - Drift is induced by the escalating tool-selection distribution.
      - Governance HALT events occur and APBs are issued (APB_REQUIRED).
      - All issued APBs pass V1-V5 cryptographic verification.
      - Agent receives tool results after RESUME (T9.1 viability evidence).
      - DENY events are reported separately (permanent RAM-gate denial;
        no APB issued — distinguishable from the HALT->APB->RESUME path).

  E2.B -- LiveLLM (Ollama, single run, optional)
    Same checks on one real-LLM run. Skipped if Ollama is unavailable.

Governance outcome taxonomy (P9 §3.2):
  ADMIT:        Tool executed directly. Non-halt path (T9.1).
  APB_REQUIRED: Tool halted; human APB required. RESUME restores execution.
  DENY:         Tool permanently denied without APB opportunity.
                Occurs when RAM authority = DENY (not HALT). Different from
                APB_REQUIRED — no signature is requested or produced.
                DENY is a valid governance outcome, not a T9.1 violation.

Output:
  results/exp_e2/exp_e2_summary.json
  results/exp_e2/exp_e2_table.tex

Gate (Definition-of-Done):
  1. At least 1 HALT event (APB_REQUIRED) across all seeds.
  2. All issued APBs pass V1-V5 verification (100.0 % valid).
  3. All HALTs resolved via RESUME (T9.1 holds for cooperative governance).
  4. DENY count explicitly reported (informational; does not fail gate).
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

# ── Configuration ──────────────────────────────────────────────────────────────

N_SEEDS    = 5          # deterministic seeds for E2.A
N_BURN_IN  = 50         # burn-in steps per session
N_DRIFT    = 150        # drift steps per session
N_TOTAL    = N_BURN_IN + N_DRIFT   # 200 steps

LIVE_MODEL = "mistral:7b"    # Ollama model for E2.B (optional)
N_LIVE_STEPS = 80            # shorter run for E2.B (live LLM is slow)

RESULTS_DIR = Path(__file__).parent.parent / "results" / "exp_e2"

# ── Registry + keypair factory ─────────────────────────────────────────────────


def _make_principal() -> tuple[PrincipalRegistry, str, bytes]:
    sk_bytes, pk_bytes = generate_keypair()
    H_id = "human-H"
    principal = Principal(
        H_id=H_id,
        public_key=pk_bytes,
        registered_at=datetime.now(timezone.utc).isoformat(),
    )
    registry = PrincipalRegistry()
    registry.add(principal)
    return registry, H_id, sk_bytes


def _new_interceptor(registry: PrincipalRegistry, H_id: str) -> MCPInterceptor:
    return MCPInterceptor(registry=registry, H_id=H_id)


# ── Single-run driver ──────────────────────────────────────────────────────────


def run_mock_session(
    seed: int,
    registry: PrincipalRegistry,
    H_id: str,
    sk_bytes: bytes,
) -> dict[str, Any]:
    """Run one MockLLM session (N_BURN_IN + N_DRIFT steps). Returns summary."""
    interceptor = _new_interceptor(registry, H_id)
    client = MCPAgentClient(
        interceptor=interceptor,
        sk_bytes=sk_bytes,
        H_id=H_id,
        auto_decision="RESUME",
    )
    llm = MockLLM(seed=seed)

    for step in range(N_TOTAL):
        if step < N_BURN_IN:
            phase, progress = "burn_in", 0.0
        else:
            phase    = "drift"
            progress = (step - N_BURN_IN) / N_DRIFT

        tool_name, _ = llm.select(phase, progress)
        args = _default_args(tool_name)
        client.call_tool(tool_name, args)

    s = client.summary()
    s["seed"] = seed
    return s


def run_live_session(
    registry: PrincipalRegistry,
    H_id: str,
    sk_bytes: bytes,
    model: str = LIVE_MODEL,
    n_steps: int = N_LIVE_STEPS,
) -> dict[str, Any] | None:
    """Run one LiveLLM session. Returns None if Ollama unavailable."""
    try:
        import ollama
        ollama.list()   # raises if Ollama not running
    except Exception as exc:
        print(f"      [skip] Ollama unavailable: {exc}")
        return None

    try:
        from agent.live_llm import LiveLLM
    except ImportError as exc:
        print(f"      [skip] LiveLLM import failed: {exc}")
        return None

    burn_in = n_steps // 4
    drift   = n_steps - burn_in

    interceptor = _new_interceptor(registry, H_id)
    client = MCPAgentClient(
        interceptor=interceptor,
        sk_bytes=sk_bytes,
        H_id=H_id,
        auto_decision="RESUME",
    )
    live = LiveLLM(model=model, temperature=0.6)

    for step in range(n_steps):
        if step < burn_in:
            phase, progress = "burn_in", 0.0
        else:
            phase    = "drift"
            progress = (step - burn_in) / drift

        tool_name, _, _ = live.select_tool(phase, progress)
        args = _default_args(tool_name)
        client.call_tool(tool_name, args)

    s = client.summary()
    s["model"] = model
    return s


def _default_args(tool_name: str) -> dict[str, Any]:
    return {
        "read_file":     {"path": "data.log"},
        "query_api":     {"endpoint": "/status"},
        "write_data":    {"target": "db.table", "payload": "data"},
        "delete_record": {"record_id": "rec-001"},
        "admin_action":  {"action": "reset_pipeline"},
    }.get(tool_name, {})


# ── Aggregation ────────────────────────────────────────────────────────────────


def _aggregate(sessions: list[dict[str, Any]]) -> dict[str, Any]:
    n = len(sessions)
    def mean(key): return sum(s[key] for s in sessions) / n
    def total(key): return sum(s[key] for s in sessions)

    n_halt_total  = total("n_halt")
    n_valid_total = total("n_apb_valid")
    n_resume_total= total("n_resume")

    apb_validity_pct = (
        100.0 * n_valid_total / n_halt_total if n_halt_total else 0.0
    )

    t91_hold = all(s["T9_1_hold"] for s in sessions if s["n_halt"] > 0)

    d_first = [s["D_hat_at_first_halt"] for s in sessions
               if s["D_hat_at_first_halt"] is not None]
    d_first_mean = sum(d_first) / len(d_first) if d_first else None

    return {
        "n_sessions":         n,
        "n_steps_per_session": N_TOTAL,
        "total_steps":        total("n_total"),
        "total_admit":        total("n_admit"),
        "total_halt":         n_halt_total,
        "total_deny":         total("n_deny"),
        "total_resume":       n_resume_total,
        "total_apb_issued":   n_halt_total,
        "total_apb_valid":    n_valid_total,
        "total_apb_verified": total("n_apb_verified"),
        "apb_validity_pct":   round(apb_validity_pct, 4),
        "T9_1_hold":          t91_hold,
        "D_hat_first_halt_mean": round(d_first_mean, 4) if d_first_mean else None,
        "D_hat_final_mean":   round(mean("D_hat_final"), 4),
    }


# ── LaTeX table ────────────────────────────────────────────────────────────────


def _latex_table(summary: dict[str, Any]) -> str:
    agg = summary["E2A_aggregate"]
    live = summary.get("E2B_live")

    t91 = r"\checkmark" if agg["T9_1_hold"] else r"\times"
    apb_pct = f"{agg['apb_validity_pct']:.1f}\\%"

    deny_note = r"\textit{(no APB; perm. denial)}"
    rows = (
        rf"  Steps & {agg['total_steps']:,} & "
        + (rf"{live['n_total'] if live else '---'}" + r" \\") + "\n"
        rf"  ADMIT events & {agg['total_admit']:,} & --- \\" + "\n"
        rf"  HALT events (APBRequired) & {agg['total_halt']:,} & "
        + (rf"{live['n_halt'] if live else '---'}" + r" \\") + "\n"
        rf"  DENY events {deny_note} & {agg['total_deny']:,} & "
        + (rf"{live.get('n_deny', '---') if live else '---'}" + r" \\") + "\n"
        rf"  APB validity (V1--V5) & {apb_pct} & "
        + (r"100.0\%" if live and live['n_apb_valid'] == live['n_halt'] else "---") + r" \\" + "\n"
        rf"  RESUME resolutions & {agg['total_resume']:,} & "
        + (rf"{live['n_resume'] if live else '---'}" + r" \\") + "\n"
        rf"  $\hat{{D}}$ at first halt (mean) & {agg['D_hat_first_halt_mean']:.3f} & --- \\" + "\n"
        rf"  T9.1 Transparency Invariance & {t91} & "
        + (rf"{'\\checkmark' if live and live.get('T9_1_hold') else '---'}" + r" \\") + "\n"
    )

    return (
        r"\begin{table}[h]" "\n"
        r"\centering" "\n"
        r"\caption{E2 --- Real-agent APB end-to-end validation. "
        rf"E2.A: MockLLM, {agg['n_sessions']} seeds "
        rf"$\times$ {agg['n_steps_per_session']} steps "
        rf"({N_BURN_IN} burn-in + {N_DRIFT} drift). "
        r"E2.B: LiveLLM (" + (LIVE_MODEL if live else "skipped") + r").}" "\n"
        r"\label{tab:e2-real-agent}" "\n"
        r"\begin{tabular}{lrr}" "\n"
        r"\toprule" "\n"
        r"Metric & E2.A (MockLLM) & E2.B (LiveLLM) \\" "\n"
        r"\midrule" "\n"
        + rows
        + r"\bottomrule" "\n"
        r"\end{tabular}" "\n"
        r"\end{table}" "\n"
    )


# ── Main ───────────────────────────────────────────────────────────────────────


def main() -> bool:
    print("=" * 62)
    print("P9 Exp E2 -- Real-Agent APB End-to-End Validation")
    print("=" * 62)

    registry, H_id, sk_bytes = _make_principal()

    # ── E2.A: MockLLM sessions ─────────────────────────────────────────────
    print(f"\n[E2.A] MockLLM  seeds={N_SEEDS}  steps={N_TOTAL}  "
          f"(burn_in={N_BURN_IN} + drift={N_DRIFT})")
    mock_sessions: list[dict[str, Any]] = []
    for seed in range(N_SEEDS):
        s = run_mock_session(seed, registry, H_id, sk_bytes)
        mock_sessions.append(s)
        print(f"  seed={seed}: admit={s['n_admit']}  "
              f"halt(APB)={s['n_halt']}  "
              f"deny={s['n_deny']}  "
              f"apb_valid={s['n_apb_valid']}  "
              f"resume={s['n_resume']}  "
              f"D_hat_first={s['D_hat_at_first_halt']}  "
              f"D_final={s['D_hat_final']}")

    agg = _aggregate(mock_sessions)
    print(f"\n  Aggregate: admit={agg['total_admit']}  "
          f"halt(APB_REQUIRED)={agg['total_halt']}  "
          f"deny={agg['total_deny']}  "
          f"apb_valid={agg['apb_validity_pct']}%  "
          f"T9.1={'HOLD' if agg['T9_1_hold'] else 'VIOLATED'}")
    print(f"  Note: DENY = permanent RAM-gate denial; no APB issued.")
    print(f"        HALT = APB_REQUIRED; RESUME restores execution.")

    # Gate checks
    gate_1 = agg["total_halt"] > 0
    gate_2 = agg["apb_validity_pct"] == 100.0
    gate_3 = agg["T9_1_hold"]

    # ── E2.B: LiveLLM (optional) ───────────────────────────────────────────
    print(f"\n[E2.B] LiveLLM  model={LIVE_MODEL}  steps={N_LIVE_STEPS}")
    live_result = run_live_session(registry, H_id, sk_bytes)
    if live_result:
        print(f"  halt={live_result['n_halt']}  "
              f"apb_valid={live_result['n_apb_valid']}  "
              f"resume={live_result['n_resume']}  "
              f"D_final={live_result['D_hat_final']}")
    else:
        print("  Skipped (Ollama unavailable)")

    # ── Gate summary ───────────────────────────────────────────────────────
    gate_ok = gate_1 and gate_2 and gate_3
    deny_info = agg["total_deny"]
    print(f"\n[GATE]")
    print(f"  1. At least 1 HALT (APB_REQUIRED): {'PASS' if gate_1 else 'FAIL'}  "
          f"(total={agg['total_halt']})")
    print(f"  2. APB validity == 100.0%:         {'PASS' if gate_2 else 'FAIL'}  "
          f"({agg['apb_validity_pct']}%)")
    print(f"  3. T9.1 hold (all HALTs=RESUME):   {'PASS' if gate_3 else 'FAIL'}")
    print(f"  4. DENY events (INFO only):        {deny_info} events  "
          f"(permanent denial; no APB; not a T9.1 violation)")
    print(f"  Overall: {'PASS' if gate_ok else 'FAIL'}")

    # ── Save ───────────────────────────────────────────────────────────────
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    summary: dict[str, Any] = {
        "timestamp":      time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "config": {
            "n_seeds":     N_SEEDS,
            "n_burn_in":   N_BURN_IN,
            "n_drift":     N_DRIFT,
            "n_total":     N_TOTAL,
            "live_model":  LIVE_MODEL,
            "n_live_steps": N_LIVE_STEPS,
        },
        "E2A_sessions":  mock_sessions,
        "E2A_aggregate": agg,
        "E2B_live":      live_result,
        "gate": {
            "halt_occurred":       gate_1,
            "apb_100pct_valid":    gate_2,
            "T9_1_hold":           gate_3,
            "overall":             gate_ok,
        },
        "T9_1_evidence": (
            f"All {agg['total_halt']} HALT events resolved via signed APB; "
            f"agent received tool results after RESUME "
            f"-> T9.1 Transparency Invariance holds"
            if gate_ok else "T9.1 check failed"
        ),
    }

    json_path = RESULTS_DIR / "exp_e2_summary.json"
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    print(f"\n  Saved -> {json_path}")

    tex_path = RESULTS_DIR / "exp_e2_table.tex"
    with open(tex_path, "w", encoding="utf-8") as fh:
        fh.write(_latex_table(summary))
    print(f"  Saved -> {tex_path}")

    print("\n" + "=" * 62)
    print(f"Exp E2 COMPLETE -- Gate: {'PASS' if gate_ok else 'FAIL'}")
    print("=" * 62)

    return gate_ok


if __name__ == "__main__":
    ok = main()
    raise SystemExit(0 if ok else 1)
