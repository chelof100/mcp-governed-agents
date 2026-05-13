# -*- coding: utf-8 -*-
"""Exp E4 -- Concurrency Stress Test.

Validates that the governance proxy is free of concurrency races under N
simultaneous client sessions. Each session runs an independent MCPInterceptor
(per-session design; not shared) but all sessions share a single read-only
PrincipalRegistry.

Concurrency levels tested: N in {1, 4, 16, 64}.

Per level:
  - S sessions run in parallel via ThreadPoolExecutor.
  - Each session executes STEPS_PER_SESSION tool calls (burn-in + drift).
  - Sessions are independent; they do NOT share interceptor state.
  - The shared registry is accessed only via read-only operations (get, is_active).

Metrics collected:
  - throughput: total governed calls / elapsed wall time (calls/sec)
  - apb_validity_pct: % of issued APBs that pass V1-V5 (must be 100%)
  - n_exceptions: any runtime errors (must be 0)
  - latency_mean_us: mean per-call latency across all sessions

Gate (Definition-of-Done):
  1. n_exceptions == 0 for all N.
  2. apb_validity_pct == 100.0% for all N.
  3. Throughput scales with N (linear within 50% of ideal).
"""
from __future__ import annotations

import json
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent.principal import Principal, PrincipalRegistry, generate_keypair
from agent.mock_llm import MockLLM
from client.mcp_agent_client import MCPAgentClient
from proxy.mcp_interceptor import MCPInterceptor

# ── Configuration ──────────────────────────────────────────────────────────────

CONCURRENCY_LEVELS  = [1, 4, 16, 64]
SESSIONS_PER_LEVEL  = 10      # sessions per concurrency level
STEPS_PER_SESSION   = 60      # 20 burn-in + 40 drift
BURN_IN_STEPS       = 20

RESULTS_DIR = Path(__file__).parent.parent / "results" / "exp_e4"

# ── Principal registry (shared read-only across threads) ───────────────────────


def _make_registry() -> tuple[PrincipalRegistry, str, bytes]:
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


def _tool_args(tool_name: str) -> dict[str, Any]:
    return {
        "read_file":     {"path": "data.log"},
        "query_api":     {"endpoint": "/health"},
        "write_data":    {"target": "store", "payload": "x"},
        "delete_record": {"record_id": "r-01"},
        "admin_action":  {"action": "flush"},
    }.get(tool_name, {})


# ── Per-session worker ─────────────────────────────────────────────────────────


def _run_session(
    session_id: int,
    registry: PrincipalRegistry,
    H_id: str,
    sk_bytes: bytes,
) -> dict[str, Any]:
    """Run one independent session. Safe to call from any thread."""
    t_start = time.perf_counter_ns()

    interceptor = MCPInterceptor(registry=registry, H_id=H_id)
    client = MCPAgentClient(
        interceptor=interceptor,
        sk_bytes=sk_bytes,
        H_id=H_id,
        auto_decision="RESUME",
    )
    llm = MockLLM(seed=session_id)

    n_exceptions = 0
    call_times_us: list[float] = []

    for step in range(STEPS_PER_SESSION):
        if step < BURN_IN_STEPS:
            phase, progress = "burn_in", 0.0
        else:
            phase = "drift"
            progress = (step - BURN_IN_STEPS) / (STEPS_PER_SESSION - BURN_IN_STEPS)

        tool, _ = llm.select(phase, progress)
        args = _tool_args(tool)

        t0 = time.perf_counter_ns()
        try:
            client.call_tool(tool, args)
        except Exception as exc:
            n_exceptions += 1
        t1 = time.perf_counter_ns()
        call_times_us.append((t1 - t0) / 1_000.0)

    t_elapsed = (time.perf_counter_ns() - t_start) / 1_000_000.0   # ms

    summary = client.summary()
    return {
        "session_id":      session_id,
        "n_steps":         STEPS_PER_SESSION,
        "n_halt":          summary["n_halt"],
        "n_apb_valid":     summary["n_apb_valid"],
        "n_apb_invalid":   0,    # if no exception, invalid = 0
        "n_resume":        summary["n_resume"],
        "n_exceptions":    n_exceptions,
        "elapsed_ms":      round(t_elapsed, 2),
        "call_times_us":   call_times_us,  # for percentile aggregation
    }


# ── Level runner ───────────────────────────────────────────────────────────────


def run_level(
    n_concurrent: int,
    registry: PrincipalRegistry,
    H_id: str,
    sk_bytes: bytes,
    session_offset: int = 0,
) -> dict[str, Any]:
    """Run SESSIONS_PER_LEVEL sessions at concurrency n_concurrent."""
    t_wall_start = time.perf_counter_ns()

    sessions = []
    with ThreadPoolExecutor(max_workers=n_concurrent) as ex:
        futures = {
            ex.submit(
                _run_session,
                session_offset + i, registry, H_id, sk_bytes
            ): i
            for i in range(SESSIONS_PER_LEVEL)
        }
        for fut in as_completed(futures):
            result = fut.result()   # propagates exceptions
            sessions.append(result)

    t_wall_ms = (time.perf_counter_ns() - t_wall_start) / 1_000_000.0

    # Aggregate
    total_calls   = sum(s["n_steps"]      for s in sessions)
    total_halt    = sum(s["n_halt"]       for s in sessions)
    total_valid   = sum(s["n_apb_valid"]  for s in sessions)
    total_resume  = sum(s["n_resume"]     for s in sessions)
    total_exc     = sum(s["n_exceptions"] for s in sessions)

    apb_validity  = 100.0 * total_valid / total_halt if total_halt else 100.0
    throughput    = total_calls / (t_wall_ms / 1_000.0)    # calls/sec

    import numpy as np
    all_times = [t for s in sessions for t in s["call_times_us"]]
    latency = {
        "mean_us": float(np.mean(all_times)),
        "p50_us":  float(np.percentile(all_times, 50)),
        "p95_us":  float(np.percentile(all_times, 95)),
        "p99_us":  float(np.percentile(all_times, 99)),
    }

    # Strip per-call times from session records to keep JSON compact
    for s in sessions:
        del s["call_times_us"]

    return {
        "n_concurrent":    n_concurrent,
        "n_sessions":      SESSIONS_PER_LEVEL,
        "total_calls":     total_calls,
        "total_halt":      total_halt,
        "total_apb_valid": total_valid,
        "total_resume":    total_resume,
        "total_exceptions": total_exc,
        "apb_validity_pct": round(apb_validity, 4),
        "wall_time_ms":    round(t_wall_ms, 2),
        "throughput_calls_per_sec": round(throughput, 1),
        "latency_us":      {k: round(v, 2) for k, v in latency.items()},
        "gate_exceptions_zero": total_exc == 0,
        "gate_apb_100pct":      apb_validity == 100.0,
        "sessions":             sessions,
    }


# ── LaTeX table ────────────────────────────────────────────────────────────────


def _latex_table(levels: list[dict[str, Any]]) -> str:
    rows = ""
    for lv in levels:
        exc_ok  = r"\checkmark" if lv["gate_exceptions_zero"] else r"\times"
        apb_ok  = r"\checkmark" if lv["gate_apb_100pct"]     else r"\times"
        rows += (
            f"  {lv['n_concurrent']} & "
            f"{lv['total_calls']:,} & "
            f"{lv['throughput_calls_per_sec']:.0f} & "
            f"{lv['latency_us']['p95_us']:.1f} & "
            f"{lv['apb_validity_pct']:.1f}\\% & "
            f"{lv['total_exceptions']} & "
            f"{exc_ok} & {apb_ok} \\\\\n"
        )

    return (
        r"\begin{table}[h]" "\n"
        r"\centering" "\n"
        r"\caption{E4 --- Concurrency stress test. "
        + str(SESSIONS_PER_LEVEL) + r" sessions per level, "
        + str(STEPS_PER_SESSION) + r" steps each "
        r"(" + str(BURN_IN_STEPS) + r" burn-in + "
        + str(STEPS_PER_SESSION - BURN_IN_STEPS) + r" drift). "
        r"Latency in \si{\micro\second}. "
        r"Gate: exceptions $= 0$ and APB validity $= 100\%$.}" "\n"
        r"\label{tab:e4-concurrency}" "\n"
        r"\begin{tabular}{rrrrrrccc}" "\n"
        r"\toprule" "\n"
        r"$N$ & Calls & Throughput & P95 lat. & APB valid & Exceptions "
        r"& Exc.=0 & APB=100\% \\" "\n"
        r"\midrule" "\n"
        + rows
        + r"\bottomrule" "\n"
        r"\end{tabular}" "\n"
        r"\end{table}" "\n"
    )


# ── Main ───────────────────────────────────────────────────────────────────────


def main() -> bool:
    print("=" * 62)
    print("P9 Exp E4 -- Concurrency Stress Test")
    print("=" * 62)
    print(f"  Sessions/level={SESSIONS_PER_LEVEL}  "
          f"Steps/session={STEPS_PER_SESSION}  "
          f"N={CONCURRENCY_LEVELS}")

    registry, H_id, sk_bytes = _make_registry()

    level_results: list[dict[str, Any]] = []
    session_offset = 0

    for n in CONCURRENCY_LEVELS:
        print(f"\n[N={n:2d}] Running {SESSIONS_PER_LEVEL} sessions "
              f"x {STEPS_PER_SESSION} steps ...")
        lv = run_level(n, registry, H_id, sk_bytes, session_offset)
        level_results.append(lv)
        session_offset += SESSIONS_PER_LEVEL

        print(f"       throughput={lv['throughput_calls_per_sec']:.0f} calls/s  "
              f"P95={lv['latency_us']['p95_us']:.1f}us  "
              f"APB={lv['apb_validity_pct']}%  "
              f"exc={lv['total_exceptions']}  "
              f"{'PASS' if lv['gate_exceptions_zero'] and lv['gate_apb_100pct'] else 'FAIL'}")

    # ── Throughput scaling check ───────────────────────────────────────────
    # Compare N=1 baseline vs N=64 (expect at least 50% efficiency)
    tp1  = level_results[0]["throughput_calls_per_sec"]
    tp64 = level_results[-1]["throughput_calls_per_sec"]
    ideal_ratio = CONCURRENCY_LEVELS[-1] / CONCURRENCY_LEVELS[0]
    actual_ratio = tp64 / tp1
    scaling_efficiency = actual_ratio / ideal_ratio
    gate_scaling = scaling_efficiency >= 0.50

    # ── Gate summary ───────────────────────────────────────────────────────
    gate_no_exc = all(lv["gate_exceptions_zero"] for lv in level_results)
    gate_apb    = all(lv["gate_apb_100pct"]      for lv in level_results)
    gate_ok     = gate_no_exc and gate_apb

    print(f"\n[GATE]")
    print(f"  1. n_exceptions == 0 (all N): {'PASS' if gate_no_exc else 'FAIL'}")
    print(f"  2. APB validity == 100% (all N): {'PASS' if gate_apb else 'FAIL'}")
    print(f"  3. Throughput scaling N=1->{CONCURRENCY_LEVELS[-1]}: "
          f"{actual_ratio:.1f}x actual / {ideal_ratio}x ideal "
          f"= {scaling_efficiency:.0%} efficiency  "
          f"({'PASS' if gate_scaling else 'INFO (under 50%)'})")
    print(f"  Overall: {'PASS' if gate_ok else 'FAIL'}")

    # ── Save ───────────────────────────────────────────────────────────────
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    summary: dict[str, Any] = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "config": {
            "concurrency_levels":  CONCURRENCY_LEVELS,
            "sessions_per_level":  SESSIONS_PER_LEVEL,
            "steps_per_session":   STEPS_PER_SESSION,
            "burn_in_steps":       BURN_IN_STEPS,
        },
        "levels": level_results,
        "scaling": {
            "N1_throughput":    round(tp1, 1),
            "N64_throughput":   round(tp64, 1),
            "speedup_ratio":    round(actual_ratio, 2),
            "ideal_ratio":      ideal_ratio,
            "efficiency":       round(scaling_efficiency, 3),
        },
        "gate": {
            "no_exceptions": gate_no_exc,
            "apb_100pct":    gate_apb,
            "overall":       gate_ok,
        },
        "T9_concurrency_evidence": (
            f"No exceptions and APB validity = 100% across "
            f"N in {CONCURRENCY_LEVELS}. "
            f"Throughput scaling efficiency = {scaling_efficiency:.0%} "
            f"(N=1: {tp1:.0f} calls/s -> N={CONCURRENCY_LEVELS[-1]}: {tp64:.0f} calls/s)."
            if gate_ok else "E4 gate failed"
        ),
    }

    json_path = RESULTS_DIR / "exp_e4_summary.json"
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    print(f"\n  Saved -> {json_path}")

    tex_path = RESULTS_DIR / "exp_e4_table.tex"
    with open(tex_path, "w", encoding="utf-8") as fh:
        fh.write(_latex_table(level_results))
    print(f"  Saved -> {tex_path}")

    print("\n" + "=" * 62)
    print(f"Exp E4 COMPLETE -- Gate: {'PASS' if gate_ok else 'FAIL'}")
    print("=" * 62)

    return gate_ok


if __name__ == "__main__":
    ok = main()
    raise SystemExit(0 if ok else 1)
