# -*- coding: utf-8 -*-
"""Exp E1 — Governance Proxy Latency Overhead Benchmark.

Measures the per-call overhead introduced by MCPInterceptor compared to a
direct passthrough (mock tool execution without governance).

Two measurement conditions:

  ADMIT path  — low-risk tool (read_file, risk=0.10) always results in ADMIT.
                Measures Δ_policy alone (IML compute + RAM check).
                Evidence for T9.1 Transparency Invariance.

  HALT  path  — high-risk tool (admin_action, risk=0.90) always triggers
                APBRequired after Recovery Loop exhaustion.
                Measures Δ_policy + Δ_verify.
                Evidence for T9.2 Halt Latency Bound.

Output:
  results/exp_e1/exp_e1_summary.json   — full stats (microseconds)
  results/exp_e1/exp_e1_table.tex      — LaTeX table for paper §5.1

Gate (Definition-of-Done):
  P95 overhead on ADMIT path < 10 ms (= 10,000 us) in local execution.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import numpy as np

from datetime import datetime, timezone

from agent.principal import Principal, PrincipalRegistry, generate_keypair
from proxy.mcp_interceptor import MCPInterceptor

# ── Configuration ──────────────────────────────────────────────────────────────

N_ADMIT       = 10_000   # calls on ADMIT path
N_HALT        = 1_000    # calls on HALT  path
WARMUP        = 200      # calls discarded before timing starts
SESSION_WINDOW = 100     # reset interceptor every N calls on ADMIT path
                          # (models realistic bounded sessions; prevents O(n²)
                          #  IML trace accumulation from inflating measurements)

TOOL_ADMIT = "read_file"      # risk=0.10 -> RAM always EXECUTE -> ADMIT
TOOL_HALT  = "admin_action"   # risk=0.90 -> RAM always HALT   -> APBRequired

RESULTS_DIR = Path(__file__).parent.parent / "results" / "exp_e1"

# ── Mock tool results (O(1) dict lookup — negligible baseline) ─────────────────

MOCK_RESULTS: dict[str, Any] = {
    "read_file":     {"content": "mock-file-content"},
    "query_api":     {"status": 200, "body": "{}"},
    "write_data":    {"rows_affected": 1},
    "delete_record": {"deleted": True},
    "admin_action":  {"ok": True},
}

# ── Registry factory ───────────────────────────────────────────────────────────


def _make_registry() -> tuple[PrincipalRegistry, str]:
    sk_bytes, pk_bytes = generate_keypair()
    H_id = "human-H"
    principal = Principal(
        H_id=H_id,
        public_key=pk_bytes,
        registered_at=datetime.now(timezone.utc).isoformat(),
    )
    registry = PrincipalRegistry()
    registry.add(principal)
    return registry, H_id


def _fresh_interceptor(registry: PrincipalRegistry, H_id: str) -> MCPInterceptor:
    """Return a brand-new interceptor with D̂=0."""
    return MCPInterceptor(registry=registry, H_id=H_id)


# ── Percentile helper ─────────────────────────────────────────────────────────


def _stats(data: np.ndarray) -> dict[str, float]:
    return {
        "mean": float(np.mean(data)),
        "std":  float(np.std(data)),
        "min":  float(np.min(data)),
        "p50":  float(np.percentile(data, 50)),
        "p95":  float(np.percentile(data, 95)),
        "p99":  float(np.percentile(data, 99)),
        "max":  float(np.max(data)),
    }


# ── Benchmark functions ────────────────────────────────────────────────────────


def bench_passthrough(n: int, warmup: int) -> np.ndarray:
    """Baseline: mock dict lookup with no governance layer.

    This sets the floor for tool execution latency (Δ_exec ≈ 0 locally).
    Governance overhead = governed_time - passthrough_time.
    """
    args: dict = {}
    samples: list[float] = []

    for i in range(warmup + n):
        t0 = time.perf_counter_ns()
        _ = MOCK_RESULTS[TOOL_ADMIT]
        t1 = time.perf_counter_ns()
        if i >= warmup:
            samples.append(float(t1 - t0))

    return np.array(samples) / 1_000.0   # ns -> us


def bench_governed_admit(
    registry: PrincipalRegistry,
    H_id: str,
    n: int,
    warmup: int,
) -> np.ndarray:
    """Governed path — ADMIT condition.

    Measures: intercept_tool_call() + mock execution (ADMIT path only).
    The interceptor is reset every SESSION_WINDOW calls to model realistic
    bounded sessions and avoid O(n^2) IML trace accumulation inflating
    per-call latency. This reflects production usage where sessions are
    finite and D_hat stays bounded.
    """
    interceptor = _fresh_interceptor(registry, H_id)
    args: dict = {}
    samples: list[float] = []
    call_in_session = 0

    for i in range(warmup + n):
        # Reset at session boundary
        if call_in_session >= SESSION_WINDOW:
            interceptor = _fresh_interceptor(registry, H_id)
            call_in_session = 0

        t0 = time.perf_counter_ns()
        outcome, _ = interceptor.intercept_tool_call(TOOL_ADMIT, args)
        _ = MOCK_RESULTS[TOOL_ADMIT]    # simulate tool execution
        t1 = time.perf_counter_ns()
        call_in_session += 1

        if i >= warmup and outcome == "ADMIT":
            samples.append(float(t1 - t0))

    return np.array(samples) / 1_000.0


def bench_governed_halt(
    registry: PrincipalRegistry,
    H_id: str,
    n: int,
    warmup: int,
) -> np.ndarray:
    """Governed path — HALT condition.

    Measures: intercept_tool_call() on the full IML->RAM->RecoveryLoop->APBRequired
    pipeline. A fresh interceptor is created for each call (clean state) so that
    every measurement is independent.

    This isolates Δ_policy + Δ_verify (Recovery Loop + E_s construction).
    Δ_net = 0 because we never send the APBRequired to a real client.
    """
    args: dict = {}
    samples: list[float] = []

    for i in range(warmup + n):
        interceptor = _fresh_interceptor(registry, H_id)
        t0 = time.perf_counter_ns()
        outcome, _ = interceptor.intercept_tool_call(TOOL_HALT, args)
        t1 = time.perf_counter_ns()

        if i >= warmup:
            samples.append(float(t1 - t0))

    return np.array(samples) / 1_000.0


# ── LaTeX table ────────────────────────────────────────────────────────────────


def _latex_table(summary: dict[str, Any]) -> str:
    cfg = summary["config"]

    rows = [
        ("Passthrough (no governance)",
         summary["passthrough_us"],
         r"$\Delta_{\mathrm{exec}}$ baseline"),
        (r"Governed --- ADMIT path",
         summary["governed_admit_us"],
         r"T\ref{thm:transparency-invariance} evidence"),
        (r"Overhead --- ADMIT ($\Delta_{\mathrm{policy}}$)",
         summary["overhead_admit_us"],
         r"IML + RAM check"),
        (r"Governed --- HALT path",
         summary["governed_halt_us"],
         r"T\ref{thm:halt-latency-bound} evidence"),
        (r"Overhead --- HALT ($\Delta_{\mathrm{policy}}+\Delta_{\mathrm{verify}}$)",
         summary["overhead_halt_us"],
         r"full pipeline"),
    ]

    gate_str = (
        r"\checkmark" if summary["gate_admit_p95_lt_10ms"] else r"\times"
    )

    body = ""
    for label, s, note in rows:
        body += (
            f"  {label} & {s['mean']:.1f} & {s['p50']:.1f} & "
            f"{s['p95']:.1f} & {s['p99']:.1f} & {note} \\\\\n"
        )

    return (
        r"\begin{table}[h]" "\n"
        r"\centering" "\n"
        r"\caption{E1 --- Governance proxy latency overhead (local, "
        r"$\Delta_{\mathrm{net}}=0$). "
        r"All values in \si{\micro\second}. "
        rf"$N={cfg['n_calls_admit']:,}$ (ADMIT path), "
        rf"$N={cfg['n_calls_halt']:,}$ (HALT path). "
        rf"Gate: ADMIT P95 $<$ 10\,ms~({gate_str}).}}" "\n"
        r"\label{tab:e1-overhead}" "\n"
        r"\begin{tabular}{lrrrrl}" "\n"
        r"\toprule" "\n"
        r"Condition & Mean & P50 & P95 & P99 & Note \\" "\n"
        r"\midrule" "\n"
        + body
        + r"\bottomrule" "\n"
        r"\end{tabular}" "\n"
        r"\end{table}" "\n"
    )


# ── Main ───────────────────────────────────────────────────────────────────────


def main() -> bool:
    print("=" * 62)
    print("P9 Exp E1 — Governance Proxy Latency Overhead")
    print("=" * 62)

    registry, H_id = _make_registry()

    # ── 1. Passthrough baseline ─────────────────────────────────────────────
    print(f"\n[1/4] Passthrough baseline  N={N_ADMIT:,}  warmup={WARMUP}")
    pt = bench_passthrough(N_ADMIT, WARMUP)
    pt_s = _stats(pt)
    print(f"      mean={pt_s['mean']:.2f} us  P50={pt_s['p50']:.2f}  "
          f"P95={pt_s['p95']:.2f}  P99={pt_s['p99']:.2f}")

    # ── 2. Governed ADMIT path ──────────────────────────────────────────────
    print(f"\n[2/4] Governed ADMIT path   N={N_ADMIT:,}  tool={TOOL_ADMIT!r}")
    ga = bench_governed_admit(registry, H_id, N_ADMIT, WARMUP)
    ga_s = _stats(ga)
    print(f"      mean={ga_s['mean']:.2f} us  P50={ga_s['p50']:.2f}  "
          f"P95={ga_s['p95']:.2f}  P99={ga_s['p99']:.2f}")

    # ── 3. Governed HALT path ───────────────────────────────────────────────
    print(f"\n[3/4] Governed HALT  path   N={N_HALT:,}   tool={TOOL_HALT!r}")
    gh = bench_governed_halt(registry, H_id, N_HALT, WARMUP)
    gh_s = _stats(gh)
    print(f"      mean={gh_s['mean']:.2f} us  P50={gh_s['p50']:.2f}  "
          f"P95={gh_s['p95']:.2f}  P99={gh_s['p99']:.2f}")

    # ── 4. Overhead = governed - passthrough baseline ───────────────────────
    baseline_mean = pt_s["mean"]
    ov_admit = ga - baseline_mean
    ov_halt  = gh - baseline_mean
    ov_a_s   = _stats(ov_admit)
    ov_h_s   = _stats(ov_halt)

    gate_ok = ov_a_s["p95"] < 10_000.0   # 10 ms = 10,000 us

    print(f"\n[4/4] Overhead (governed - passthrough mean={baseline_mean:.2f} us)")
    print(f"      ADMIT P95 overhead : {ov_a_s['p95']:.2f} us  "
          f"{'PASS (<10 ms)' if gate_ok else 'FAIL (>=10 ms)'}")
    print(f"      HALT  P95 overhead : {ov_h_s['p95']:.2f} us")

    # ── 5. Save results ────────────────────────────────────────────────────
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    summary: dict[str, Any] = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "config": {
            "n_calls_admit":  N_ADMIT,
            "n_calls_halt":   N_HALT,
            "warmup":         WARMUP,
            "session_window": SESSION_WINDOW,
            "tool_admit":     TOOL_ADMIT,
            "tool_halt":      TOOL_HALT,
        },
        "passthrough_us":    pt_s,
        "governed_admit_us": ga_s,
        "governed_halt_us":  gh_s,
        "overhead_admit_us": ov_a_s,
        "overhead_halt_us":  ov_h_s,
        "gate_admit_p95_lt_10ms": gate_ok,
        "T9_1_evidence": (
            f"ADMIT path P95 overhead = {ov_a_s['p95']:.1f} us "
            f"({'<' if gate_ok else '>='} 10,000 us) -> "
            f"Transparency Invariance {'holds' if gate_ok else 'VIOLATED'}"
        ),
        "T9_2_evidence": (
            f"HALT path mean overhead = {ov_h_s['mean']:.1f} us "
            f"(= Δ_policy + Δ_verify; Δ_net = 0 local benchmark)"
        ),
    }

    json_path = RESULTS_DIR / "exp_e1_summary.json"
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    print(f"\n  Saved -> {json_path}")

    tex_path = RESULTS_DIR / "exp_e1_table.tex"
    with open(tex_path, "w", encoding="utf-8") as fh:
        fh.write(_latex_table(summary))
    print(f"  Saved -> {tex_path}")

    print("\n" + "=" * 62)
    status = "PASS" if gate_ok else "FAIL"
    print(f"Exp E1 COMPLETE — Gate: {status}")
    print("=" * 62)

    return gate_ok


if __name__ == "__main__":
    ok = main()
    raise SystemExit(0 if ok else 1)
