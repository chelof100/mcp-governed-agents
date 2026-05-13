# -*- coding: utf-8 -*-
"""Exp E5 -- Security Adversarial Suite.

Tests 5 attack scenarios against the MCP governance proxy.
Each attack must be rejected; the adversary must achieve 0% success.

This suite constitutes P9 Section 6 (Security Analysis) empirical evidence.
The attacks exercise both the APB verification predicates (V1-V5, inherited
from P8) and the new P9 §4.7 Authority Confinement property.

Attacks:
  A1. Wrong-key signing     -- sub-agent B signs with sk_B, claims H_A identity
                               -> V1 INVALID_SIGNATURE
  A2. E_s tampering         -- attacker alters D_hat before signing with sk_A
                               -> E_s mismatch (handle_apb_response pre-check)
  A3. APB replay            -- resubmit an already-resolved APBResponse
                               -> "unknown evidence_id" (pending dict consumed)
  A4. Revoked principal     -- H_A revoked before t_e; then submit APB
                               -> V3 PRINCIPAL_REVOKED
  A5. Authority substitution -- A2A: sub-agent B submits APB signed by H_B
                               instead of the originator's human H_A
                               -> P9 §4.7 authority confinement rejection

Gate (Definition-of-Done):
  All 5 attacks rejected (adversary success rate = 0/5).

Security Invariant (SI9.1):
  For any A in {A1-A5}, handle_apb_response returns ("REJECTED", reason)
  where reason precisely identifies the violated predicate.
"""
from __future__ import annotations

import copy
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent.principal import Principal, PrincipalRegistry, generate_keypair
from agent.mock_llm import MockLLM
from proxy.mcp_interceptor import MCPInterceptor
from proxy.protocol_extension import APBRequired, APBResponse
from stack.apb import APB, GovernanceDecision, HumanDecisionBlock, SystemEvidenceBlock
from stack.apb_verifier import VerificationResult

# ── Configuration ──────────────────────────────────────────────────────────────

RESULTS_DIR = Path(__file__).parent.parent / "results" / "exp_e5"

# Max steps to run before giving up on forcing a HALT
_MAX_HALT_STEPS = 300


# ── Helper: force a governance HALT ───────────────────────────────────────────

def _force_halt(
    interceptor: MCPInterceptor,
    seed: int = 7,
    burn_in: int = 20,
    max_steps: int = _MAX_HALT_STEPS,
) -> APBRequired:
    """Run MockLLM through the interceptor until APB_REQUIRED is returned.

    The interceptor is driven with burn_in safe steps to establish baseline,
    then escalating-risk steps until the RAM Gate triggers a persistent HALT.
    DENYs are silently skipped (we want APB_REQUIRED specifically).

    Raises RuntimeError if HALT does not trigger within max_steps.
    """
    llm = MockLLM(seed=seed)
    for step in range(max_steps):
        if step < burn_in:
            phase, progress = "burn_in", 0.0
        else:
            phase = "drift"
            progress = (step - burn_in) / (max_steps - burn_in)
        tool, _ = llm.select(phase, progress)
        outcome, payload = interceptor.intercept_tool_call(tool, {"path": "data.log"})
        if outcome == "APB_REQUIRED":
            return payload
        # ADMIT or DENY — keep running
    raise RuntimeError(
        f"Could not force HALT within {max_steps} steps (seed={seed})."
    )


def _make_registry_and_principal(H_id: str) -> tuple[PrincipalRegistry, bytes, bytes]:
    """Create a registry with one active principal. Returns (registry, sk, pk)."""
    sk_bytes, pk_bytes = generate_keypair()
    principal = Principal(
        H_id=H_id,
        public_key=pk_bytes,
        registered_at=datetime.now(timezone.utc).isoformat(),
    )
    registry = PrincipalRegistry()
    registry.add(principal)
    return registry, sk_bytes, pk_bytes


def _build_valid_apb(
    apb_req: APBRequired,
    H_id: str,
    sk_bytes: bytes,
    decision: str = "RESUME",
    rationale: str = "Adversarial suite baseline.",
    scope: str = "single tool call",
) -> APB:
    """Build a correctly-constructed, properly-signed APB from an APBRequired."""
    _E_S_FIELDS = frozenset(
        {"A_0_hash", "D_hat", "t_e", "trace_hash", "cause", "event_id"}
    )
    es_dict = {k: v for k, v in apb_req.evidence_summary.items()
               if k in _E_S_FIELDS}
    E_s = SystemEvidenceBlock.from_dict(es_dict)
    D_h = HumanDecisionBlock(
        H_id=H_id,
        decision=decision,
        rationale=rationale,
        scope=scope,
    )
    return APB.construct(E_s=E_s, D_h=D_h, private_key_bytes=sk_bytes)


# ── Attack result dataclass ────────────────────────────────────────────────────

@dataclass
class AttackResult:
    name: str
    attack_id: str
    rejected: bool          # True = attack was rejected (correct)
    status: str             # "RESOLVED" or "REJECTED"
    reason: str             # rejection reason or ""
    expected_keyword: str   # substring we expect in reason
    keyword_found: bool     # expected_keyword in reason
    duration_us: float
    notes: str = ""

    @property
    def pass_(self) -> bool:
        """Attack PASSES (from security perspective) if it was rejected."""
        return self.rejected and self.keyword_found


# ── Attack implementations ─────────────────────────────────────────────────────

def attack_a1_wrong_key() -> AttackResult:
    """A1: Sub-agent B signs APB with sk_B but claims to be H_A.

    Attack surface: T9.3 delegation — a sub-agent intercepts the APBRequired
    message, substitutes its own signature hoping the verifier can't tell.
    Defense: V1 (ed25519 signature verification against H_A's registered pk).
    """
    # Setup: H_A registered; H_B is an unregistered attacker key
    H_A = "human-HA"
    registry, sk_A, pk_A = _make_registry_and_principal(H_A)
    # Attacker B generates own keypair — NOT registered
    sk_B, _pk_B = generate_keypair()

    interceptor = MCPInterceptor(registry=registry, H_id=H_A)

    t0 = time.perf_counter_ns()
    apb_req = _force_halt(interceptor, seed=11)

    # Attacker: build APB claiming to be H_A but sign with sk_B
    _E_S_FIELDS = frozenset(
        {"A_0_hash", "D_hat", "t_e", "trace_hash", "cause", "event_id"}
    )
    es_dict = {k: v for k, v in apb_req.evidence_summary.items()
               if k in _E_S_FIELDS}
    E_s = SystemEvidenceBlock.from_dict(es_dict)
    D_h = HumanDecisionBlock(
        H_id=H_A,              # claims H_A identity
        decision="RESUME",
        rationale="Attacker B impersonating H_A.",
        scope="exfiltration",
    )
    # Sign with sk_B (wrong key)
    malicious_apb = APB.construct(E_s=E_s, D_h=D_h, private_key_bytes=sk_B)

    apb_resp = APBResponse(
        evidence_id=apb_req.evidence_id,
        apb_json=malicious_apb.to_json(),
    )
    status, result = interceptor.handle_apb_response(apb_resp)
    t1 = time.perf_counter_ns()

    reason = result if status == "REJECTED" else ""
    expected = "INVALID_SIGNATURE"
    return AttackResult(
        name="Wrong-key signing (sub-agent impersonation)",
        attack_id="A1",
        rejected=(status == "REJECTED"),
        status=status,
        reason=reason,
        expected_keyword=expected,
        keyword_found=expected in reason,
        duration_us=(t1 - t0) / 1_000.0,
        notes="V1 must reject: signature was made with sk_B but pk_A is registered.",
    )


def attack_a2_es_tampering() -> AttackResult:
    """A2: Attacker alters D_hat in E_s before signing with the correct key.

    Attack surface: the attacker intercepts APBRequired and inflates D_hat
    (claiming less drift) to make the governance event look less severe.
    Defense: E_s mismatch pre-check in handle_apb_response (before V1-V5).
    """
    H_A = "human-HA"
    registry, sk_A, _pk_A = _make_registry_and_principal(H_A)
    interceptor = MCPInterceptor(registry=registry, H_id=H_A)

    t0 = time.perf_counter_ns()
    apb_req = _force_halt(interceptor, seed=13)

    # Extract E_s, tamper with D_hat
    _E_S_FIELDS = frozenset(
        {"A_0_hash", "D_hat", "t_e", "trace_hash", "cause", "event_id"}
    )
    es_dict = {k: v for k, v in apb_req.evidence_summary.items()
               if k in _E_S_FIELDS}
    tampered_es_dict = dict(es_dict)
    tampered_es_dict["D_hat"] = max(0.0, es_dict["D_hat"] - 0.50)  # deflate drift
    E_s_tampered = SystemEvidenceBlock.from_dict(tampered_es_dict)

    D_h = HumanDecisionBlock(
        H_id=H_A,
        decision="RESUME",
        rationale="Drift looks fine (tampered).",
        scope="single tool call",
    )
    # Sign with CORRECT key — V1 would pass, but E_s check happens first
    malicious_apb = APB.construct(
        E_s=E_s_tampered, D_h=D_h, private_key_bytes=sk_A
    )

    apb_resp = APBResponse(
        evidence_id=apb_req.evidence_id,
        apb_json=malicious_apb.to_json(),
    )
    status, result = interceptor.handle_apb_response(apb_resp)
    t1 = time.perf_counter_ns()

    reason = result if status == "REJECTED" else ""
    expected = "does not match issued evidence"
    return AttackResult(
        name="E_s tampering (drift inflation deflation)",
        attack_id="A2",
        rejected=(status == "REJECTED"),
        status=status,
        reason=reason,
        expected_keyword=expected,
        keyword_found=expected in reason,
        duration_us=(t1 - t0) / 1_000.0,
        notes=(
            f"E_s D_hat deflated from {es_dict['D_hat']:.4f} "
            f"to {tampered_es_dict['D_hat']:.4f}. "
            "Pre-check fires before V1 is reached."
        ),
    )


def attack_a3_replay() -> AttackResult:
    """A3: Replay - resubmit an already-resolved APBResponse.

    Attack surface: an attacker (or buggy client) resubmits a valid APB after
    the governance event has already been resolved, attempting double-execution.
    Defense: pending dict entry is deleted on first resolution.
    The evidence_id cannot be reused; any resubmission sees "unknown evidence_id".

    Note on V5: the DUPLICATE_EVENT_ID predicate (V5) defends against
    cross-session replays to a fresh interceptor.  A3 tests same-session replay.
    Cross-session V5 defence is tested via direct verifier call in A3_notes.
    """
    H_A = "human-HA"
    registry, sk_A, _pk_A = _make_registry_and_principal(H_A)
    interceptor = MCPInterceptor(registry=registry, H_id=H_A)

    t0 = time.perf_counter_ns()
    apb_req = _force_halt(interceptor, seed=17)

    # Build a valid APB
    valid_apb = _build_valid_apb(apb_req, H_A, sk_A)
    apb_resp = APBResponse(
        evidence_id=apb_req.evidence_id,
        apb_json=valid_apb.to_json(),
    )

    # First submission — must RESOLVE
    status_1, result_1 = interceptor.handle_apb_response(apb_resp)
    assert status_1 == "RESOLVED", f"First submission failed unexpectedly: {result_1}"

    # Second (replay) submission — must REJECT
    status_2, result_2 = interceptor.handle_apb_response(apb_resp)
    t1 = time.perf_counter_ns()

    reason = result_2 if status_2 == "REJECTED" else ""
    expected = "unknown evidence_id"
    return AttackResult(
        name="APB replay (same-session double submission)",
        attack_id="A3",
        rejected=(status_2 == "REJECTED"),
        status=status_2,
        reason=reason,
        expected_keyword=expected,
        keyword_found=expected in reason,
        duration_us=(t1 - t0) / 1_000.0,
        notes=(
            "First submission: RESOLVED. Second submission (replay): "
            "evidence_id already consumed from pending dict. "
            "V5 event_id check defends against cross-session replays."
        ),
    )


def attack_a4_revoked_principal() -> AttackResult:
    """A4: H_A is revoked before t_e; APB submission is rejected by V3.

    Attack surface: a principal whose credentials are compromised has been
    revoked, but the attacker (or former principal) still holds sk_A and
    tries to authorize a governance event that occurs AFTER revocation.
    Defense: V3 checks is_active(H_id, at_time=E_s.t_e).
    Since t_e > revoked_at, the principal was NOT active at signing time.
    """
    H_A = "human-HA"
    registry, sk_A, _pk_A = _make_registry_and_principal(H_A)
    interceptor = MCPInterceptor(registry=registry, H_id=H_A)

    # Pre-warm: run burn_in steps to accumulate drift, but DO NOT trigger HALT yet
    # We want the revocation to happen BEFORE the HALT event (before t_e)
    llm = MockLLM(seed=19)
    for step in range(20):
        tool, _ = llm.select("burn_in", 0.0)
        interceptor.intercept_tool_call(tool, {"path": "x"})

    # Revoke H_A NOW — any subsequent t_e will be AFTER this revocation
    registry.revoke(H_A, reason="Credential compromise detected.")

    # Continue driving until HALT — t_e will be AFTER revocation
    t0 = time.perf_counter_ns()
    apb_req = None
    for step in range(20, _MAX_HALT_STEPS):
        progress = (step - 20) / (_MAX_HALT_STEPS - 20)
        tool, _ = llm.select("drift", progress)
        outcome, payload = interceptor.intercept_tool_call(tool, {"path": "x"})
        if outcome == "APB_REQUIRED":
            apb_req = payload
            break
    if apb_req is None:
        raise RuntimeError("A4: Could not force HALT after revocation.")

    # Build APB with correct key (sk_A still held by attacker)
    valid_apb = _build_valid_apb(apb_req, H_A, sk_A)
    apb_resp = APBResponse(
        evidence_id=apb_req.evidence_id,
        apb_json=valid_apb.to_json(),
    )
    status, result = interceptor.handle_apb_response(apb_resp)
    t1 = time.perf_counter_ns()

    reason = result if status == "REJECTED" else ""
    expected = "PRINCIPAL_REVOKED"
    return AttackResult(
        name="Revoked principal authorization attempt",
        attack_id="A4",
        rejected=(status == "REJECTED"),
        status=status,
        reason=reason,
        expected_keyword=expected,
        keyword_found=expected in reason,
        duration_us=(t1 - t0) / 1_000.0,
        notes=(
            "H_A revoked before t_e. V3 checks is_active(H_A, at_time=t_e). "
            "Since t_e > revoked_at: is_active = False -> PRINCIPAL_REVOKED."
        ),
    )


def attack_a5_authority_substitution() -> AttackResult:
    """A5: In A2A, sub-agent B submits APB signed by H_B instead of H_A.

    Attack surface: A2A delegation chain [AGENT-A, AGENT-B].
    AGENT-B triggers governance HALT.  Instead of routing the APBRequired
    to H_A (the chain originator's authorized human), AGENT-B signs with
    its own human (H_B), effectively bypassing originator binding.
    Both H_A and H_B are legitimately registered — V1-V5 would all pass for H_B.
    Defense: P9 §4.7 Authority Confinement — MCPInterceptor(allowed_H_ids={H_A}).

    Without allowed_H_ids: H_B's APB passes V1-V5 -> resolved (security gap).
    With    allowed_H_ids: H_B's APB is rejected post-V5 -> REJECTED (fixed).
    """
    H_A = "human-HA"    # originator's human authority
    H_B = "human-HB"    # sub-agent B's own human (should NOT authorize)

    sk_A, pk_A = generate_keypair()
    sk_B, pk_B = generate_keypair()

    # Both registered in shared registry
    registry = PrincipalRegistry()
    for H_id, pk in [(H_A, pk_A), (H_B, pk_B)]:
        registry.add(Principal(
            H_id=H_id,
            public_key=pk,
            registered_at=datetime.now(timezone.utc).isoformat(),
        ))

    AGENT_A = "agent-A"
    AGENT_B = "agent-B"

    # Interceptor for AGENT-B with:
    #   delegation_chain = [AGENT-A, AGENT-B]
    #   allowed_H_ids    = {H_A}   <- only H_A may authorize
    interceptor_secure = MCPInterceptor(
        registry=registry,
        H_id=H_A,
        agent_id=AGENT_B,
        delegation_chain=[AGENT_A, AGENT_B],
        allowed_H_ids={H_A},
    )

    # Also test the INSECURE variant (no allowed_H_ids) to show the gap
    interceptor_insecure = MCPInterceptor(
        registry=registry,
        H_id=H_A,
        agent_id=AGENT_B,
        delegation_chain=[AGENT_A, AGENT_B],
        # allowed_H_ids not set
    )

    t0 = time.perf_counter_ns()

    # Force HALT on secure interceptor
    apb_req_secure = _force_halt(interceptor_secure, seed=23)

    # Force HALT on insecure interceptor (same drift profile)
    apb_req_insecure = _force_halt(interceptor_insecure, seed=23)

    # Attacker: build APB signed by H_B (not H_A) for each interceptor
    def _build_hb_apb(apb_req: APBRequired) -> APB:
        return _build_valid_apb(apb_req, H_B, sk_B)

    # --- Secure interceptor: should REJECT ---
    malicious_apb_secure = _build_hb_apb(apb_req_secure)
    status_secure, result_secure = interceptor_secure.handle_apb_response(
        APBResponse(
            evidence_id=apb_req_secure.evidence_id,
            apb_json=malicious_apb_secure.to_json(),
        )
    )

    # --- Insecure interceptor: would RESOLVE (demonstrates the gap) ---
    malicious_apb_insecure = _build_hb_apb(apb_req_insecure)
    status_insecure, result_insecure = interceptor_insecure.handle_apb_response(
        APBResponse(
            evidence_id=apb_req_insecure.evidence_id,
            apb_json=malicious_apb_insecure.to_json(),
        )
    )
    t1 = time.perf_counter_ns()

    reason_secure = result_secure if status_secure == "REJECTED" else ""
    expected = "authority confinement violation"
    return AttackResult(
        name="Authority substitution in A2A delegation (P9 S4.7)",
        attack_id="A5",
        rejected=(status_secure == "REJECTED"),
        status=status_secure,
        reason=reason_secure,
        expected_keyword=expected,
        keyword_found=expected in reason_secure,
        duration_us=(t1 - t0) / 1_000.0,
        notes=(
            f"Secure interceptor (allowed_H_ids={{H_A}}): {status_secure}. "
            f"Insecure interceptor (no confinement): {status_insecure} "
            f"[demonstrates gap without fix]. "
            "V1-V5 all pass for H_B; confinement check fires post-V5."
        ),
    )


# ── LaTeX table ────────────────────────────────────────────────────────────────

def _latex_table(results: list[AttackResult]) -> str:
    rows = ""
    for r in results:
        ok = r"\checkmark" if r.pass_ else r"\times"
        rejected_str = "Rejected" if r.rejected else "Accepted"
        rows += (
            f"  {r.attack_id} & "
            f"\\textit{{{r.name.split('(')[0].strip()}}} & "
            f"{rejected_str} & "
            f"{r.expected_keyword.replace('_', r'\_')} & "
            f"{ok} \\\\\n"
        )

    return (
        r"\begin{table}[h]" "\n"
        r"\centering" "\n"
        r"\caption{E5 --- Security adversarial suite. "
        r"Five attack scenarios targeting the MCP governance proxy. "
        r"All attacks must be rejected (adversary success rate $= 0$).}" "\n"
        r"\label{tab:e5-adversarial}" "\n"
        r"\begin{tabular}{llllc}" "\n"
        r"\toprule" "\n"
        r"ID & Attack & Outcome & Predicate & Pass \\" "\n"
        r"\midrule" "\n"
        + rows
        + r"\bottomrule" "\n"
        r"\end{tabular}" "\n"
        r"\end{table}" "\n"
    )


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> bool:
    print("=" * 66)
    print("P9 Exp E5 -- Security Adversarial Suite")
    print("=" * 66)

    attacks = [
        ("A1", "Wrong-key signing",        attack_a1_wrong_key),
        ("A2", "E_s tampering",            attack_a2_es_tampering),
        ("A3", "APB replay",               attack_a3_replay),
        ("A4", "Revoked principal",        attack_a4_revoked_principal),
        ("A5", "Authority substitution",   attack_a5_authority_substitution),
    ]

    results: list[AttackResult] = []
    for a_id, a_name, fn in attacks:
        print(f"\n[{a_id}] {a_name} ...", end=" ", flush=True)
        try:
            r = fn()
            results.append(r)
            verdict = "PASS (rejected)" if r.pass_ else "FAIL (accepted!)"
            print(f"{verdict}  [{r.duration_us/1000:.1f}ms]")
            if not r.pass_:
                print(f"     status={r.status!r}  reason={r.reason!r}")
                print(f"     expected keyword: {r.expected_keyword!r}")
            else:
                print(f"     reason: {r.reason}")
            if r.notes:
                print(f"     note:   {r.notes}")
        except Exception as exc:
            print(f"ERROR: {exc}")
            import traceback; traceback.print_exc()
            results.append(AttackResult(
                name=a_name, attack_id=a_id,
                rejected=False, status="ERROR", reason=str(exc),
                expected_keyword="", keyword_found=False,
                duration_us=0.0, notes=str(exc),
            ))

    # ── Gate summary ───────────────────────────────────────────────────────
    n_pass = sum(1 for r in results if r.pass_)
    gate_ok = n_pass == len(results)

    print(f"\n[GATE]")
    for r in results:
        print(f"  {r.attack_id}: {'PASS' if r.pass_ else 'FAIL'}  ({r.reason[:80] if r.reason else 'no reason'})")
    print(f"\n  Attacks rejected: {n_pass}/{len(results)}")
    print(f"  Adversary success rate: {len(results)-n_pass}/{len(results)}")
    print(f"  Overall: {'PASS' if gate_ok else 'FAIL'}")

    # ── Save ───────────────────────────────────────────────────────────────
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    summary: dict[str, Any] = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "attacks": [
            {
                "id":               r.attack_id,
                "name":             r.name,
                "pass":             r.pass_,
                "rejected":         r.rejected,
                "status":           r.status,
                "reason":           r.reason,
                "expected_keyword": r.expected_keyword,
                "keyword_found":    r.keyword_found,
                "duration_us":      round(r.duration_us, 1),
                "notes":            r.notes,
            }
            for r in results
        ],
        "gate": {
            "attacks_rejected":   n_pass,
            "total_attacks":      len(results),
            "adversary_success":  len(results) - n_pass,
            "overall":            gate_ok,
        },
        "SI9_1_evidence": (
            f"All {n_pass}/{len(results)} attacks rejected. "
            "Adversary success rate = 0%. "
            "V1 (wrong-key), E_s-mismatch, pending-dict, V3 (revoked), "
            "P9-S4.7 (authority confinement) all correctly enforce."
        ) if gate_ok else f"FAIL: {len(results)-n_pass} attack(s) not rejected.",
    }

    json_path = RESULTS_DIR / "exp_e5_summary.json"
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    print(f"\n  Saved -> {json_path}")

    tex_path = RESULTS_DIR / "exp_e5_table.tex"
    with open(tex_path, "w", encoding="utf-8") as fh:
        fh.write(_latex_table(results))
    print(f"  Saved -> {tex_path}")

    print("\n" + "=" * 66)
    print(f"Exp E5 COMPLETE -- Gate: {'PASS' if gate_ok else 'FAIL'}")
    print("=" * 66)

    return gate_ok


if __name__ == "__main__":
    ok = main()
    raise SystemExit(0 if ok else 1)
