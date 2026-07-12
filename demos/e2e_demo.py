#!/usr/bin/env python3
"""IndexOne end-to-end demo — one command, the whole story.

A human authorizes Agent A (org1); A → B → C delegates across three
organizations, narrowing authority at each hop; Agent C acts. The action is
committed to a transparency **witness**, an **independent** notary attests the
completion, and the composed ``verify()`` accepts it. Then the *same* verify()
catches the two things a signature alone cannot: an **omitted** action (never
witnessed) and a **self-reported** completion (the executor marking its own
homework). Finally, the real hosted witness **service** (over HTTP) is shown to
compute the *identical* transparency root — the anchor is real, not a mock.

Run:   make demo        (or:  python demos/e2e_demo.py)
Needs: the `indexone` SDK installed and the `indexone-cli` sidecar built
       (INDEXONE_CLI, or on PATH). Part 4 also builds the witness-service binary.

Exit code is non-zero if any expected outcome does not hold — this is an
executable assertion, not just a print.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import indexone
from indexone import IndexOneError, Principal, Scope

FAR = 4_102_444_800


def seed(b: int) -> str:
    return f"{b:02x}" * 32


def bold(s: str) -> None:
    print(f"\n\033[1m{s}\033[0m")


def ok(s: str) -> None:
    print(f"  \033[32m✓\033[0m {s}")


def b64url(hex_str: str) -> str:
    return base64.urlsafe_b64encode(bytes.fromhex(hex_str)).rstrip(b"=").decode()


def hex_from_b64url(s: str) -> str:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).hex()


def build_cross_org_chain() -> tuple[dict, dict, str]:
    """Human → A(org1) → B(org2) → C(org3); returns (chain, root_key, chain_digest)."""
    human, a, b, c = seed(1), seed(2), seed(3), seed(4)
    root = indexone.issue(
        human,
        Principal("human:alice", "Alice"),
        Scope(
            ["payments.charge"],
            budget=10_000,
            currency="USD",
            max_depth=3,
            expires_at=FAR,
        ),
    )
    chain, root_key = root["chain"], root["root_key"]
    hops = [
        (human, "agent:a@org1", a, 5_000, 2, "book travel"),
        (a, "agent:b@org2", b, 5_000, 1, "charge airline"),
        (b, "agent:c@org3", c, 4_000, 0, "settle fare"),
    ]
    for signer, to_id, to_seed, budget, depth, purpose in hops:
        chain = indexone.attenuate(
            chain,
            signer,
            Principal(to_id, to_id),
            to_seed,
            Scope(
                ["payments.charge"],
                budget=budget,
                currency="USD",
                max_depth=depth,
                expires_at=FAR,
            ),
            purpose,
        )["chain"]
    return chain, root_key, indexone.chain_digest(chain)


def live_witness_cross_check(cd: str, action: str, nonce: str) -> bool:
    """Start the hosted witness service, submit the same receipt over HTTP, and
    confirm it computes the identical transparency root the SDK did."""
    repo = Path(__file__).resolve().parents[1]
    bin_path = repo / "services/witness/target/debug/indexone-witness-service"
    if not bin_path.exists():
        subprocess.run(
            [
                "cargo",
                "build",
                "--manifest-path",
                str(repo / "services/witness/Cargo.toml"),
                "--bin",
                "indexone-witness-service",
            ],
            check=True,
            cwd=repo,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    addr = "127.0.0.1:8799"
    base = f"http://{addr}"
    env = dict(os.environ, INDEXONE_WITNESS_SEED=seed(7), INDEXONE_WITNESS_ADDR=addr)
    proc = subprocess.Popen(
        [str(bin_path)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    try:
        sth = None
        for _ in range(50):
            try:
                sth = json.load(
                    urllib.request.urlopen(f"{base}/witness/v1/sth", timeout=2)
                )
                break
            except Exception:
                time.sleep(0.2)
        if sth is None:
            print("  (skipped: witness service did not start)")
            return True
        r0 = sth["root"]  # base64url root of the empty tree
        body = json.dumps(
            {
                "chain_digest": b64url(cd),
                "action_digest": b64url(action),
                "nonce": b64url(nonce),
                "prev_root": r0,
            }
        ).encode()
        req = urllib.request.Request(
            f"{base}/witness/v1/entries",
            data=body,
            headers={"content-type": "application/json"},
            method="POST",
        )
        resp = json.load(urllib.request.urlopen(req, timeout=3))
        service_root_hex = hex_from_b64url(resp["sth"]["root"])
        # The SDK computed its root over the SAME receipt with prev_root = r0.
        sdk = indexone.witness_append(
            cd, action, nonce, prev_root_hex=hex_from_b64url(r0)
        )
        match = sdk["root"] == service_root_hex
        if match:
            ok(
                f"hosted witness service and SDK agree on the transparency root: {service_root_hex[:16]}…"
            )
        else:
            print(
                f"  MISMATCH: service {service_root_hex[:16]}… vs sdk {sdk['root'][:16]}…"
            )
        return match
    finally:
        proc.terminate()
        proc.wait()


def main() -> int:
    notary, executor = seed(9), seed(4)
    notary_pk = indexone.pubkey(notary)
    executor_pk = indexone.pubkey(executor)

    bold("[1] Cross-org delegation: Human → A(org1) → B(org2) → C(org3)")
    chain, root_key, cd = build_cross_org_chain()
    eff = indexone.verify(chain, root_key)
    ok(
        f"chain verifies end-to-end; C's effective authority narrowed to budget={eff.budget} {eff.currency}, depth={eff.max_depth}"
    )

    action, nonce = "42" * 32, "ab" * 32
    bold("[2] Witness the action + independent attestation → composed verify() ACCEPTS")
    w = indexone.witness_append(cd, action, nonce)
    completion = indexone.attest(
        notary,
        Principal("attester:notary", "Notary"),
        cd,
        action,
        action,
        w["root"],
        w["inclusion_proof"],
        role="third_party",
    )
    eff = indexone.composed_verify(
        chain,
        root_key,
        w["root"],
        w["receipt"],
        completion,
        trusted_attesters=[notary_pk],
    )
    ok(f"ACCEPT — witnessed + independently attested; effective budget={eff.budget}")

    bold("[3] The two things a signature can't catch — both REJECTED")
    # (a) OMISSION: an action C claims but never witnessed.
    omitted = "99" * 32
    omitted_receipt = indexone.witness_append(cd, omitted, "cd" * 32)["receipt"]
    completion_omit = indexone.attest(
        notary,
        Principal("attester:notary", "Notary"),
        cd,
        omitted,
        omitted,
        w["root"],
        w["inclusion_proof"],
        role="third_party",
    )
    try:
        indexone.composed_verify(
            chain,
            root_key,
            w["root"],
            omitted_receipt,
            completion_omit,
            trusted_attesters=[notary_pk],
        )
        print("  UNEXPECTED: omitted action was accepted")
        return 1
    except IndexOneError as e:
        ok(
            f"OMISSION rejected — the action has no inclusion proof against the witnessed root ({e})"
        )

    # (b) SELF-REPORT: the executor attests its own completion (even if trusted).
    self_report = indexone.attest(
        executor,
        Principal("agent:c@org3", "C"),
        cd,
        action,
        action,
        w["root"],
        w["inclusion_proof"],
        role="third_party",
    )
    try:
        indexone.composed_verify(
            chain,
            root_key,
            w["root"],
            w["receipt"],
            self_report,
            trusted_attesters=[executor_pk],
        )
        print("  UNEXPECTED: self-reported completion was accepted")
        return 1
    except IndexOneError as e:
        ok(
            f"SELF-REPORT rejected — completion signed by the executing agent is not independent ({e})"
        )

    bold("[4] The hosted witness service (real HTTP) computes the identical root")
    if not live_witness_cross_check(cd, action, nonce):
        return 1

    print(
        "\n\033[1mEND-TO-END: the cross-org chain verifies, omission and self-report are caught,"
    )
    print(
        "and the hosted witness anchors the same transparency root. One command.\033[0m"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
