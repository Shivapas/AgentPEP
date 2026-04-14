"""CLI tool for verifying hash-chained context integrity.

Sprint 36 — APEP-285: Verify that a session's hash-chained context
has not been tampered with by walking the chain and recomputing hashes.

Usage::

    python -m app.cli.verify_context --session-id <session_id>
"""

from __future__ import annotations

import argparse
import asyncio
import sys


async def _verify(session_id: str, verbose: bool) -> int:
    """Run the verification."""
    from app.services.hash_chained_context import hash_chained_context

    result = await hash_chained_context.verify_chain(session_id)

    if result.valid:
        print(f"OK: {result.verified_entries}/{result.total_entries} entries verified")
        if verbose and result.total_entries > 0:
            chain = await hash_chained_context.get_chain(session_id)
            for entry in chain:
                print(
                    f"  seq={entry.sequence_number} "
                    f"chain_hash={entry.chain_hash[:16]}... "
                    f"source={entry.source}"
                )
        return 0

    print(f"FAILED: {result.detail}")
    if result.first_tampered_sequence is not None:
        print(f"  First tampered entry at sequence {result.first_tampered_sequence}")
        print(f"  Entry ID: {result.first_tampered_entry_id}")
    print(f"  Verified {result.verified_entries}/{result.total_entries} entries before failure")
    return 1


def main(argv: list[str] | None = None) -> int:
    """Run the context verification CLI."""
    parser = argparse.ArgumentParser(
        description="Verify AgentPEP hash-chained context integrity (Sprint 36)"
    )
    parser.add_argument(
        "--session-id",
        required=True,
        help="Session ID whose context chain to verify",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print details for each chain entry",
    )
    args = parser.parse_args(argv)

    return asyncio.run(_verify(args.session_id, args.verbose))


if __name__ == "__main__":
    sys.exit(main())
