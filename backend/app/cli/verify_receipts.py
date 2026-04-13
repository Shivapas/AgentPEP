"""CLI tool for batch verification of signed receipts.

Sprint 32 — APEP-257: Offline verification of signed receipts without
server access.

Usage::

    python -m app.cli.verify_receipts \\
        --receipts-file receipts.jsonl \\
        --key-file verify.key \\
        [--verbose]

The receipts file should be a JSONL file where each line is::

    {"receipt": "agentpep-receipt-v1|...", "record": {...}}

The key file should contain a single line::

    {algorithm}:{base64_key}
"""

from __future__ import annotations

import argparse
import json
import sys


def main(argv: list[str] | None = None) -> int:
    """Run the receipt verification CLI.

    Returns:
        0 if all receipts are valid, 1 if any are invalid.
    """
    parser = argparse.ArgumentParser(
        description="Verify AgentPEP signed receipts offline"
    )
    parser.add_argument(
        "--receipts-file",
        required=True,
        help="Path to JSONL file containing receipt+record pairs",
    )
    parser.add_argument(
        "--key-file",
        required=True,
        help="Path to verify key file (format: algorithm:base64_key)",
    )
    parser.add_argument(
        "--key-id",
        default="default",
        help="Key ID to register the verify key under (default: 'default')",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print details for each receipt",
    )
    args = parser.parse_args(argv)

    # Import here to avoid pulling in the full app stack
    from app.services.receipt_verifier import ReceiptVerifier

    verifier = ReceiptVerifier()

    # Load verify key
    try:
        verifier.load_key_from_file(args.key_file, key_id=args.key_id)
    except FileNotFoundError:
        print(f"ERROR: Key file not found: {args.key_file}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"ERROR: Invalid key file format: {exc}", file=sys.stderr)
        return 1

    # Process receipts
    total = 0
    passed = 0
    failed = 0

    try:
        with open(args.receipts_file) as f:
            for line_num, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                total += 1
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    print(f"  Line {line_num}: FAILED (invalid JSON)")
                    failed += 1
                    continue

                receipt = entry.get("receipt", "")
                record = entry.get("record", {})

                if verifier.verify(receipt, record):
                    passed += 1
                    if args.verbose:
                        decision_id = record.get("decision_id", "?")
                        print(f"  Line {line_num}: OK (decision_id={decision_id})")
                else:
                    failed += 1
                    decision_id = record.get("decision_id", "?")
                    print(f"  Line {line_num}: FAILED (decision_id={decision_id})")
    except FileNotFoundError:
        print(
            f"ERROR: Receipts file not found: {args.receipts_file}",
            file=sys.stderr,
        )
        return 1

    # Summary
    print(f"\n{passed}/{total} receipts verified successfully")
    if failed > 0:
        print(f"{failed} receipt(s) FAILED verification")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
