from __future__ import annotations

import argparse
import json
import sys

from .scanner import SEVERITY_ORDER, audit_repository, should_fail


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repo-public-audit",
        description="Audit a repository before making it public.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Repository path to audit.")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format.",
    )
    parser.add_argument(
        "--fail-on",
        choices=tuple(SEVERITY_ORDER),
        default=None,
        help="Exit with status 1 when findings at or above this severity exist.",
    )
    parser.add_argument(
        "--max-file-bytes",
        type=int,
        default=1_000_000,
        help="Skip content scan and warn for files larger than this size.",
    )
    parser.add_argument(
        "--history",
        action="store_true",
        help="Also scan bounded Git history for risky paths and secret-like values.",
    )
    parser.add_argument(
        "--history-commits",
        type=int,
        default=50,
        help="Maximum number of commits to scan when --history is enabled.",
    )
    parser.add_argument(
        "--history-max-blob-bytes",
        type=int,
        default=200_000,
        help="Skip historical blobs larger than this size.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        result = audit_repository(
            args.path,
            max_file_bytes=args.max_file_bytes,
            include_history=args.history,
            history_commits=args.history_commits,
            history_max_blob_bytes=args.history_max_blob_bytes,
        )
    except Exception as exc:
        print(f"repo-public-audit: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    else:
        print_text(result)

    if args.fail_on and should_fail(result, args.fail_on):
        return 1
    return 0


def print_text(result) -> None:
    count = len(result.findings)
    print(f"repo-public-audit: {count} finding{'s' if count != 1 else ''}")
    if not result.findings:
        print("\nNo findings. This is not a guarantee of safety; review Git history before publishing.")
        return

    for finding in result.findings:
        location = finding.path
        if finding.line:
            location += f":{finding.line}"
        print(f"\n[{finding.severity}] {finding.rule}: {location}")
        print(f"  {finding.message}")


if __name__ == "__main__":
    raise SystemExit(main())
