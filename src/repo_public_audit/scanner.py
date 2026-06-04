from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import re
import subprocess
from typing import Iterable, Sequence


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}

DEFAULT_IGNORES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}

RISKY_FILE_NAMES = {
    ".env",
    ".env.local",
    ".env.production",
    ".npmrc",
    ".pypirc",
    "id_rsa",
    "id_dsa",
    "id_ed25519",
    "credentials.json",
    "service-account.json",
    "client_secret.json",
    "database.sqlite",
    "database.sqlite3",
    "dump.sql",
}

RISKY_EXTENSIONS = {
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".sqlite",
    ".sqlite3",
    ".db",
    ".sql",
}

BUSINESS_KEYWORDS = {
    "customer",
    "customers",
    "client",
    "clients",
    "invoice",
    "invoices",
    "payroll",
    "revenue",
    "finance",
    "accounting",
    "orders",
    "tokens",
    "credentials",
    "private",
    "internal",
}

SECRET_PATTERNS: Sequence[tuple[str, re.Pattern[str]]] = (
    ("private-key-block", re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("generic-secret-assignment", re.compile(r"(?i)\b(api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*['\"]?[^'\"\s]{12,}")),
)

TEXT_EXTENSIONS = {
    "",
    ".cfg",
    ".conf",
    ".css",
    ".csv",
    ".env",
    ".example",
    ".gitignore",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".jsx",
    ".md",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}


@dataclass(frozen=True)
class Finding:
    severity: str
    rule: str
    path: str
    message: str
    line: int | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class AuditResult:
    root: str
    findings: tuple[Finding, ...]

    @property
    def highest_severity(self) -> str | None:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity

    def to_dict(self) -> dict[str, object]:
        return {
            "root": self.root,
            "findings": [finding.to_dict() for finding in self.findings],
            "highest_severity": self.highest_severity,
        }


def audit_repository(
    root: str | Path,
    *,
    max_file_bytes: int = 1_000_000,
    include_history: bool = False,
    history_commits: int = 50,
    history_max_blob_bytes: int = 200_000,
) -> AuditResult:
    root_path = Path(root).expanduser().resolve()
    findings: list[Finding] = []

    if not root_path.exists():
        raise FileNotFoundError(root_path)
    if not root_path.is_dir():
        raise NotADirectoryError(root_path)

    files = list(iter_files(root_path))
    findings.extend(check_required_files(root_path))

    for path in files:
        rel = path.relative_to(root_path).as_posix()
        findings.extend(check_path(path, rel))

        try:
            size = path.stat().st_size
        except OSError:
            continue

        if size > max_file_bytes:
            findings.append(
                Finding(
                    severity="medium",
                    rule="large-file",
                    path=rel,
                    message=f"Large file ({size} bytes) may not belong in a public source repository.",
                )
            )
            continue

        if is_probably_text(path):
            findings.extend(scan_text_file(path, rel))

    if include_history:
        findings.extend(scan_git_history(root_path, history_commits, history_max_blob_bytes))

    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.path, f.rule, f.line or 0))
    return AuditResult(root=str(root_path), findings=tuple(findings))


def iter_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if should_ignore(path, root):
            continue
        if path.is_file():
            yield path


def should_ignore(path: Path, root: Path) -> bool:
    rel_parts = path.relative_to(root).parts
    return any(part in DEFAULT_IGNORES for part in rel_parts)


def check_required_files(root: Path) -> list[Finding]:
    present = {path.name.lower() for path in root.iterdir() if path.is_file()}
    findings: list[Finding] = []

    required = {
        "readme": ("medium", "Add a README with purpose, install, usage, and limitations."),
        "license": ("medium", "Add an open-source license before inviting reuse."),
        "contributing": ("low", "Add contribution guidance if you want outside help."),
        "security": ("low", "Add a security policy so reporters know where to send issues."),
        "code_of_conduct": ("low", "Add a code of conduct for community expectations."),
    }

    groups = {
        "readme": ("readme.md", "readme.rst", "readme.txt"),
        "license": ("license", "license.md", "copying"),
        "contributing": ("contributing.md", ".github/contributing.md"),
        "security": ("security.md", ".github/security.md"),
        "code_of_conduct": ("code_of_conduct.md", "code-of-conduct.md"),
    }

    for key, filenames in groups.items():
        found = any((root / filename).exists() or filename in present for filename in filenames)
        if not found:
            severity, message = required[key]
            findings.append(
                Finding(
                    severity=severity,
                    rule="missing-file",
                    path=filenames[0],
                    message=message,
                )
            )

    return findings


def check_path(path: Path, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    lower_name = path.name.lower()
    lower_rel = rel.lower()

    if lower_name in RISKY_FILE_NAMES or path.suffix.lower() in RISKY_EXTENSIONS:
        findings.append(
            Finding(
                severity="high",
                rule="risky-path",
                path=rel,
                message="Secret-like or environment-specific file name should not be public.",
            )
        )

    for keyword in BUSINESS_KEYWORDS:
        if keyword in lower_rel:
            findings.append(
                Finding(
                    severity="medium",
                    rule="business-keyword",
                    path=rel,
                    message=f"Path contains business-sensitive keyword: {keyword}.",
                )
            )
            break

    return findings


def is_probably_text(path: Path) -> bool:
    return path.suffix.lower() in TEXT_EXTENSIONS or path.name.lower() in RISKY_FILE_NAMES


def scan_text_file(path: Path, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings

    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule, pattern in SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(
                    Finding(
                        severity="high",
                        rule=rule,
                        path=rel,
                        line=line_number,
                        message="Secret-like value found. Review and rotate if real.",
                    )
                )
                break

    return findings


def scan_git_history(root: Path, max_commits: int, max_blob_bytes: int) -> list[Finding]:
    findings: list[Finding] = []
    if max_commits <= 0:
        return findings

    if not is_git_repo(root):
        findings.append(
            Finding(
                severity="low",
                rule="history-unavailable",
                path=".",
                message="Git history scan requested, but this path is not inside a Git repository.",
            )
        )
        return findings

    commits = git_lines(root, ["rev-list", "--all", f"--max-count={max_commits}"])
    seen_blobs: set[str] = set()
    seen_risky_paths: set[tuple[str, str]] = set()

    for commit in commits:
        short = commit[:12]
        for blob_sha, rel in list_commit_blobs(root, commit):
            path_key = (rel, short)
            if path_key not in seen_risky_paths:
                findings.extend(check_history_path(rel, short))
                seen_risky_paths.add(path_key)

            if blob_sha in seen_blobs:
                continue
            seen_blobs.add(blob_sha)

            suffix = Path(rel).suffix.lower()
            name = Path(rel).name.lower()
            if suffix not in TEXT_EXTENSIONS and name not in RISKY_FILE_NAMES:
                continue

            size = git_blob_size(root, blob_sha)
            if size is None or size > max_blob_bytes:
                continue

            text = git_blob_text(root, blob_sha)
            if text is None:
                continue
            findings.extend(scan_history_text(text, short, rel))

    return findings


def check_history_path(rel: str, commit_short: str) -> list[Finding]:
    findings: list[Finding] = []
    lower_name = Path(rel).name.lower()
    if lower_name in RISKY_FILE_NAMES or Path(rel).suffix.lower() in RISKY_EXTENSIONS:
        findings.append(
            Finding(
                severity="high",
                rule="history-risky-path",
                path=f"{commit_short}:{rel}",
                message="Risky file path exists in Git history. Rotate credentials if this file contained secrets.",
            )
        )
    return findings


def scan_history_text(text: str, commit_short: str, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule, pattern in SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(
                    Finding(
                        severity="high",
                        rule=f"history-{rule}",
                        path=f"{commit_short}:{rel}",
                        line=line_number,
                        message="Secret-like value found in Git history. Review and rotate if real.",
                    )
                )
                break
    return findings


def is_git_repo(root: Path) -> bool:
    completed = run_git(root, ["rev-parse", "--is-inside-work-tree"], text=True)
    return completed.returncode == 0 and completed.stdout.strip() == "true"


def list_commit_blobs(root: Path, commit: str) -> Iterable[tuple[str, str]]:
    completed = run_git(root, ["ls-tree", "-r", "-z", commit], text=False)
    if completed.returncode != 0:
        return

    entries = completed.stdout.split(b"\0")
    for entry in entries:
        if not entry:
            continue
        try:
            meta, raw_path = entry.split(b"\t", 1)
            parts = meta.decode("ascii", errors="ignore").split()
            if len(parts) < 3 or parts[1] != "blob":
                continue
            path = raw_path.decode("utf-8", errors="replace")
            if any(part in DEFAULT_IGNORES for part in Path(path).parts):
                continue
            yield parts[2], path
        except ValueError:
            continue


def git_blob_size(root: Path, blob_sha: str) -> int | None:
    completed = run_git(root, ["cat-file", "-s", blob_sha], text=True)
    if completed.returncode != 0:
        return None
    try:
        return int(completed.stdout.strip())
    except ValueError:
        return None


def git_blob_text(root: Path, blob_sha: str) -> str | None:
    completed = run_git(root, ["cat-file", "-p", blob_sha], text=False)
    if completed.returncode != 0:
        return None
    return completed.stdout.decode("utf-8", errors="ignore")


def git_lines(root: Path, args: list[str]) -> list[str]:
    completed = run_git(root, args, text=True)
    if completed.returncode != 0:
        return []
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


def run_git(root: Path, args: list[str], *, text: bool) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=text,
    )


def should_fail(result: AuditResult, threshold: str) -> bool:
    threshold_value = SEVERITY_ORDER[threshold]
    return any(SEVERITY_ORDER[finding.severity] >= threshold_value for finding in result.findings)
