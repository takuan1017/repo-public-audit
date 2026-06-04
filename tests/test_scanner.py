from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from repo_public_audit.scanner import audit_repository, should_fail


class ScannerTests(unittest.TestCase):
    def test_flags_secret_like_value(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_basic_oss_files(root)
            fake_key = "sk-" + "testvalue12345678901234567890"
            (root / "settings.py").write_text(f"API_KEY='{fake_key}'\n", encoding="utf-8")

            result = audit_repository(root)

            self.assertTrue(any(f.rule == "openai-key" for f in result.findings))
            self.assertTrue(should_fail(result, "high"))

    def test_flags_risky_file_name(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_basic_oss_files(root)
            (root / ".env").write_text("DEBUG=true\n", encoding="utf-8")

            result = audit_repository(root)

            self.assertTrue(any(f.rule == "risky-path" and f.path == ".env" for f in result.findings))

    def test_missing_oss_files_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.py").write_text("print('hello')\n", encoding="utf-8")

            result = audit_repository(root)
            rules = {(f.rule, f.path) for f in result.findings}

            self.assertIn(("missing-file", "readme.md"), rules)
            self.assertIn(("missing-file", "license"), rules)

    def test_clean_basic_repo_has_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_basic_oss_files(root)
            (root / "src").mkdir()
            (root / "src" / "hello.py").write_text("print('hello')\n", encoding="utf-8")

            result = audit_repository(root)

            self.assertEqual((), result.findings)

    @unittest.skipIf(shutil.which("git") is None, "git is required for history scan tests")
    def test_history_scan_flags_removed_secret_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_git(root, "init")
            run_git(root, "config", "user.email", "test@example.com")
            run_git(root, "config", "user.name", "Test Maintainer")

            secret_line = "TOKEN=" + "notarealbutlongvalue"
            (root / ".env").write_text(secret_line + "\n", encoding="utf-8")
            run_git(root, "add", ".env")
            run_git(root, "commit", "-m", "Add temporary environment file")

            (root / ".env").unlink()
            write_basic_oss_files(root)
            (root / "main.py").write_text("print('clean now')\n", encoding="utf-8")
            run_git(root, "add", ".")
            run_git(root, "commit", "-m", "Clean public tree")

            result = audit_repository(root, include_history=True, history_commits=10)
            rules = {finding.rule for finding in result.findings}

            self.assertIn("history-risky-path", rules)
            self.assertIn("history-generic-secret-assignment", rules)
            self.assertTrue(should_fail(result, "high"))


def write_basic_oss_files(root: Path) -> None:
    (root / "README.md").write_text("# Demo\n", encoding="utf-8")
    (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
    (root / "CONTRIBUTING.md").write_text("# Contributing\n", encoding="utf-8")
    (root / "SECURITY.md").write_text("# Security\n", encoding="utf-8")
    (root / "CODE_OF_CONDUCT.md").write_text("# Code of Conduct\n", encoding="utf-8")


def run_git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    )


if __name__ == "__main__":
    unittest.main()
