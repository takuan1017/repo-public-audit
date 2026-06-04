# repo-public-audit

[![CI](https://github.com/takuan1017/repo-public-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/takuan1017/repo-public-audit/actions/workflows/ci.yml)
[![Weekly Maintenance](https://github.com/takuan1017/repo-public-audit/actions/workflows/weekly-maintenance.yml/badge.svg)](https://github.com/takuan1017/repo-public-audit/actions/workflows/weekly-maintenance.yml)

`repo-public-audit` is a small CLI that checks a repository before you make it public.

It is designed for maintainers who want a quick, local answer to questions like:

- Did I accidentally leave secrets, tokens, or private keys in the current tree?
- Are there obviously sensitive filenames or business-only documents?
- Is the repo missing basic open-source hygiene such as a README, license, contribution guide, or security policy?
- What should I fix before sharing the repository publicly?

The tool is intentionally conservative: a warning is not proof of a leak, and a clean report is not proof of safety. It gives you a focused checklist before you publish.

## Install

From a local checkout:

```bash
python -m pip install -e .
```

## Usage

Audit the current repository:

```bash
repo-public-audit .
```

Return JSON for automation:

```bash
repo-public-audit . --format json
```

Fail CI when high-severity findings are present:

```bash
repo-public-audit . --fail-on high
```

Run a bounded Git history scan before making a repository public:

```bash
repo-public-audit . --history --history-commits 50 --fail-on high
```

## What It Checks

Current-tree risk checks:

- Secret-like values, including common API key, token, private key, and credential patterns
- Sensitive filenames such as `.env`, `id_rsa`, `credentials.json`, and database dumps
- Business-sensitive keywords in file paths and text
- Oversized files that may be inappropriate for source control

Optional Git history checks:

- Risky file paths that existed in recent commits
- Secret-like values in bounded historical blobs
- Conservative commit and blob-size limits to keep scans usable on normal repositories

OSS readiness checks:

- `README`
- `LICENSE`
- `CONTRIBUTING`
- `SECURITY`
- `CODE_OF_CONDUCT`
- issue templates or pull request templates

## Example Output

```text
repo-public-audit: 3 findings

[high] risky-path: .env
  Secret-like or environment-specific file name should not be public.

[medium] missing-file: LICENSE
  Add an open-source license before inviting reuse.

[low] missing-file: SECURITY.md
  Add a security policy so reporters know where to send issues.
```

## Scope

History scanning is bounded by commit count and blob size. If a secret has ever been committed, treat it as exposed and rotate it even if the scanner output is clean.

## Roadmap

- Git history scanning with bounded commit and file-size controls
- SARIF output for GitHub code scanning
- Configurable allowlist rules
- GitHub repository metadata checks
- Better language-specific secret detectors

See `docs/codex-for-oss-application-plan.md` for the current maintainer roadmap.

## Contributing

Issues and pull requests are welcome. Start with `CONTRIBUTING.md`.

## License

MIT
