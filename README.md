# repo-public-audit

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

## What It Checks

Current-tree risk checks:

- Secret-like values, including common API key, token, private key, and credential patterns
- Sensitive filenames such as `.env`, `id_rsa`, `credentials.json`, and database dumps
- Business-sensitive keywords in file paths and text
- Oversized files that may be inappropriate for source control

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

This project currently scans the working tree. It does not yet perform a complete Git history rewrite audit. If a secret has ever been committed, treat it as exposed and rotate it.

## Roadmap

- Git history scanning with bounded commit and file-size controls
- SARIF output for GitHub code scanning
- Configurable allowlist rules
- GitHub repository metadata checks
- Better language-specific secret detectors

## Contributing

Issues and pull requests are welcome. Start with `CONTRIBUTING.md`.

## License

MIT

