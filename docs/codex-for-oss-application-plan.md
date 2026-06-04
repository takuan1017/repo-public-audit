# Codex for OSS Application Plan

This is a maintainer roadmap for making `repo-public-audit` useful as a real open-source project before applying to Codex for Open Source.

The goal is not to manufacture activity. The goal is to produce visible, reviewable maintenance work that improves the project for future users.

## Positioning

`repo-public-audit` helps maintainers answer a practical pre-release question:

> Is this repository safe and ready to make public?

The project is useful for solo developers, maintainers, and small teams who want a local, conservative audit before opening a repository.

## Two-Week Plan

### Week 1: Core Utility

- Add bounded Git history scanning. Done in `v0.2.0` scope.
- Add configurable allowlist rules.
- Improve CLI output with summary counts by severity.
- Add more tests for false positives and sensitive path detection.
- Keep CI and weekly maintenance green.

### Week 2: Maintainer Readiness

- Add SARIF output for GitHub code scanning.
- Add GitHub metadata checks for README, license, topics, issues, and security policy.
- Add example reports in `docs/examples/`.
- Cut a `v0.2.0` release.
- Prepare the Codex for OSS application text with project scope, maintainer role, and API-credit use cases.

## Application Evidence to Build

- Public repo with a clear README and MIT license.
- Passing CI.
- Scheduled daily readiness check.
- Scheduled weekly maintenance report PR.
- Open roadmap issues.
- Versioned releases.
- Practical use case connected to OSS maintainership.

## Automation Policy

Automation should keep the maintainer loop tight without manufacturing fake activity.

- Daily automation checks tests and public-readiness only.
- Weekly automation creates a reviewable maintenance report PR.
- Code changes should still be meaningful and reviewed.
- Empty commits, cosmetic churn, and artificial contribution inflation are out of scope.

## Application Draft Notes

Primary reason for eligibility:

```text
I maintain repo-public-audit, an open-source CLI that helps maintainers audit repositories before making them public. It detects secret-like values, risky file paths, and missing OSS readiness files so maintainers can publish code more safely. Codex would help accelerate detectors, tests, documentation, and security-focused review workflows.
```

API-credit use:

```text
API credits would be used to prototype and evaluate repository-risk explanations, issue triage, test generation, documentation improvements, and maintainer automation around public-release safety checks.
```

## Weekly Maintenance Checklist

- Review open issues.
- Pick one small implementation or documentation task.
- Run local tests.
- Run `repo-public-audit . --history --history-commits 50 --fail-on high`.
- Push a real change only when there is a real improvement.
