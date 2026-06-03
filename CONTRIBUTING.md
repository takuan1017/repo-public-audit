# Contributing

Thanks for helping improve `repo-public-audit`.

## Development Setup

```bash
python -m pip install -e .
python -m unittest
```

## Pull Request Guidelines

- Keep rules conservative and explain why a finding should exist.
- Add tests for new detectors.
- Avoid collecting or transmitting repository contents.
- Do not add network calls to the scanner path unless there is a strong reason.

## Good First Issues

- Add a detector for another common credential format.
- Improve output formatting.
- Add documentation examples for CI usage.

