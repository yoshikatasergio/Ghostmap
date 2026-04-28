---
name: Bug report
about: Report a bug in GhostMap (Yoshi Edition)
title: "[BUG] "
labels: bug
assignees: yoshikatasergio
---

## Description

Describe the bug clearly and concisely.

## Reproduction

Command line you ran (REDACT the target host before pasting):

```bash
python sqlmap.py -u "https://<REDACTED>/?id=1" --batch --random-agent ...
```

## Expected behavior

What you expected to happen.

## Actual behavior

What actually happened.

## Diagnostic dump (recommended)

If possible, attach the `--sergio` diagnostic dump. The dump is engineered
to be safe to share — it does NOT contain your target's URL, parameter
values, cookies, or response bodies.

To generate it: re-run with `--sergio` and find the file at
`output/<engagement>/ghostmap-sergio-<timestamp>.txt`.

## Environment

- GhostMap version: (from `python sqlmap.py --version`)
- Python version: (from `python --version`)
- OS: Windows / Linux / macOS

## Additional context

Any other context about the problem.
