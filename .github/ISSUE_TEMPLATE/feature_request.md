---
name: Feature request
about: Suggest a new feature or improvement for GhostMap
title: "[FEATURE] "
labels: enhancement
assignees: yoshikatasergio
---

## Problem

Describe the operator pain point this feature would solve.
What's currently painful or missing?

## Proposed solution

Describe the feature you'd like.

## Scope considerations

GhostMap is intentionally narrow in scope. We do **not** add:

- Automated WAF bypass / stealth / rate-limit evasion
- New RCE vectors beyond what upstream sqlmap supports
- Auto-extraction of credentials / hashes / tokens
- Lateral movement / pivoting / port forwarding
- Disabling of defensive software on the target

If your feature falls into one of these categories, please open an
issue at https://github.com/sqlmapproject/sqlmap or build it as a
private fork.

## Alternatives considered

What other approaches did you think about?

## Additional context

Any other context, screenshots, or examples.
