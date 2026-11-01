# Threat model

## Protected assets

`GITHUB_TOKEN` scopes, repository contents, release tags, automation credentials, runner filesystem, build artifacts and downstream supply-chain consumers.

## Attacker control assumptions

External contributors can influence pull request titles/bodies/head refs and repository content in their fork, issues or comments where allowed. Some workflows triggered by low-trust events may upload artifacts subsequently consumed by a more privileged `workflow_run` pipeline. The scanner does **not** assert any particular attacker has access to a specific repo.

## Threats modeled

1. Untrusted interpolation into a shell script generated from a `run` step.
2. Privileged workflows checking out PR-controlled revisions.
3. A cross-workflow artifact handoff to a subsequent execution-capable step.
4. Excessively permissive token scopes, persistent checkout credentials or unpinned action references.
5. Shared self-hosted runner use on lower-trust event handlers.

## Trust boundaries

`PR/fork -> workflow event -> job token/runner -> artifact upload -> workflow_run consumer -> script execution / repository mutation`.

## Design mitigations

The scanner never executes workflow content, never requires secrets or network credentials, uses a safe YAML loader, refuses duplicate mapping keys and aliases, enforces input limits, and reports the evidence linking each step. The integration pipeline runs with read-only token permissions and pinned action revisions.

## Non-goals and residual risks

- Not a complete GitHub Actions interpreter, abstract interpreter or taint engine.
- Dynamic `if:` conditions, reusable workflow internals, external actions behavior and runtime data provenance are not modeled.
- Untrusted event analysis depends on GitHub and organization settings, policies and trust decisions outside the YAML file.
- `workflow_dispatch` is treated as potentially untrusted to avoid claiming a security guarantee about authorized callers; this can produce false positives.
- Some `workflow_run` artifact consumers are safe because they only parse validated data; the model flags them conservatively if a subsequent step resembles execution.
- Malicious expressions in unexpected contexts and token access through third-party actions may not be detected.
- Action SHAs are syntax checked only; validity, ownership and vulnerability status are not checked online.
- Empty reports cannot certify an environment or replace code review, zizmor, CodeQL or dynamic checks.
