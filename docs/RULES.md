# Security findings — rules and remediation

Rules refer to declared workflow intent. They are **heuristics**, and finding severity is a prioritization aid rather than an empirically proven exploitability rating.

| Rule | Severity | Detection | Practical mitigation |
| --- | --- | --- | --- |
| TG001 | medium | Implicit token permission defaults | Set `permissions: {contents: read}` or `permissions: {}` explicitly. |
| TG002 | medium | Any explicitly writable token permission | Narrow to the minimum job and scope. |
| TG003 | high for `pull_request_target`, otherwise medium unless issue comments reference secrets | Potentially privileged event with write permission or secrets | Separate privileges, validate provenance and restrict token. |
| TG004 | high | Lower-trust trigger on `self-hosted` | Isolate ephemeral runners, avoid shared persistent runners. |
| TG005 | medium | Remote action not syntactically SHA/digest pinned | Pin full immutable SHA verified with GitHub. |
| TG006 | high | Untrusted event expression directly in `run` | Pass expressions through `env:` and quote values as data. |
| TG007 | critical/high | Privileged event checks out PR head revision | Don't run untrusted code with elevated privileges. |
| TG008 | low | Checkout persists credentials in privileged job | `persist-credentials: false` if feasible. |
| TG009 | critical/high | Untrusted workflow uploaded artifact, downstream workflow_run downloads and has a later execution-like step | Verify data origin and integrity; never execute artifact-controlled scripts. |

**Notes:** Rule TG003 is a context/risk indicator; `workflow_run` itself is not a vulnerability. TG009 requires a same-name producer, an upload-artifact step, a workflow_run linkage, a download-artifact step and a later command resembling execution. It does not establish that downloaded content was executed. Actions pinned by SHA might still be compromised or vulnerable. TG006 is limited to known attacker-influenced context members (e.g., `github.event.pull_request.title`, `github.head_ref`).
