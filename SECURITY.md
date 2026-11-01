# Security policy

Supported releases: **1.x**. Security reports should not be opened as public GitHub issues if they contain exploitable details or sensitive repository data. Use GitHub's **Report a vulnerability** / private vulnerability reporting when enabled, or contact the repository owner by an agreed private channel. Do not include access tokens, secrets, or private workflow files in a report. Fixes will be tested, reviewed, and released with changelog entries. No guaranteed response or SLA is implied.

This project **only reads local workflow definitions**. It does not run scripts, call Kubernetes, or access a GitHub API token. Analyses are conservative heuristics; a green result does not guarantee a secure pipeline. Running the tool on unknown content should still take place in an isolated, unprivileged environment.
