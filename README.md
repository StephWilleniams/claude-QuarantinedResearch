# quarantined-research (phase 1)

A Claude Code plugin that runs web research in a throwaway Podman container and returns a sanitized report. While a report is waiting, your Claude session can only read the report folder; you approve or reject it from your own terminal. A session that read a report you rejected stays read-only for good.

Design: see the "Quarantined Deep Research — Architecture" doc.

## What is in phase 1

| Piece | File |
| --- | --- |
| Worker image (Claude Code, web search and fetch only, no shell, no file tools) | `quarantine/Containerfile`, `quarantine/entrypoint.sh` |
| Egress firewall (HTTPS to public addresses only; private, link-local and IPv6 blocked) | `quarantine/init-firewall.sh` |
| Worker permissions and guard hook (logs every call; blocks other tools, canary leaks, suspicious URLs; fetch and search caps) | `quarantine/settings.json`, `quarantine/hooks/fetch_guard.py` |
| Worker instructions and output format | `quarantine/worker-prompt.md` |
| Validator, sanitizer, report renderer | `lib/qr/validate.py`, `lib/qr/sanitize.py`, `lib/qr/render.py` |
| Launcher, approve, reject | `bin/qr-launch`, `bin/qr-approve`, `bin/qr-reject` |
| Main-session gate | `hooks/hooks.json`, `hooks/gate.py` |
| Tamper tripwire (seal of the plugin's files, checked before starting and unlocking) | `lib/qr/integrity.py` |
| Skill and `/research` command | `skills/quarantined-research/SKILL.md`, `commands/research.md` |
| Tier 1 tests (no network, no model) | `tests/` |

Changes from the doc, made during the build:

- The worker returns its claims as its final message instead of writing a file, so it has no file tools at all and no write guard is needed.
- The canary, suspicious-URL checks and caps (planned for phase 2) were simple enough to include in the guard now.
- Raw worker output is deleted once the report is built; only the sanitized report survives.
- After an independent security review: while a report is pending, Claude can read only the report folder (not your other files); sessions that read a rejected report stay locked; approve and launch refuse to run if the plugin's files changed since you sealed them; Claude's shell may not run `podman`.

## One-time setup (in your own terminal)

1. Podman machine. On macOS, containers run inside the Podman VM:
   `podman machine init --cpus 4 --memory 4096` (skip if you already have one), then `podman machine start`.
2. Put the scripts on your PATH, for example add this to `~/.zshrc`:
   `export PATH="/path/to/isolatedResearch_skill/bin:$PATH"`
   (use the real path to this folder, and keep the quotes if it contains spaces)
3. Build the worker image. This is the only step that downloads packages (Debian, npm):
   `qr-launch build`
4. Seal the plugin's files (re-run this after any deliberate change to the plugin):
   `qr-launch seal`
5. Create a subscription token and save it:
   `claude setup-token`, copy the token it prints, then `qr-launch set-token` and paste it (input is hidden). It is stored in `~/.qr/secrets/oauth_token` with mode 600. The token lasts a year; treat it like a password.
6. Make sure `ANTHROPIC_API_KEY` is not set in the shell that starts jobs, or the launcher will remove it from the worker's environment so runs stay on your subscription.
7. Load the plugin: `claude --plugin-dir "/path/to/isolatedResearch_skill"`.

## Using it

- In Claude Code: `/research <question>`. Claude starts the job and gives you a job id.
- When the job finishes, the report lands in `~/.qr/inbox/<job id>/report.md` and every Claude session can read only the report folder. Ask Claude to read the report and help you review it.
- In your own terminal: `qr-approve` (or `qr-reject`). It checks the seal, shows the report, then asks you to type the job id.
- After a reject, the sessions that read that report stay locked. Start a new one.

## Tests

`python3 -m unittest discover -s tests -v` runs the tier 1 tests: no network, no model calls, no containers. Tier 2 (model in the loop on synthetic pages) comes in phase 2.

## Not yet verified on your machine

These need your Mac, Podman and Claude Code, and none of them involve fetching real web pages:

- The image builds, and the Claude Code version inside it supports `--restricted` (the entrypoint refuses to run if not).
- The firewall works inside the Podman VM with the capabilities the launcher grants.
- Files written by the container into `~/.qr/jobs/<id>/io` are readable by you on the Mac side.
- The plugin loads and the gate hook fires: in your terminal run `mkdir -p ~/.qr && touch ~/.qr/TAINTED`, ask Claude to run `ls`, expect a denial, then `rm ~/.qr/TAINTED`.

## Known limits

- String matching on shell commands is a backstop, not a boundary. The firm guarantee is narrower: while a report is pending, only Read, Grep and Glob run, and only inside the report folders.
- The seal is a tripwire, not a lock: anything running as your user could also rewrite `~/.qr/seal.json`.
- Approving unlocks the sessions that read the report, by design. Approve only reports you trust.
- The gate blocks Claude from running `podman` at all, to keep the token out of `podman inspect`.
- If the worker's web fetch runs on Anthropic's servers rather than in the container, the container firewall does not see those requests; the guard's log and URL checks still apply.
