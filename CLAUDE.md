# quarantined-research

A Claude Code plugin that runs web research in a throwaway Podman container, returns a sanitized report, and keeps the main session read-only until the user approves the report in their own terminal. Design and threat model: see README.md and the "Quarantined Deep Research — Architecture" doc.

## Rules for working on this project

- **No live web testing.** Never fetch real web pages to test anything. Tests use synthetic inputs only. Downloading packages to build the image (Debian, npm) is fine; research runs are not.
- **Don't load this plugin in the session that develops it.** Its gate hook blocks edits to this folder and blocks `podman`, by design. Develop in a plain session (`claude` in this folder); test the plugin in a separate session started with `claude --plugin-dir "/path/to/isolatedResearch_skill"` (use the real path to this folder, and keep the quotes if it contains spaces).
- **Hands off the user-only steps.** Never run `qr-launch set-token`, `qr-launch seal`, `qr-approve` or `qr-reject`, never run `claude setup-token`, and never read or print anything under `~/.qr/secrets`. These scripts refuse to run without a terminal anyway; do not work around that.
- **Ask before** changing shell profiles (`~/.zshrc`), creating or deleting a Podman machine, or anything outside this folder.
- After any code change, run `python3 -m unittest discover -s tests` and tell the user to re-run `qr-launch seal` in their own terminal.
- Security-relevant changes (gate, guard, sanitizer, firewall, entrypoint) get an independent review by a subagent before the user re-seals.

## Setup checklist

Claude can do steps 1 to 6 in a plain session. Steps 7 to 10 belong to the user, in their own terminal.

1. Check tools: `python3 --version` (3.9 or newer), `podman --version`, `podman machine list`. If there is no running machine, propose `podman machine init --cpus 4 --memory 4096` and `podman machine start`, and ask first.
2. Version control: `git init`, check that `.gitignore` covers caches, then make a first commit of the files as they are.
3. Run the tier 1 tests on macOS: `python3 -m unittest discover -s tests -v`. All should pass.
4. Build the worker image: `podman build -t qr-worker:latest -f quarantine/Containerfile quarantine`.
5. Check the image, with no token and no research:
   - `podman run --rm --entrypoint claude qr-worker:latest --version` shows 2.1.301.
   - `podman run --rm --entrypoint claude qr-worker:latest --help | grep -- --restricted` finds the flag.
6. Check the container pieces that could not be tested before. None of these reach the web:
   - Firewall: `podman run --rm --cap-drop=ALL --cap-add=NET_ADMIN --cap-add=NET_RAW --sysctl net.ipv6.conf.all.disable_ipv6=1 --entrypoint /bin/bash qr-worker:latest -c '/opt/qr/init-firewall.sh && iptables -S OUTPUT'`. It should print the rules, ending in a final REJECT.
   - Worker home: `podman run --rm --read-only --cap-drop=ALL --cap-add=SETUID --cap-add=SETGID --cap-add=SETPCAP --security-opt=no-new-privileges --tmpfs /home/worker:rw,size=16m,mode=1777 --entrypoint /bin/bash qr-worker:latest -c 'setpriv --reuid=worker --regid=worker --init-groups --inh-caps=-all --bounding-set=-all --no-new-privs sh -c "mkdir -p /home/worker/qr && stat -c \"%u %g %a\" /home/worker/qr"'`. Expect `10001 10001 755`: the worker can create and own its files. (Podman's `--tmpfs` does not accept `uid=`/`gid=`, so the home tmpfs is mode 1777.)
   - Job folder writes: make a temporary folder, mount it with `-v <folder>:/job:rw`, run `--entrypoint /bin/sh qr-worker:latest -c 'echo ok > /job/t'`, then confirm the file is readable on the Mac and owned by the user.
   - Report each result to the user. If a check fails, propose a fix, get an independent review if it is security-relevant, and rerun the tests.
7. (User) Add the scripts to PATH in `~/.zshrc`: `export PATH="/path/to/isolatedResearch_skill/bin:$PATH"`.
8. (User) `qr-launch seal`.
9. (User) `claude setup-token`, then `qr-launch set-token`, and paste the token.
10. (User) Start a separate session with the plugin loaded, using `claude --plugin-dir` with the quoted path above, then check the gate. In a terminal: `mkdir -p ~/.qr && touch ~/.qr/TAINTED`. Ask Claude to run `ls`; it should be refused. Then `rm ~/.qr/TAINTED`.
