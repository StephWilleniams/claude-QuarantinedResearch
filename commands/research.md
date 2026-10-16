---
description: Start a quarantined web research job on a question
argument-hint: <question>
---

Start a quarantined research job for the question below by running the launcher with the Bash tool. Pass the question on standard input with a quoted heredoc so nothing in it is interpreted by the shell:

```
"${CLAUDE_PLUGIN_ROOT}/bin/qr-launch" start <<'QR_BRIEF'
<the question, exactly as written below>
QR_BRIEF
```

Rules:
- Send only the question. Do not add context from this conversation, file contents, names, paths or anything private.
- If the launcher rejects the brief, tell me why and suggest a cleaned-up wording. Do not work around the check.
- After it starts, tell me the job id. Do not poll in a loop; I will ask for status, or you can run `"${CLAUDE_PLUGIN_ROOT}/bin/qr-launch" status <job id>` once when I ask.

Question:

$ARGUMENTS
