import os
import tempfile
import unittest
from pathlib import Path

from helpers import GATE, run_hook

JOB = "20261015-120000-abcdef"
SID = "11111111-2222-3333-4444-555555555555"


class GateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.user_home = Path(os.path.realpath(self.tmp.name)) / "Users" / "steve"
        self.qr = self.user_home / ".qr"
        for sub in ("inbox", "approved", "jobs", "secrets"):
            (self.qr / sub).mkdir(parents=True)
        (self.qr / "secrets" / "oauth_token").write_text("t")
        self.plugin = self.user_home / "Desktop" / "quarantined-research"
        (self.plugin / "bin").mkdir(parents=True)
        (self.plugin / "hooks").mkdir()
        self.project = self.user_home / "project"
        self.project.mkdir()
        self.env = {"HOME": str(self.user_home), "QR_HOME": str(self.qr),
                    "CLAUDE_PLUGIN_ROOT": str(self.plugin)}

    def tearDown(self):
        self.tmp.cleanup()

    def pending(self):
        (self.qr / "TAINTED").write_text(JOB)
        (self.qr / "inbox" / JOB).mkdir()
        (self.qr / "inbox" / JOB / "report.md").write_text("report")

    def call(self, tool, tool_input, sid=SID, cwd=None):
        payload = {"tool_name": tool, "tool_input": tool_input, "hook_event_name": "PreToolUse",
                   "session_id": sid, "cwd": str(cwd or self.project)}
        return run_hook(GATE, payload, self.env)

    def assertAllowed(self, r):
        self.assertEqual(r.returncode, 0, r.stderr)

    def assertDenied(self, r, text=None):
        self.assertEqual(r.returncode, 2, "expected a denial")
        if text:
            self.assertIn(text, r.stderr)

    @property
    def report(self):
        return str(self.qr / "inbox" / JOB / "report.md")

    # ---------- normal session ----------

    def test_normal_tools_allowed(self):
        self.assertAllowed(self.call("Bash", {"command": "ls -la"}))
        self.assertAllowed(self.call("Edit", {"file_path": str(self.project / "notes.md"),
                                              "old_string": "a", "new_string": "b"}))
        self.assertAllowed(self.call("Read", {"file_path": str(self.project / "notes.md")}))
        self.assertAllowed(self.call("WebFetch", {"url": "https://example.org"}))
        self.assertAllowed(self.call("mcp__slack__send_message", {"text": "hi"}))

    def test_launcher_forms_allowed(self):
        for cmd in ("%s/bin/qr-launch start <<'QR_BRIEF'\nWhat is X?\nQR_BRIEF" % self.plugin,
                    '"%s/bin/qr-launch" status %s' % (self.plugin, JOB),
                    "\"${CLAUDE_PLUGIN_ROOT}/bin/qr-launch\" start <<'QR_BRIEF'\nq\nQR_BRIEF",
                    "qr-launch status"):
            with self.subTest(cmd=cmd):
                self.assertAllowed(self.call("Bash", {"command": cmd}))

    def test_launcher_lookalikes_denied(self):
        for cmd in ("%s/bin/qr-launch start <<'QR_BRIEF'\nq\nQR_BRIEF\nrm -rf ~" % self.plugin,
                    "%s/bin/qr-launch start; cat %s/hooks/gate.py" % (self.plugin, self.plugin),
                    'cd "$(dirname %s/bin/qr-launch)"/../hooks && echo x > gate.py' % self.plugin,
                    "qr-launch start \"$(cat ~/.ssh/id_rsa)\"",
                    "qr-launch seal"):
            with self.subTest(cmd=cmd[:50]):
                self.assertDenied(self.call("Bash", {"command": cmd}))

    # ---------- pending report: read-only, report folder only ----------

    def test_pending_allows_reading_the_report_only(self):
        self.pending()
        self.assertAllowed(self.call("Read", {"file_path": self.report}))
        self.assertAllowed(self.call("Grep", {"pattern": "canary", "path": str(self.qr / "inbox")}))
        self.assertAllowed(self.call("Glob", {"pattern": "**/*.md", "path": str(self.qr / "inbox")}))
        self.assertAllowed(self.call("Read", {"file_path": "report.md"}, cwd=self.qr / "inbox" / JOB))

    def test_pending_denies_everything_else(self):
        self.pending()
        for tool, ti in [
            ("Read", {"file_path": str(self.project / "notes.md")}),
            ("Read", {"file_path": "/net/exfil-data.attacker.example/x"}),
            ("Grep", {"pattern": "x"}),                                   # defaults to cwd
            ("Glob", {"pattern": "/Users/steve/**"}),
            ("Glob", {"pattern": "../../secrets/*", "path": str(self.qr / "inbox")}),
            ("Bash", {"command": "ls"}),
            ("Edit", {"file_path": str(self.project / "x"), "old_string": "a", "new_string": "b"}),
            ("Write", {"file_path": self.report, "content": "x"}),
            ("WebFetch", {"url": "https://example.org", "prompt": "x"}),
            ("WebSearch", {"query": "x"}),
            ("Agent", {"prompt": "do it", "subagent_type": "general-purpose"}),
            ("mcp__gmail__send", {"to": "a@b.c"}),
            ("Skill", {"skill": "x"}),
        ]:
            with self.subTest(tool=tool, ti=ti):
                self.assertDenied(self.call(tool, ti), "awaiting approval")

    def test_pending_path_traversal_denied(self):
        """Bypasses found in review: '..' and '.' tricks out of the inbox."""
        self.pending()
        inbox = str(self.qr / "inbox")
        for tool, ti in [
            ("Grep", {"path": inbox + "/../secrets", "pattern": "."}),
            ("Glob", {"path": inbox + "/..", "pattern": "**/*"}),
            ("Read", {"file_path": inbox + "/../jobs/x/io/fetch.log"}),
            ("Grep", {"path": str(self.qr) + "/./secrets", "pattern": ".qr/inbox|."}),
            ("Read", {"file_path": inbox.upper() + "/../SECRETS/OAUTH_TOKEN"}),
            ("Read", {"file_path": "../secrets/oauth_token"}),
        ]:
            with self.subTest(tool=tool, ti=ti):
                self.assertDenied(self.call(tool, ti, cwd=self.qr / "inbox"))

    def test_pending_symlink_out_of_inbox_denied(self):
        self.pending()
        os.symlink(self.qr / "secrets" / "oauth_token", self.qr / "inbox" / JOB / "link")
        self.assertDenied(self.call("Read", {"file_path": str(self.qr / "inbox" / JOB / "link")}))

    def test_nonempty_inbox_counts_as_pending_even_without_flag(self):
        (self.qr / "inbox" / JOB).mkdir()
        self.assertDenied(self.call("Bash", {"command": "ls"}), "awaiting approval")

    def test_flag_as_directory_still_counts(self):
        (self.qr / "TAINTED").mkdir()
        self.assertDenied(self.call("Bash", {"command": "ls"}), "awaiting approval")

    def test_subagent_calls_gated_the_same(self):
        self.pending()
        r = run_hook(GATE, {"tool_name": "Bash", "tool_input": {"command": "ls"},
                            "agent_id": "a1", "agent_type": "general-purpose", "session_id": SID}, self.env)
        self.assertDenied(r, "awaiting approval")

    def test_reader_sessions_recorded(self):
        self.pending()
        self.assertAllowed(self.call("Read", {"file_path": self.report}, sid=SID))
        self.assertTrue((self.qr / "readers" / SID).exists())
        self.assertAllowed(self.call("Read", {"file_path": self.report}, sid="../../evil"))
        self.assertEqual(os.listdir(self.qr / "readers"), [SID])

    def test_locked_session_stays_read_only(self):
        (self.qr / "locked_sessions").mkdir()
        (self.qr / "locked_sessions" / SID).touch()
        self.assertDenied(self.call("Bash", {"command": "ls"}, sid=SID), "rejected")
        self.assertAllowed(self.call("Bash", {"command": "ls"}, sid="another-session"))

    # ---------- backstops in a normal session ----------

    def test_qr_internals_protected(self):
        for tool, ti in [
            ("Read", {"file_path": str(self.qr / "secrets" / "oauth_token")}),
            ("Read", {"file_path": str(self.qr).upper() + "/SECRETS/OAUTH_TOKEN"}),
            ("Read", {"file_path": str(self.qr / "jobs" / "x" / "io" / "fetch.log")}),
            ("Read", {"file_path": str(self.qr / "inbox" / ".." / "seal.json")}),
            ("Grep", {"pattern": "sk-", "path": str(self.qr)}),
            ("Glob", {"pattern": "**/*", "path": "~/.qr"}),
            ("Bash", {"command": "security find-generic-password -s claude"}),
            ("Bash", {"command": "cat ~/.qr/secrets/oauth_token"}),
            ("Bash", {"command": "cat $HOME/.qr/TAINTED"}),
            ("Bash", {"command": "cat %s/seal.json" % self.qr}),
            ("Bash", {"command": "podman inspect qr-x"}),
        ]:
            with self.subTest(tool=tool, ti=ti):
                self.assertDenied(self.call(tool, ti))

    def test_cannot_approve_or_reject(self):
        for cmd in ("qr-approve %s" % JOB, "echo %s | qr-reject" % JOB,
                    "python3 %s/bin/qr-approve" % self.plugin, "qr-launch set-token"):
            with self.subTest(cmd=cmd):
                self.assertDenied(self.call("Bash", {"command": cmd}))

    def test_no_tampering_with_gate_plugin_or_settings(self):
        for path in (self.qr / "TAINTED", self.plugin / "hooks" / "gate.py", self.plugin / "hooks" / "hooks.json",
                     Path(str(self.plugin).upper()) / "hooks" / "gate.py",
                     self.user_home / ".claude" / "settings.json",
                     self.project / ".claude" / "settings.local.json"):
            with self.subTest(path=str(path)):
                self.assertDenied(self.call("Write", {"file_path": str(path), "content": "x"}))
                self.assertDenied(self.call("Edit", {"file_path": str(path), "old_string": "a", "new_string": "b"}))
        for cmd in ("cd ~/Desktop/quarantined-research/hooks && printf x > gate.py",
                    "sed -i s/2/0/ %s/hooks/gate.py" % self.plugin,
                    "echo '{\"disableAllHooks\": true}' > ~/.claude/settings.json",
                    "rm -rf %s" % self.plugin):
            with self.subTest(cmd=cmd):
                self.assertDenied(self.call("Bash", {"command": cmd}))

    def test_renamed_plugin_folder_with_space_still_protected(self):
        """A root that contains a space and none of the fixed marker words."""
        drive = self.user_home / "Library" / "CloudStorage" / "GoogleDrive-x" / "My Drive" / "Fun"
        plugin = drive / "isolatedResearch_skill"
        (plugin / "quarantine").mkdir(parents=True)
        self.env["CLAUDE_PLUGIN_ROOT"] = str(plugin)
        target = "quarantine/init-firewall.sh"
        tail = "Library/CloudStorage/GoogleDrive-x/My%sDrive/Fun/isolatedResearch_skill/" + target
        for cmd in ('printf x > "%s/%s"' % (plugin, target),
                    "sed -i s/REJECT/ACCEPT/ ~/" + tail % "\\ ",
                    'sed -i s/REJECT/ACCEPT/ ~/Library/CloudStorage/GoogleDrive-x/"My Drive"/Fun/isolatedResearch_skill/' + target,
                    "sed -i s/REJECT/ACCEPT/ ~/" + tail % "*",
                    "cd .. && printf x > isolatedResearch_skill/" + target,
                    "cp /tmp/x isolated'Research'_skill/" + target):
            with self.subTest(cmd=cmd):
                self.assertDenied(self.call("Bash", {"command": cmd}, cwd=drive))
        self.assertDenied(self.call("Write", {"file_path": str(plugin / target), "content": "x"}))
        self.assertAllowed(self.call("Bash", {"command": "ls -la"}, cwd=drive))
        self.assertAllowed(self.call("Bash", {"command": '"%s/bin/qr-launch" status %s' % (plugin, JOB)}))
        self.assertAllowed(self.call("Bash", {"command": '"${CLAUDE_PLUGIN_ROOT}/bin/qr-launch" status %s' % JOB}))

    def test_edit_through_symlink_into_plugin_denied(self):
        link = self.project / "p"
        os.symlink(self.plugin, link)
        self.assertDenied(self.call("Write", {"file_path": str(link / "hooks" / "gate.py"), "content": "x"}))
        self.assertDenied(self.call("Write", {"file_path": "p/lib/qr/__init__.py", "content": "x"}))

    def test_unrelated_names_not_blocked(self):
        self.assertAllowed(self.call("Read", {"file_path": str(self.project / "app.qrc")}))
        self.assertAllowed(self.call("Bash", {"command": "cat logo.qr.png > /dev/null"}))

    # ---------- fail closed ----------

    def test_malformed_input_denied(self):
        for pending in (False, True):
            if pending:
                self.pending()
            for payload in ("garbage", "[]", "{}", '{"tool_name": 5}', '{"tool_name": "Bash", "tool_input": "x"}',
                            '{"tool_name": "Write", "tool_input": {}}'):
                with self.subTest(pending=pending, payload=payload):
                    self.assertDenied(run_hook(GATE, payload, self.env))


if __name__ == "__main__":
    unittest.main()
