#!/usr/bin/env python3
"""tools/test-affected.py against the workspace's AGENTS.md: its table and the helper's can't
drift apart. Outside the workspace there is no table to hold it to, and it says so."""

import importlib.util
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
AGENTS = os.path.join(os.path.dirname(os.path.dirname(HERE)), "AGENTS.md")


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, file))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


affected = load("test_affected", "test-affected.py")
proof = load("proof", "proof.py")


def agents_table():
    """AGENTS.md's table under "What to test after a change": (Changed, Run) per row."""
    with open(AGENTS) as f:
        section = f.read().split("### What to test after a change", 1)[1]
    rows = [[c.strip() for c in l.strip().strip("|").split(" | ")] for l in section.splitlines() if l.startswith("|")]
    return [tuple(r) for r in rows[2:]]


class Table(unittest.TestCase):
    @unittest.skipUnless(os.path.exists(AGENTS), "not in the workspace: no AGENTS.md to hold the table to")
    def test_rows_are_the_agents_table_word_for_word(self):
        self.assertEqual(agents_table(), [(r.changed, r.run) for r in affected.ROWS])

    def test_every_part_is_a_part_of_the_proof(self):
        known = proof.parts_table("/nonexistent")
        for r in affected.ROWS:
            for part in r.parts:
                self.assertIn(part, known, r.changed)


class Paths(unittest.TestCase):
    def rows(self, project, path):
        return [r.changed for r in affected.rows_of(project, path)]

    def test_paths(self):
        boot, installed, core = "kira's boot, close or unlock", "Installed-system code of kira (`control`, `status`, the admin commands)", "`kira/core/`"
        argon = "Argon2id, or what memory the boot takes"
        for project, path, want in (
            ("kira", "docs/TESTING.md", ["Docs only"]),
            ("assh", "README.md", ["Docs only"]),
            ("kira", "core/README.md", ["Docs only"]),
            ("kira", "tools/vmtest.py", ["Test tools"]),
            ("kira", "internal/admin/control.go", [installed]),
            ("kira", "main.go", [installed]),
            ("kira", "initramfs/systemd/kira.service", [boot]),
            ("kira", "internal/bootclose/close.go", [boot]),
            ("kira", "internal/diskkey/combine.go", [boot, argon]),
            ("kira", "core/attest/quote.go", [core]),
            ("assh", "server/server.go", ["`assh/`"]),
            ("kira", "assh", ["`assh/`"]),
            ("safearch", "assh", ["`assh/`"]),
            ("kira", "go-uefi-slim", ["`go-uefi-slim/`"]),
            ("kira", "tpm2-verifier", ["`tpm2-verifier/`"]),
            ("kira-vault", "kira", [core]),
            ("kira-vault", "main.go", ["`kira-vault/`"]),
            ("safearch", "build.sh", ["`safearch/`"]),
            ("go-uefi-slim", "uki/uki.go", ["`go-uefi-slim/`"]),
            ("go-tui-slim", "tui/frame.go", ["`go-tui-slim/`"]),
            ("kira", "go-tui-slim", ["`go-tui-slim/`"]),
            ("assh", "go-tui-slim", ["`go-tui-slim/`"]),
            ("tpm2-verifier", "ekroots/roots.go", ["`tpm2-verifier/`"]),
            ("marify", "android/app/x.kt", []),
            ("marify", "core.properties", [core]),
        ):
            self.assertEqual(self.rows(project, path), want, f"{project}/{path}")

    def test_parts_each_once_in_the_tables_order(self):
        rows = [r for r in affected.ROWS if r.changed in ("`kira/core/`", "`assh/`")]
        self.assertEqual(affected.parts_of(rows), ["test-all", "machines", "vault", "marify", "assh", "safearch-run"])


if __name__ == "__main__":
    unittest.main()
