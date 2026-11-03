"""Unit tests for fscan argument construction (no fscan binary required)."""
from __future__ import annotations

import unittest
from pathlib import Path

from app.scanner import build_args, quote_cmd

FSCAN = r"C:\tools\fscan.exe"
RESULT = Path("result.json")


def base_config(**overrides):
    cfg = {
        "target": "127.0.0.1",
        "mode": "all",
        "ports_preset": "custom",
        "ports": "80,443",
        "threads": 100,
        "timeout": 2,
        "brute": False,
        "poc": False,
        "redis": False,
    }
    cfg.update(overrides)
    return cfg


class BuildArgsTests(unittest.TestCase):
    def test_url_target_uses_web_mode(self):
        args = build_args(base_config(target="https://example.com/login"), FSCAN, RESULT)
        self.assertIn("-u", args)
        self.assertIn("https://example.com/login", args)
        self.assertNotIn("-h", args)
        self.assertNotIn("-p", args)

    def test_mixed_url_and_host_is_rejected(self):
        with self.assertRaises(ValueError):
            build_args(base_config(target="127.0.0.1\nhttps://example.com"), FSCAN, RESULT)

    def test_custom_ports_and_flags(self):
        args = build_args(base_config(ports="8000-8100", brute=True, poc=True), FSCAN, RESULT)
        self.assertEqual(args[args.index("-p") + 1], "8000-8100")
        self.assertNotIn("-nobr", args)
        self.assertNotIn("-nopoc", args)

    def test_plugin_mode_requires_plugins(self):
        with self.assertRaises(ValueError):
            build_args(base_config(mode="plugin", plugins=""), FSCAN, RESULT)

    def test_custom_args_keep_quoted_paths(self):
        args = build_args(
            base_config(custom_args='-userf "C:\\dict\\users.txt" -debug'),
            FSCAN,
            RESULT,
        )
        self.assertIn(r"C:\dict\users.txt", args)
        self.assertIn("-debug", args)

    def test_quote_cmd_quotes_spaces(self):
        cmd = quote_cmd([r"C:\Program Files\fscan.exe", "-h", "127.0.0.1"])
        self.assertTrue(cmd.startswith('"C:\\Program Files\\fscan.exe"'))


if __name__ == "__main__":
    unittest.main()
