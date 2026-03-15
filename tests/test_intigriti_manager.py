from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hunterops.intigriti_manager import IntigritiManager


class IntigritiManagerTests(unittest.TestCase):
    def test_filter_targets_by_cached_scope_and_wildcard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "scope.json"
            cache.write_text(
                '{"hosts":["api.example.com"],"wildcard_suffixes":["example.net"]}',
                encoding="utf-8",
            )
            mgr = IntigritiManager(
                cfg={
                    "enabled": True,
                    "strict_scope_enforcement": True,
                    "scope_cache_file": str(cache),
                }
            )
            targets = [
                "api.example.com",
                "foo.example.net",
                "out.example.org",
            ]
            self.assertEqual(
                mgr.filter_targets(targets),
                ["api.example.com", "foo.example.net"],
            )

    def test_sync_scopes_collects_hosts_and_wildcards(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "scope.json"
            with patch.dict("os.environ", {"INTIGRITI_API_TOKEN": "t"}, clear=False):
                mgr = IntigritiManager(
                    cfg={
                        "enabled": True,
                        "strict_scope_enforcement": True,
                        "scope_cache_file": str(cache),
                        "program_handles": ["demo"],
                    }
                )
                mgr._fetch_programs = lambda timeout=20: [  # type: ignore[method-assign]
                    {"id": "p1", "handle": "demo", "name": "Demo Program"}
                ]
                mgr._resolve_domains_content = lambda program, timeout=20: [  # type: ignore[method-assign]
                    {"endpoint": "https://api.example.com"},
                    {"endpoint": "*.example.net"},
                ]
                out = mgr.sync_scopes(timeout=5)

            self.assertTrue(out.get("enabled", False))
            self.assertIn("api.example.com", out.get("hosts", []))
            self.assertIn("example.net", out.get("wildcard_suffixes", []))
            self.assertTrue(cache.exists())


if __name__ == "__main__":
    unittest.main()
