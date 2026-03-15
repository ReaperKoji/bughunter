from __future__ import annotations

import unittest

from hunterops.url_utils import normalize_endpoint, normalize_url, match_patterns


class UrlUtilsTests(unittest.TestCase):
    def test_normalize_endpoint_sorts_query(self) -> None:
        self.assertEqual(normalize_endpoint("/api?b=2&a=1"), "/api?a=1&b=2")

    def test_normalize_url_defaults_and_ports(self) -> None:
        url = normalize_url("HTTPS://Example.com:443/path?b=2&a=1")
        self.assertEqual(url, "https://example.com/path?a=1&b=2")

    def test_match_patterns_case_insensitive(self) -> None:
        self.assertTrue(match_patterns("api.Example.com", ["*.example.com"]))
        self.assertFalse(match_patterns("api.Example.com", ["*.other.com"]))


if __name__ == "__main__":
    unittest.main()
