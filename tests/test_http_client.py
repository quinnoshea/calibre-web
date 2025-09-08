import unittest
from unittest.mock import patch

import importlib.util
import os
import sys

# Import cps.http_client without importing full cps package (to avoid Flask dep in tests)
MODULE_PATH = os.path.join(os.path.dirname(__file__), '..', 'cps', 'http_client.py')
spec = importlib.util.spec_from_file_location('cps.http_client', MODULE_PATH)
http_client = importlib.util.module_from_spec(spec)
sys.modules['cps.http_client'] = http_client
spec.loader.exec_module(http_client)

is_blocked_destination = http_client.is_blocked_destination
SafeRequestError = http_client.SafeRequestError


class TestHttpClientSSRFGuard(unittest.TestCase):
    def test_blocks_loopback_literal(self):
        blocked, reason = is_blocked_destination("http://127.0.0.1:8000")
        self.assertTrue(blocked)
        self.assertIn("private/loopback", reason)

    def test_blocks_ipv6_loopback_literal(self):
        blocked, _ = is_blocked_destination("http://[::1]:8080")
        self.assertTrue(blocked)

    def test_blocks_unresolvable_host(self):
        with patch.object(http_client, "_resolve_host", return_value=[]):
            blocked, reason = is_blocked_destination("https://does-not-resolve.invalid")
            self.assertTrue(blocked)
            self.assertIn("Unresolvable", reason)

    def test_blocks_localhost_via_dns(self):
        with patch.object(http_client, "_resolve_host", return_value=["127.0.0.1"]):
            blocked, reason = is_blocked_destination("http://localhost")
            self.assertTrue(blocked)
            self.assertIn("private/loopback", reason)

    def test_allows_public_host_when_not_allowlisted(self):
        # Simulate public IP resolution for example.com
        with patch.object(http_client, "_resolve_host", return_value=["93.184.216.34"]):
            blocked, reason = is_blocked_destination("https://example.com/")
            self.assertFalse(blocked, reason)

    def test_enforces_allowlist(self):
        with patch.object(http_client, "_resolve_host", return_value=["93.184.216.34"]):
            blocked, reason = is_blocked_destination(
                "https://example.com/", allowed_hosts=["covers.example.org"]
            )
            self.assertTrue(blocked)
            self.assertIn("allowlist", reason)


if __name__ == "__main__":
    unittest.main()
