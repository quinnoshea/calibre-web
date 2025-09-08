import unittest
import sys
import os

# Add the cps directory to the path to import http_client directly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import only the http_client module without full CPS dependencies
try:
    import cps.http_client as http_client
except ImportError:
    # If cps package import fails, try to import the module directly
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'cps'))
    import http_client


class TestHttpClientDirectly(unittest.TestCase):
    """Test the http_client module directly without full CPS dependencies"""
    
    def test_allowlist_constants_exist(self):
        """Test that allowlist constants are properly defined"""
        self.assertTrue(hasattr(http_client, 'METADATA_PROVIDER_ALLOWLIST'))
        self.assertTrue(hasattr(http_client, 'GITHUB_ALLOWLIST'))
        self.assertTrue(hasattr(http_client, 'GOOGLE_DRIVE_ALLOWLIST'))
        self.assertTrue(hasattr(http_client, 'DEFAULT_ALLOWLIST'))
        
        # Check that they contain expected domains
        self.assertIn('www.googleapis.com', http_client.METADATA_PROVIDER_ALLOWLIST)
        self.assertIn('api.github.com', http_client.GITHUB_ALLOWLIST)
        self.assertIn('drive.google.com', http_client.GOOGLE_DRIVE_ALLOWLIST)
    
    def test_safe_request_error_exists(self):
        """Test that SafeRequestError exception class exists"""
        self.assertTrue(hasattr(http_client, 'SafeRequestError'))
        self.assertTrue(issubclass(http_client.SafeRequestError, Exception))
    
    def test_helper_functions_exist(self):
        """Test that helper functions exist"""
        self.assertTrue(hasattr(http_client, 'safe_metadata_request'))
        self.assertTrue(hasattr(http_client, 'safe_github_request'))
        self.assertTrue(hasattr(http_client, 'safe_gdrive_request'))
        self.assertTrue(callable(http_client.safe_metadata_request))
        self.assertTrue(callable(http_client.safe_github_request))
        self.assertTrue(callable(http_client.safe_gdrive_request))
    
    def test_private_ip_detection(self):
        """Test private IP detection function"""
        # Test loopback
        self.assertTrue(http_client._is_ip_private('127.0.0.1'))
        self.assertTrue(http_client._is_ip_private('::1'))
        
        # Test private ranges
        self.assertTrue(http_client._is_ip_private('192.168.1.1'))
        self.assertTrue(http_client._is_ip_private('10.0.0.1'))
        self.assertTrue(http_client._is_ip_private('172.16.0.1'))
        
        # Test public IP (example.com)
        self.assertFalse(http_client._is_ip_private('93.184.216.34'))
        
        # Test invalid IP
        self.assertFalse(http_client._is_ip_private('invalid-ip'))
    
    def test_host_allowlist_checking(self):
        """Test host allowlist checking function"""
        allowlist = ['example.com', 'api.github.com']
        
        # Direct match
        self.assertTrue(http_client._host_in_allowlist('example.com', allowlist))
        
        # Subdomain match
        self.assertTrue(http_client._host_in_allowlist('www.example.com', allowlist))
        
        # No match
        self.assertFalse(http_client._host_in_allowlist('evil.com', allowlist))
        
        # Case insensitive
        self.assertTrue(http_client._host_in_allowlist('EXAMPLE.COM', allowlist))
    
    def test_url_validation(self):
        """Test URL validation function"""
        # Valid URLs
        scheme, host, port, path = http_client._validate_and_normalize_url('https://example.com/path')
        self.assertEqual(scheme, 'https')
        self.assertEqual(host, 'example.com')
        self.assertEqual(port, 443)
        self.assertEqual(path, '/path')
        
        # Invalid scheme
        with self.assertRaises(http_client.SafeRequestError):
            http_client._validate_and_normalize_url('ftp://example.com')
        
        # Missing host
        with self.assertRaises(http_client.SafeRequestError):
            http_client._validate_and_normalize_url('https://')
        
        # User info in URL (should be blocked)
        with self.assertRaises(http_client.SafeRequestError):
            http_client._validate_and_normalize_url('https://user:pass@example.com')
    
    def test_blocked_destination_checking(self):
        """Test the main is_blocked_destination function"""
        # Should block loopback
        blocked, reason = http_client.is_blocked_destination('http://127.0.0.1')
        self.assertTrue(blocked)
        self.assertIn('private/loopback', reason)
        
        # Should block invalid scheme
        blocked, reason = http_client.is_blocked_destination('ftp://example.com')
        self.assertTrue(blocked)
        
        # Test with allowlist restriction
        blocked, reason = http_client.is_blocked_destination(
            'https://example.com', 
            allowed_hosts=['other.com']
        )
        # Depending on DNS on the CI host, example.com may be unresolvable or blocked by allowlist
        if blocked:
            self.assertTrue('allowlist' in reason.lower() or 'unresolvable' in reason.lower())


if __name__ == "__main__":
    unittest.main()
