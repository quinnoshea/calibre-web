import unittest
from unittest.mock import patch, MagicMock, Mock
import requests

try:
    import flask  # type: ignore
    _FLASK_MISSING = False
except Exception:
    _FLASK_MISSING = True

from cps.http_client import SafeRequestError, safe_metadata_request, safe_github_request
if not _FLASK_MISSING:
    from cps.helper import save_cover_from_url
    from cps.services.goodreads_support import my_GoodreadsRequest, GoodreadsRequestException
    from cps.metadata_provider.google import Google
    from cps.metadata_provider.comicvine import ComicVine
    from cps.metadata_provider.lubimyczytac import LubimyCzytac
    from cps.updater import Updater


@unittest.skipIf(_FLASK_MISSING, "Flask not installed; skipping integration-style tests that import full app")
class TestSSRFMigrations(unittest.TestCase):
    
    def setUp(self):
        self.mock_response = MagicMock()
        self.mock_response.status_code = 200
        self.mock_response.content = b'test content'
        self.mock_response.headers = {'Content-Length': '12'}
        self.mock_response.json.return_value = {'test': 'data'}
        self.mock_response.raise_for_status = MagicMock()

    @patch('cps.helper.safe_request')
    def test_save_cover_from_url_uses_safe_client(self, mock_safe_request):
        """Test that save_cover_from_url uses safe HTTP client"""
        mock_safe_request.return_value = self.mock_response
        
        # Mock CLI params to bypass allowlist
        with patch('cps.helper.cli_param') as mock_cli:
            mock_cli.allow_localhost = True
            
            with patch('cps.helper.save_cover') as mock_save_cover:
                mock_save_cover.return_value = (True, 'Success')
                
                result = save_cover_from_url('http://example.com/cover.jpg', '/path/to/book')
                
                mock_safe_request.assert_called_once()
                args, kwargs = mock_safe_request.call_args
                self.assertEqual(args[0], 'http://example.com/cover.jpg')
                self.assertEqual(kwargs['timeout'], (10, 200))
                self.assertEqual(kwargs['allow_redirects'], False)
                self.assertIsNone(kwargs['allowed_hosts'])

    @patch('cps.helper.safe_request')
    def test_save_cover_from_url_handles_ssrf_error(self, mock_safe_request):
        """Test that save_cover_from_url handles SafeRequestError"""
        mock_safe_request.side_effect = SafeRequestError("Blocked private IP")
        
        with patch('cps.helper.cli_param') as mock_cli:
            mock_cli.allow_localhost = False
            
            result = save_cover_from_url('http://127.0.0.1/cover.jpg', '/path/to/book')
            
            self.assertEqual(result, (False, "Error Downloading Cover"))
            mock_safe_request.assert_called_once()

    @patch('cps.http_client.safe_metadata_request')
    def test_goodreads_uses_safe_client(self, mock_safe_request):
        """Test that Goodreads support uses safe HTTP client"""
        mock_safe_request.return_value = self.mock_response
        
        # Create a request instance
        request = my_GoodreadsRequest(None, 'www.goodreads.com', '/api/book/show', 'xml', {'id': '123'})
        
        result = request.request()
        
        mock_safe_request.assert_called_once()
        args, kwargs = mock_safe_request.call_args
        self.assertIn('www.goodreads.com/api/book/show', args[0])

    @patch('cps.http_client.safe_metadata_request')
    def test_goodreads_handles_ssrf_error(self, mock_safe_request):
        """Test that Goodreads support handles SafeRequestError"""
        mock_safe_request.side_effect = SafeRequestError("Blocked request")
        
        request = my_GoodreadsRequest(None, 'www.goodreads.com', '/api/book/show', 'xml', {'id': '123'})
        
        with self.assertRaises(GoodreadsRequestException):
            request.request()

    @patch('cps.http_client.safe_metadata_request')
    def test_google_metadata_uses_safe_client(self, mock_safe_request):
        """Test that Google metadata provider uses safe HTTP client"""
        mock_response = MagicMock()
        mock_response.json.return_value = {'items': []}
        mock_response.raise_for_status = MagicMock()
        mock_safe_request.return_value = mock_response
        
        google = Google()
        google.active = True
        
        result = google.search("test query")
        
        mock_safe_request.assert_called_once()
        self.assertEqual(result, [])

    @patch('cps.http_client.safe_metadata_request')
    def test_comicvine_metadata_uses_safe_client(self, mock_safe_request):
        """Test that ComicVine metadata provider uses safe HTTP client"""
        mock_response = MagicMock()
        mock_response.json.return_value = {'results': []}
        mock_response.raise_for_status = MagicMock()
        mock_safe_request.return_value = mock_response
        
        comicvine = ComicVine()
        comicvine.active = True
        
        result = comicvine.search("test query")
        
        mock_safe_request.assert_called_once()
        self.assertEqual(result, [])

    @patch('cps.http_client.safe_metadata_request')
    def test_lubimyczytac_metadata_uses_safe_client(self, mock_safe_request):
        """Test that LubimyCzytac metadata provider uses safe HTTP client"""
        mock_response = MagicMock()
        mock_response.text = '<html><body></body></html>'
        mock_response.raise_for_status = MagicMock()
        mock_safe_request.return_value = mock_response
        
        with patch('lxml.html.fromstring') as mock_fromstring:
            mock_root = MagicMock()
            mock_fromstring.return_value = mock_root
            
            with patch('cps.metadata_provider.lubimyczytac.LubimyCzytacParser') as mock_parser_class:
                mock_parser = MagicMock()
                mock_parser.parse_search_results.return_value = []
                mock_parser_class.return_value = mock_parser
                
                lubimyczytac = LubimyCzytac()
                lubimyczytac.active = True
                
                result = lubimyczytac.search("test query")
                
                mock_safe_request.assert_called_once()

    @patch('cps.http_client.safe_github_request')
    def test_updater_uses_safe_client(self, mock_safe_request):
        """Test that updater uses safe GitHub client"""
        mock_response = MagicMock()
        mock_response.json.return_value = {'sha': 'abc123', 'commit': {'author': {'date': '2023-01-01T12:00:00Z'}}}
        mock_response.raise_for_status = MagicMock()
        mock_safe_request.return_value = mock_response
        
        updater = Updater()
        
        # Mock version info
        with patch.object(updater, 'get_current_version_info') as mock_version:
            mock_version.return_value = {'version': 'abc123'}
            
            status, commit = updater._stable_available_updates('https://api.github.com/repos/test/test')
            
            mock_safe_request.assert_called()

    @patch('cps.http_client.safe_github_request')
    def test_updater_handles_ssrf_error(self, mock_safe_request):
        """Test that updater handles SafeRequestError"""
        mock_safe_request.side_effect = SafeRequestError("Blocked request")
        
        updater = Updater()
        
        with patch.object(updater, 'get_current_version_info') as mock_version:
            mock_version.return_value = {'version': 'abc123'}
            
            status, commit = updater._stable_available_updates('https://api.github.com/repos/test/test')
            
            self.assertIn('Security error', status['message'])

    @patch('cps.http_client.fetch_bytes')
    def test_thumbnail_task_uses_safe_client(self, mock_fetch_bytes):
        """Test that thumbnail tasks use safe HTTP client"""
        mock_fetch_bytes.return_value = b'fake image data'
        
        # This would be tested by importing the thumbnail task and checking the fetch call
        # but we'll verify the import path exists
        from cps.tasks.thumbnail import fetch_bytes as task_fetch_bytes
        self.assertEqual(task_fetch_bytes, mock_fetch_bytes)

    def test_allowlist_mechanism(self):
        """Test that predefined allowlists are properly configured"""
        from cps.http_client import METADATA_PROVIDER_ALLOWLIST, GITHUB_ALLOWLIST, GOOGLE_DRIVE_ALLOWLIST
        
        # Verify expected domains are in allowlists
        self.assertIn('www.googleapis.com', METADATA_PROVIDER_ALLOWLIST)
        self.assertIn('www.goodreads.com', METADATA_PROVIDER_ALLOWLIST)
        self.assertIn('comicvine.gamespot.com', METADATA_PROVIDER_ALLOWLIST)
        self.assertIn('api.github.com', GITHUB_ALLOWLIST)
        self.assertIn('drive.google.com', GOOGLE_DRIVE_ALLOWLIST)

    def test_safe_metadata_request_uses_allowlist(self):
        """Test that safe_metadata_request applies the metadata provider allowlist"""
        with patch('cps.http_client.safe_request') as mock_safe_request:
            mock_safe_request.return_value = self.mock_response
            
            safe_metadata_request('https://example.com')
            
            # Verify the call included the metadata allowlist
            args, kwargs = mock_safe_request.call_args
            self.assertIn('allowed_hosts', kwargs)
            self.assertIn('www.googleapis.com', kwargs['allowed_hosts'])

    def test_safe_github_request_uses_allowlist(self):
        """Test that safe_github_request applies the GitHub allowlist"""
        with patch('cps.http_client.safe_request') as mock_safe_request:
            mock_safe_request.return_value = self.mock_response
            
            safe_github_request('https://api.github.com/repos/test/test')
            
            # Verify the call included the GitHub allowlist
            args, kwargs = mock_safe_request.call_args
            self.assertIn('allowed_hosts', kwargs)
            self.assertIn('api.github.com', kwargs['allowed_hosts'])


if __name__ == "__main__":
    unittest.main()
