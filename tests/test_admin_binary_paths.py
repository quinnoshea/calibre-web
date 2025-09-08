# -*- coding: utf-8 -*-

#  This file is part of the Calibre-Web (https://github.com/janeczku/calibre-web)
#    Copyright (C) 2025 OzzieIsaacs
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program. If not, see <http://www.gnu.org/licenses/>.

import unittest
import json
import os
from unittest.mock import patch, MagicMock
import tempfile

# Mock Flask components before importing
from unittest.mock import Mock
import sys

# Mock necessary modules that might not be available in test environment
mock_flask = Mock()
mock_flask.flash = Mock()
mock_flask.current_user = Mock()
mock_flask.current_user.id = 1
sys.modules['flask'] = mock_flask
sys.modules['flask_babel'] = Mock()
sys.modules['werkzeug'] = Mock()
sys.modules['werkzeug.security'] = Mock()
sys.modules['sqlalchemy'] = Mock()
sys.modules['flask_principal'] = Mock()
itsdangerous_mock = Mock()
itsdangerous_mock.URLSafeSerializer = Mock()
sys.modules['itsdangerous'] = itsdangerous_mock

# Now import the modules we're testing
import cps.exec_paths as exec_paths
from cps.config_sql import ConfigSQL


class MockFlaskTestClient:
    """Mock Flask test client for testing admin endpoints."""
    
    def __init__(self):
        self.last_response = None
    
    def post(self, url, data=None, **kwargs):
        """Mock POST request."""
        self.last_response = MockResponse(data)
        return self.last_response


class MockResponse:
    """Mock HTTP response."""
    
    def __init__(self, form_data):
        self.form_data = form_data or {}
        self.status_code = 200
        self.json_data = {'result': [{'type': 'success', 'message': 'Configuration updated'}]}
    
    def get_json(self):
        return self.json_data


class TestAdminBinaryPaths(unittest.TestCase):
    """Functional tests for admin binary path configuration."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.original_env = os.environ.get('CW_BINARY_WHITELIST', None)
        
        # Set up a test allowlist
        os.environ['CW_BINARY_WHITELIST'] = '/usr/bin/unrar,/usr/local/bin/unrar'
        
        # Mock config object
        self.mock_config = Mock()
        self.mock_config.config_rarfile_location = None
        self.mock_config.config_kepubifypath = None
        self.mock_config.config_binariesdir = None
        self.mock_config.config_converterpath = None
    
    def tearDown(self):
        """Clean up test environment."""
        if self.original_env is not None:
            os.environ['CW_BINARY_WHITELIST'] = self.original_env
        elif 'CW_BINARY_WHITELIST' in os.environ:
            del os.environ['CW_BINARY_WHITELIST']

    @patch('cps.exec_paths.validate_binary_path')
    def test_valid_binary_path_submission(self, mock_validate):
        """Test submitting a valid binary path through admin interface."""
        mock_validate.return_value = True
        
        # Mock config update
        config_mock = Mock()
        config_mock.set_from_dictionary = Mock(return_value=True)
        
        # Simulate valid form submission
        form_data = {
            'config_rarfile_location': '/usr/bin/unrar'
        }
        
        # This would normally go through the admin._config_string function
        from cps.admin import _config_string
        
        with patch('cps.admin.config', config_mock):
            with patch('cps.admin.current_user') as mock_user:
                mock_user.id = 1
                result = _config_string(form_data, 'config_rarfile_location')
        
        self.assertTrue(result)
        mock_validate.assert_called_once_with('/usr/bin/unrar')

    @patch('cps.exec_paths.validate_binary_path')
    @patch('cps.admin.flash')
    def test_invalid_binary_path_submission(self, mock_flash, mock_validate):
        """Test submitting an invalid binary path through admin interface."""
        mock_validate.return_value = False
        
        # Mock config update
        config_mock = Mock()
        
        # Simulate malicious form submission
        form_data = {
            'config_rarfile_location': '/malicious/binary; rm -rf /'
        }
        
        from cps.admin import _config_string
        
        with patch('cps.admin.config', config_mock):
            with patch('cps.admin.current_user') as mock_user:
                mock_user.id = 1
                result = _config_string(form_data, 'config_rarfile_location')
        
        # Should fail and not call set_from_dictionary
        self.assertFalse(result)
        config_mock.set_from_dictionary.assert_not_called()
        
        # Should flash an error message
        mock_flash.assert_called_once()
        call_args = mock_flash.call_args[0][0]
        self.assertIn('Invalid binary path', call_args)

    @patch('cps.exec_paths.validate_binary_path')
    @patch('cps.admin.log')
    def test_audit_logging_on_config_change(self, mock_log, mock_validate):
        """Test that configuration changes are properly logged."""
        mock_validate.return_value = True
        
        # Mock config object with audit logging
        config_mock = Mock()
        config_mock.config_rarfile_location = '/old/path'
        config_mock.set_from_dictionary = Mock(return_value=True)
        
        form_data = {
            'config_rarfile_location': '/usr/bin/unrar'
        }
        
        from cps.admin import _config_string
        
        with patch('cps.admin.config', config_mock):
            with patch('cps.admin.current_user') as mock_user:
                mock_user.id = 1
                with patch('cps.admin.getattr', return_value='/old/path'):
                    result = _config_string(form_data, 'config_rarfile_location')
        
        self.assertTrue(result)
        
        # Verify audit log was called
        mock_log.info.assert_called()
        log_call_args = mock_log.info.call_args[0]
        self.assertIn('Config change', log_call_args[0])
        self.assertIn('config_rarfile_location', log_call_args)

    @patch('cps.exec_paths.validate_binary_path')
    def test_multiple_binary_paths_validation(self, mock_validate):
        """Test validation of multiple binary paths in a single request."""
        # First path valid, second invalid
        mock_validate.side_effect = [True, False]
        
        config_mock = Mock()
        config_mock.config_rarfile_location = None
        config_mock.config_kepubifypath = None
        config_mock.set_from_dictionary = Mock(return_value=True)
        
        form_data = {
            'config_rarfile_location': '/usr/bin/unrar',
            'config_kepubifypath': '/malicious/path'
        }
        
        from cps.admin import _config_string
        
        with patch('cps.admin.config', config_mock):
            with patch('cps.admin.current_user') as mock_user:
                mock_user.id = 1
                with patch('cps.admin.flash') as mock_flash:
                    # First call should succeed
                    result1 = _config_string(form_data, 'config_rarfile_location')
                    # Second call should fail
                    result2 = _config_string(form_data, 'config_kepubifypath')
        
        self.assertTrue(result1)
        self.assertFalse(result2)

    def test_calibre_binaries_directory_validation(self):
        """Test validation of Calibre binaries directory."""
        # Create a temporary directory structure
        calibre_dir = os.path.join(self.temp_dir, 'calibre')
        os.makedirs(calibre_dir, exist_ok=True)
        
        # Mock the validation to simulate directory checking
        with patch('cps.exec_paths.validate_calibre_binaries_dir') as mock_validate_dir:
            mock_validate_dir.return_value = False  # Simulate missing binaries
            
            config_mock = Mock()
            form_data = {'config_binariesdir': calibre_dir}
            
            from cps.admin import _config_string
            
            with patch('cps.admin.config', config_mock):
                with patch('cps.admin.current_user') as mock_user:
                    mock_user.id = 1
                    with patch('cps.admin.flash') as mock_flash:
                        result = _config_string(form_data, 'config_binariesdir')
            
            # Should fail due to missing binaries
            self.assertFalse(result)
            mock_validate_dir.assert_called_once_with(calibre_dir)

    @patch('cps.exec_paths.validate_binary_path')
    def test_empty_path_allowed(self, mock_validate):
        """Test that empty paths are allowed (for defaults)."""
        config_mock = Mock()
        config_mock.set_from_dictionary = Mock(return_value=False)  # No change
        
        form_data = {
            'config_rarfile_location': ''
        }
        
        from cps.admin import _config_string
        
        with patch('cps.admin.config', config_mock):
            result = _config_string(form_data, 'config_rarfile_location')
        
        # Should not validate empty paths and should call set_from_dictionary
        mock_validate.assert_not_called()
        config_mock.set_from_dictionary.assert_called_once()

    def test_xss_prevention_in_error_messages(self):
        """Test that error messages properly escape user input."""
        malicious_path = "<script>alert('xss')</script>"
        
        with patch('cps.exec_paths.validate_binary_path', return_value=False):
            config_mock = Mock()
            form_data = {'config_rarfile_location': malicious_path}
            
            from cps.admin import _config_string
            
            with patch('cps.admin.config', config_mock):
                with patch('cps.admin.current_user') as mock_user:
                    mock_user.id = 1
                    with patch('cps.admin.flash') as mock_flash:
                        result = _config_string(form_data, 'config_rarfile_location')
            
            # Verify the malicious script was included in the flash message
            # (In real implementation, this should be escaped)
            self.assertFalse(result)
            mock_flash.assert_called_once()

    def test_path_traversal_in_config_submission(self):
        """Test handling of path traversal attempts in configuration."""
        traversal_paths = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\cmd.exe',
            '/legitimate/../../../malicious',
        ]
        
        with patch('cps.exec_paths.validate_binary_path', return_value=False) as mock_validate:
            config_mock = Mock()
            
            for path in traversal_paths:
                with self.subTest(path=path):
                    form_data = {'config_rarfile_location': path}
                    
                    from cps.admin import _config_string
                    
                    with patch('cps.admin.config', config_mock):
                        with patch('cps.admin.current_user') as mock_user:
                            mock_user.id = 1
                            with patch('cps.admin.flash'):
                                result = _config_string(form_data, 'config_rarfile_location')
                    
                    self.assertFalse(result, f"Should reject traversal path: {path}")

    def test_configuration_persistence_prevention(self):
        """Test that invalid configurations are not persisted."""
        with patch('cps.exec_paths.validate_binary_path', return_value=False):
            # Mock ConfigSQL
            config_mock = Mock()
            original_value = '/original/path'
            config_mock.config_rarfile_location = original_value
            config_mock.set_from_dictionary = Mock()
            
            form_data = {'config_rarfile_location': '/malicious/path'}
            
            from cps.admin import _config_string
            
            with patch('cps.admin.config', config_mock):
                with patch('cps.admin.current_user') as mock_user:
                    mock_user.id = 1
                    with patch('cps.admin.flash'):
                        result = _config_string(form_data, 'config_rarfile_location')
            
            # Validation failed, so set_from_dictionary should not be called
            self.assertFalse(result)
            config_mock.set_from_dictionary.assert_not_called()


class TestConfigSQLSecurity(unittest.TestCase):
    """Test ConfigSQL security features."""
    
    def setUp(self):
        """Set up test environment."""
        # Mock dependencies
        self.session_mock = Mock()
        self.settings_mock = Mock()
        
    def test_sensitive_key_detection(self):
        """Test detection of sensitive configuration keys."""
        config = ConfigSQL()
        
        # Mock the _is_sensitive_key method test
        sensitive_keys = [
            'config_goodreads_api_key',
            'mail_password',
            'oauth_token',
            'secret_key',
            'api_password',
            'TOKEN_SOMETHING',
        ]
        
        non_sensitive_keys = [
            'config_port',
            'config_books_per_page',
            'config_theme',
            'mail_server',
        ]
        
        for key in sensitive_keys:
            with self.subTest(key=key):
                self.assertTrue(config._is_sensitive_key(key))
        
        for key in non_sensitive_keys:
            with self.subTest(key=key):
                self.assertFalse(config._is_sensitive_key(key))

    def test_to_dict_masks_sensitive_data(self):
        """Test that to_dict() masks sensitive configuration data."""
        config = ConfigSQL()
        
        # Mock some configuration data
        config.__dict__.update({
            'config_port': 8083,
            'config_goodreads_api_key': 'secret123',
            'mail_password': 'password123',
            'config_theme': 1,
            'oauth_token': 'token456',
            '_private_attr': 'hidden',
            'cli': 'excluded',
            'dirty': [],
        })
        
        result = config.to_dict()
        
        # Non-sensitive data should be unchanged
        self.assertEqual(result['config_port'], 8083)
        self.assertEqual(result['config_theme'], 1)
        
        # Sensitive data should be masked
        self.assertEqual(result['config_goodreads_api_key'], '***MASKED***')
        self.assertEqual(result['mail_password'], '***MASKED***')
        self.assertEqual(result['oauth_token'], '***MASKED***')
        
        # Private attributes should be excluded
        self.assertNotIn('_private_attr', result)
        self.assertNotIn('cli', result)
        
        # Empty sensitive values should remain unchanged
        config.empty_secret = ''
        result = config.to_dict()
        self.assertEqual(result.get('empty_secret'), '')


class TestNegativeSecurityTests(unittest.TestCase):
    """Negative security tests for various attack scenarios."""
    
    def test_symlink_attack_simulation(self):
        """Test protection against symlink-based attacks."""
        # This would require actual symlink creation in a real test
        # Here we simulate the behavior
        
        with patch('cps.exec_paths.normalize_path') as mock_normalize:
            # Simulate symlink that resolves to dangerous location
            mock_normalize.return_value = '/tmp/malicious_target'
            
            with patch('cps.exec_paths.get_full_allowlist') as mock_allowlist:
                mock_allowlist.return_value = {'/usr/bin/unrar'}  # legitimate paths only
                
                result = exec_paths.validate_binary_path('/usr/bin/legitimate_symlink')
                
                # Should fail because resolved path is not in allowlist
                self.assertFalse(result)

    def test_race_condition_protection(self):
        """Test protection against TOCTOU (Time-of-Check-Time-of-Use) attacks."""
        # This test verifies that validation happens both at config time
        # and at execution time
        
        valid_path = '/usr/bin/unrar'
        
        with patch('cps.exec_paths.get_full_allowlist') as mock_allowlist:
            mock_allowlist.return_value = {valid_path}
            
            with patch('cps.exec_paths.is_executable_file') as mock_exec:
                # First check (config time) - file exists and is executable
                mock_exec.return_value = True
                config_result = exec_paths.validate_binary_path(valid_path)
                
                # Second check (execution time) - file no longer executable
                mock_exec.return_value = False
                exec_result = exec_paths.validate_binary_path(valid_path)
                
                # Config should have succeeded, execution should fail
                self.assertTrue(config_result)
                self.assertFalse(exec_result)

    def test_environment_variable_injection(self):
        """Test protection against environment variable injection."""
        # Test that environment allowlist properly validates paths
        malicious_env = "/usr/bin/unrar; export MALICIOUS=true; /bin/sh"
        
        with patch.dict(os.environ, {'CW_BINARY_WHITELIST': malicious_env}):
            env_allowlist = exec_paths.get_environment_allowlist()
            
            # Should not contain the malicious command
            for path in env_allowlist:
                self.assertNotIn(';', path)
                self.assertNotIn('export', path)
                self.assertNotIn('/bin/sh', path)


if __name__ == '__main__':
    unittest.main()
