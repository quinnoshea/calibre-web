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

import os
import sys
import stat
import re
from typing import Set, List, Optional

try:
    from . import logger as _cps_logger
    log = _cps_logger.create()
except Exception:  # pragma: no cover - fallback for test environments without Flask stack
    import logging
    log = logging.getLogger("cps.exec_paths")

# Platform-aware default allowlists for known binary locations
_LINUX_BINARY_ALLOWLIST = {
    # Standard system paths
    '/usr/bin/unrar',
    '/usr/local/bin/unrar',
    '/usr/bin/rar',
    '/usr/local/bin/rar',
    '/usr/bin/ebook-convert',
    '/usr/local/bin/ebook-convert',
    '/usr/bin/calibredb',
    '/usr/local/bin/calibredb',
    '/usr/bin/kepubify',
    '/usr/local/bin/kepubify',
    # Common install locations
    '/opt/calibre/ebook-convert',
    '/opt/calibre/calibredb',
    '/opt/kepubify/kepubify-linux-64bit',
    '/opt/kepubify/kepubify-linux-32bit',
    # Flatpak/Snap paths
    '/var/lib/flatpak/app/com.calibre_ebook.calibre/current/active/export/bin/ebook-convert',
    '/var/lib/flatpak/app/com.calibre_ebook.calibre/current/active/export/bin/calibredb',
    '/snap/calibre/current/bin/ebook-convert',
    '/snap/calibre/current/bin/calibredb',
}

_MACOS_BINARY_ALLOWLIST = {
    # Homebrew paths
    '/usr/local/bin/unrar',
    '/usr/local/bin/rar',
    '/usr/local/bin/ebook-convert',
    '/usr/local/bin/calibredb',
    '/usr/local/bin/kepubify',
    '/opt/homebrew/bin/unrar',
    '/opt/homebrew/bin/rar',
    '/opt/homebrew/bin/ebook-convert',
    '/opt/homebrew/bin/calibredb',
    '/opt/homebrew/bin/kepubify',
    # Application bundle paths
    '/Applications/calibre.app/Contents/MacOS/ebook-convert',
    '/Applications/calibre.app/Contents/MacOS/calibredb',
    # User paths
    os.path.expanduser('~/Applications/calibre.app/Contents/MacOS/ebook-convert'),
    os.path.expanduser('~/Applications/calibre.app/Contents/MacOS/calibredb'),
}

_WINDOWS_BINARY_ALLOWLIST = {
    # Program Files paths
    r'C:\Program Files\Calibre\ebook-convert.exe',
    r'C:\Program Files\Calibre\calibredb.exe',
    r'C:\Program Files (x86)\Calibre\ebook-convert.exe',
    r'C:\Program Files (x86)\Calibre\calibredb.exe',
    r'C:\Program Files\Calibre2\ebook-convert.exe',
    r'C:\Program Files\Calibre2\calibredb.exe',
    r'C:\Program Files (x86)\Calibre2\ebook-convert.exe',
    r'C:\Program Files (x86)\Calibre2\calibredb.exe',
    r'C:\Program Files\WinRAR\UnRAR.exe',
    r'C:\Program Files (x86)\WinRAR\UnRAR.exe',
    r'C:\Program Files\WinRAR\Rar.exe',
    r'C:\Program Files (x86)\WinRAR\Rar.exe',
    r'C:\Program Files\kepubify\kepubify-windows-64bit.exe',
    r'C:\Program Files (x86)\kepubify\kepubify-windows-64bit.exe',
    # User-local paths
    os.path.expanduser(r'~\AppData\Local\Programs\Calibre\ebook-convert.exe'),
    os.path.expanduser(r'~\AppData\Local\Programs\Calibre\calibredb.exe'),
}

_FREEBSD_BINARY_ALLOWLIST = {
    '/usr/local/bin/unrar',
    '/usr/local/bin/rar',
    '/usr/local/bin/ebook-convert',
    '/usr/local/bin/calibredb',
    '/usr/local/bin/kepubify',
}

# Dangerous characters and patterns that indicate command injection attempts
_DANGEROUS_PATTERNS = [
    r'[\x00-\x1f]',  # Control characters including null bytes
    r'[;&|`$()]',    # Shell metacharacters
    r'\s+\-',        # Arguments (space followed by dash)
    r'^\-',          # Leading dash (arguments)
    r'[\'"<>]',      # Quotes and redirections
    r'\\\w',         # Escape sequences
    r'\$\w',         # Variable expansions
    r'\n|\r',        # Newlines
]

def get_platform_allowlist() -> Set[str]:
    """Get the platform-specific allowlist of binary paths."""
    if sys.platform == "win32":
        return _WINDOWS_BINARY_ALLOWLIST.copy()
    elif sys.platform.startswith("freebsd"):
        return _FREEBSD_BINARY_ALLOWLIST.copy()
    elif sys.platform == "darwin":
        return _MACOS_BINARY_ALLOWLIST.copy()
    else:
        return _LINUX_BINARY_ALLOWLIST.copy()

def get_environment_allowlist() -> Set[str]:
    """Get additional allowed binary paths from environment variable."""
    env_paths = os.environ.get('CW_BINARY_WHITELIST', '')
    if not env_paths:
        return set()
    
    paths = set()
    for path in env_paths.split(','):
        path = path.strip()
        if path:
            # Normalize the path
            try:
                normalized_path = os.path.normpath(os.path.abspath(path))
                paths.add(normalized_path)
            except (ValueError, OSError) as e:
                log.warning("Invalid path in CW_BINARY_WHITELIST: %s - %s", path, e)
                continue
    
    return paths

def get_full_allowlist() -> Set[str]:
    """Get the complete allowlist combining platform defaults and environment overrides."""
    allowlist = get_platform_allowlist()
    allowlist.update(get_environment_allowlist())
    return allowlist

def normalize_path(path: str) -> Optional[str]:
    """
    Normalize and canonicalize a binary path.
    
    Returns:
        Normalized absolute path if valid, None if invalid/unsafe
    """
    if not path or not isinstance(path, str):
        return None
    
    # Check for dangerous patterns first
    for pattern in _DANGEROUS_PATTERNS:
        if re.search(pattern, path, re.IGNORECASE):
            log.warning("Path contains dangerous pattern %s: %s", pattern, path)
            return None
    
    try:
        # Normalize the path (resolve relative components)
        normalized = os.path.normpath(path)
        
        # Convert to absolute path
        abs_path = os.path.abspath(normalized)
        
        # On Windows, normalize case and path separators
        if sys.platform == "win32":
            abs_path = os.path.normcase(abs_path)
        
        # Additional security check: ensure it's actually an absolute path
        if not os.path.isabs(abs_path):
            log.warning("Path is not absolute after normalization: %s", path)
            return None
            
        return abs_path
    except (ValueError, OSError, TypeError) as e:
        log.warning("Failed to normalize path %s: %s", path, e)
        return None

def is_executable_file(path: str) -> bool:
    """
    Check if path points to an executable file.
    
    Args:
        path: Normalized absolute path to check
    
    Returns:
        True if file exists and is executable, False otherwise
    """
    try:
        if not os.path.isfile(path):
            return False
        
        # Check executable permission (Unix-like systems)
        if hasattr(os, 'access'):
            return os.access(path, os.X_OK)
        
        # Windows - check if file has executable extension or executable bit
        if sys.platform == "win32":
            if path.lower().endswith(('.exe', '.bat', '.cmd', '.com')):
                return True
            # Check file mode for executable bit
            try:
                mode = os.stat(path).st_mode
                return bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
            except OSError:
                return False
        
        return False
    except (OSError, TypeError):
        return False

def validate_binary_path(path: str) -> bool:
    """
    Validate a binary path against security requirements.
    
    This function performs comprehensive validation:
    1. Path normalization and canonicalization
    2. Allowlist verification
    3. File existence and executability checks
    4. Security pattern detection
    
    Args:
        path: Binary path to validate
    
    Returns:
        True if path is valid and safe, False otherwise
    """
    if not path:
        return False
    
    # Normalize the path
    normalized_path = normalize_path(path)
    if not normalized_path:
        return False
    
    # Check against allowlist
    allowlist = get_full_allowlist()
    if normalized_path not in allowlist:
        log.warning("Binary path not in allowlist: %s", normalized_path)
        return False
    
    # Verify file exists and is executable
    if not is_executable_file(normalized_path):
        log.warning("Binary path is not an executable file: %s", normalized_path)
        return False
    
    log.debug("Binary path validation successful: %s", normalized_path)
    return True

def get_binary_path_keys() -> List[str]:
    """
    Get list of configuration keys that contain binary paths.
    
    Returns:
        List of config keys that should be validated as binary paths
    """
    return [
        'config_rarfile_location',
        'config_binariesdir',  # Directory containing calibre binaries
        'config_kepubifypath',
        'config_converterpath',  # Full path to ebook-convert
        'config_calibre',
    ]

def is_binary_path_key(key: str) -> bool:
    """Check if a configuration key represents a binary path that needs validation."""
    return key in get_binary_path_keys()

def validate_calibre_binaries_dir(binaries_dir: str) -> bool:
    """
    Validate a Calibre binaries directory by checking for required executables.
    
    Args:
        binaries_dir: Directory path containing Calibre binaries
    
    Returns:
        True if directory contains valid Calibre binaries, False otherwise
    """
    if not binaries_dir:
        return False
    
    normalized_dir = normalize_path(binaries_dir)
    if not normalized_dir or not os.path.isdir(normalized_dir):
        return False
    
    # Check for required Calibre binaries
    from . import constants
    
    extension = ".exe" if sys.platform == "win32" else ""
    required_binaries = ["ebook-convert", "calibredb"]
    
    for binary_name in required_binaries:
        binary_path = os.path.join(normalized_dir, binary_name + extension)
        if not validate_binary_path(binary_path):
            log.warning("Required Calibre binary not found or invalid: %s", binary_path)
            return False
    
    return True
