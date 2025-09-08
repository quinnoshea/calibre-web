#!/usr/bin/env python3
"""
Simple syntax verification script for CVE-2025-7404 SSRF fix
"""

import ast
import os
import sys

def check_syntax(filepath):
    """Check if a Python file has valid syntax"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        ast.parse(content)
        return True, None
    except SyntaxError as e:
        return False, f"Syntax error in {filepath}: {e}"
    except Exception as e:
        return False, f"Error reading {filepath}: {e}"

def verify_imports():
    """Verify that our changes maintain proper imports"""
    files_to_check = [
        'cps/http_client.py',
        'cps/tasks/thumbnail.py', 
        'cps/helper.py',
        'cps/services/goodreads_support.py',
        'cps/metadata_provider/google.py',
        'cps/metadata_provider/comicvine.py',
        'cps/metadata_provider/lubimyczytac.py',
        'cps/updater.py'
    ]
    
    all_good = True
    for filepath in files_to_check:
        if os.path.exists(filepath):
            good, error = check_syntax(filepath)
            if good:
                print(f"✓ {filepath} - Syntax OK")
            else:
                print(f"✗ {error}")
                all_good = False
        else:
            print(f"? {filepath} - File not found")
    
    return all_good

def verify_allowlists():
    """Verify that allowlists are properly defined"""
    try:
        # Read http_client.py content
        with open('cps/http_client.py', 'r') as f:
            content = f.read()
        
        required_allowlists = [
            'METADATA_PROVIDER_ALLOWLIST',
            'GITHUB_ALLOWLIST', 
            'GOOGLE_DRIVE_ALLOWLIST',
            'DEFAULT_ALLOWLIST'
        ]
        
        required_functions = [
            'safe_metadata_request',
            'safe_github_request',
            'safe_gdrive_request'
        ]
        
        required_domains = [
            'www.googleapis.com',
            'api.github.com',
            'drive.google.com',
            'www.goodreads.com'
        ]
        
        for allowlist in required_allowlists:
            if allowlist in content:
                print(f"✓ {allowlist} - Found")
            else:
                print(f"✗ {allowlist} - Missing")
                return False
                
        for function in required_functions:
            if f"def {function}" in content:
                print(f"✓ {function} - Found")
            else:
                print(f"✗ {function} - Missing") 
                return False
                
        for domain in required_domains:
            if domain in content:
                print(f"✓ {domain} - Found in allowlist")
            else:
                print(f"✗ {domain} - Missing from allowlist")
                return False
        
        return True
    except Exception as e:
        print(f"✗ Error checking allowlists: {e}")
        return False

def verify_migrations():
    """Verify that unsafe calls have been replaced"""
    checks = [
        ('cps/tasks/thumbnail.py', 'fetch_bytes', True),  # Should use fetch_bytes
        ('cps/helper.py', 'safe_request', True),  # Should have safe_request
        ('cps/updater.py', 'safe_github_request', True),  # Should have safe_github_request
        ('cps/services/goodreads_support.py', 'safe_metadata_request', True),  # Should have safe_metadata_request
    ]
    
    unsafe_patterns = [
        ('cps/tasks/thumbnail.py', 'stream = urlopen(', False),  # Should not have active urlopen
        ('cps/helper.py', 'requests.get(url,', False),  # Should not have unsafe requests.get
    ]
    
    all_good = True
    
    # Check for required safe patterns
    for filepath, pattern, should_exist in checks:
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    content = f.read()
                
                pattern_found = pattern in content
                if should_exist and pattern_found:
                    print(f"✓ {filepath} - Contains {pattern}")
                elif should_exist and not pattern_found:
                    print(f"✗ {filepath} - Missing {pattern}")
                    all_good = False
                    
            except Exception as e:
                print(f"✗ Error checking {filepath}: {e}")
                all_good = False
        else:
            print(f"? {filepath} - File not found")
    
    # Check for absence of unsafe patterns
    for filepath, pattern, should_exist in unsafe_patterns:
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    content = f.read()
                
                pattern_found = pattern in content
                if not pattern_found:
                    print(f"✓ {filepath} - Does not contain unsafe {pattern}")
                else:
                    print(f"✗ {filepath} - Still contains unsafe {pattern}")
                    all_good = False
                    
            except Exception as e:
                print(f"✗ Error checking {filepath}: {e}")
                all_good = False
            
    return all_good

def main():
    """Main verification function"""
    print("=== CVE-2025-7404 SSRF Fix Verification ===\n")
    
    print("1. Checking syntax...")
    syntax_ok = verify_imports()
    
    print("\n2. Checking allowlists and functions...")
    allowlists_ok = verify_allowlists()
    
    print("\n3. Checking migrations...")
    migrations_ok = verify_migrations()
    
    print(f"\n=== Summary ===")
    print(f"Syntax: {'✓' if syntax_ok else '✗'}")
    print(f"Allowlists: {'✓' if allowlists_ok else '✗'}")  
    print(f"Migrations: {'✓' if migrations_ok else '✗'}")
    
    all_ok = syntax_ok and allowlists_ok and migrations_ok
    print(f"Overall: {'✓ All checks passed' if all_ok else '✗ Some checks failed'}")
    
    return 0 if all_ok else 1

if __name__ == "__main__":
    sys.exit(main())