# Security Hardening Notes - CVE-2025-7404 SSRF Fix

## Overview

This document describes the comprehensive security hardening implemented to fix Server-Side Request Forgery (SSRF) vulnerabilities in Calibre-Web, specifically addressing CVE-2025-7404.

## Changes Made

### 1. Centralized Safe HTTP Client (`cps/http_client.py`)

Enhanced the existing safe HTTP client with:
- **Predefined Allowlists**: Added domain allowlists for different service types
- **Specialized Request Functions**: Created service-specific safe request functions
- **Comprehensive SSRF Protection**: Blocks private/loopback IPs, enforces allowlists, limits redirects and response sizes

### 2. Vulnerable Code Migration

Replaced all unsafe external HTTP calls with safe client implementations:

#### Files Modified:
- `cps/tasks/thumbnail.py` - Replaced `urllib.request.urlopen` with `fetch_bytes`
- `cps/helper.py` - Replaced `requests.get` with `safe_request` in `save_cover_from_url()`
- `cps/services/goodreads_support.py` - Replaced `requests.get` with `safe_metadata_request`
- `cps/metadata_provider/google.py` - Replaced `requests.get` with `safe_metadata_request`
- `cps/metadata_provider/comicvine.py` - Replaced `requests.get` with `safe_metadata_request`
- `cps/metadata_provider/lubimyczytac.py` - Replaced `requests.get` with `safe_metadata_request`
- `cps/updater.py` - Replaced multiple `requests.get` calls with `safe_github_request`

## Allowlist Configuration

### Predefined Allowlists

The safe HTTP client includes predefined allowlists for trusted domains:

#### Metadata Providers (`METADATA_PROVIDER_ALLOWLIST`):
- `www.googleapis.com` - Google Books API
- `books.google.com` - Google Books
- `www.goodreads.com` - Goodreads API
- `comicvine.gamespot.com` - ComicVine API
- `lubimyczytac.pl`, `www.lubimyczytac.pl` - Polish book database
- `www.douban.com`, `frodo.douban.com`, `img*.doubanio.com` - Douban
- `www.amazon.com`, `images-na.ssl-images-amazon.com`, `m.media-amazon.com` - Amazon

#### GitHub (`GITHUB_ALLOWLIST`):
- `api.github.com` - GitHub API
- `github.com` - GitHub

#### Google Drive (`GOOGLE_DRIVE_ALLOWLIST`):
- `drive.google.com` - Google Drive
- `docs.google.com` - Google Docs

### Service-Specific Functions

- `safe_metadata_request()` - Uses metadata provider allowlist
- `safe_github_request()` - Uses GitHub allowlist  
- `safe_gdrive_request()` - Uses Google Drive allowlist

### Developer Notes

#### Adding New External Services

When adding new external HTTP requests:

1. **Use the Safe Client**: Never use `requests.get()` or `urllib.request.urlopen()` directly
2. **Choose Appropriate Function**:
   - For metadata providers: `safe_metadata_request()`
   - For GitHub API: `safe_github_request()`
   - For Google Drive: `safe_gdrive_request()`
   - For general use: `safe_request()` with explicit allowlist

3. **Add Domain to Allowlist**: If needed, add trusted domains to the appropriate allowlist in `cps/http_client.py`

#### Example Usage

```python
from cps.http_client import safe_metadata_request, SafeRequestError

try:
    response = safe_metadata_request('https://api.example.com/books', 
                                   params={'q': 'search_term'})
    response.raise_for_status()
    data = response.json()
except SafeRequestError as e:
    log.error(f"Request blocked by security policy: {e}")
except Exception as e:
    log.error(f"Request failed: {e}")
```

### Testing

Unit tests are included in `tests/test_ssrf_migrations.py` to verify:
- All migrated code paths use safe HTTP client
- SSRF attempts are properly blocked
- Allowlists function correctly
- Error handling works as expected

### Configuration Options

#### CSP (Content Security Policy)

Environment variables for CSP configuration:
- `CW_CSP=1` - Enable CSP (report-only by default)
- `CW_CSP_ENFORCE=1` - Enable CSP enforcement mode

#### Local Development

For local development that needs to access localhost/private IPs:
- Use `cli_param.allow_localhost = True` to bypass allowlist restrictions
- This should NEVER be used in production

## Security Benefits

1. **SSRF Prevention**: Blocks requests to private/loopback IP addresses
2. **Domain Restriction**: Limits outbound requests to predefined trusted domains
3. **Request Size Limits**: Prevents large response attacks (default 2MB limit)
4. **Redirect Protection**: Validates redirect targets before following
5. **Timeout Enforcement**: Prevents hanging requests
6. **Centralized Security**: All external requests go through security-validated path

## Backward Compatibility

- Existing functionality is preserved
- Error handling maintains compatibility with existing exception handling
- CLI tools and development configurations are respected
- No breaking changes to public APIs

## Verification

To verify the fix is working:

1. **Run Tests**: `python -m unittest discover -s tests`
2. **Check Logs**: Look for "blocked URL" warnings in application logs
3. **Test SSRF Protection**: Attempt requests to `http://127.0.0.1` - should be blocked
4. **Verify Allowlists**: Ensure metadata providers and updates still work

## Future Maintenance

- Review allowlists periodically for needed updates
- Monitor logs for legitimate requests being blocked
- Update allowlists when adding new external service integrations
- Keep the safe HTTP client updated with new security best practices

---

**Note**: This security hardening addresses SSRF vulnerabilities comprehensively while maintaining full application functionality. The centralized approach makes future security updates easier to implement and maintain.