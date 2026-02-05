# Changelog

All notable changes to the Akamai-MISP integration module.

## [2.0.0] - 2026-02-05

### Major Changes

#### API v3 Migration
- Migrated all API endpoints from v1/v2 to v3
- Updated IOC information endpoint: `v1/ioc/information` → `v3/ioc/information`
- Updated threat metadata endpoint: `v1/configs/{id}/threats/{threatId}` → `v3/configs/{id}/threats/threat-meta`
- Updated IOC changes endpoint: `v1/ioc/changes` → `v3/ioc/changes`
- Updated DNS activities endpoint: `v2/configs/{id}/dns-activities/aggregate` → `v3/configs/{id}/dns-activities/aggregate`

### Added

#### Comprehensive Validation
- **Domain/Hostname Validation** (RFC 1035 compliant)
  - Format validation with regex pattern matching
  - Length validation (max 255 characters)
  - Character validation (alphanumeric, hyphens, dots)
  - Prevention of invalid formats (leading/trailing hyphens, double dots)

- **API Credentials Validation**
  - Required field presence checks
  - Non-empty value validation
  - HTTPS-only URL enforcement
  - Numeric config ID validation
  - URL format validation with urlparse

- **API Response Validation**
  - HTTP status code handling for all error codes
  - Detailed error messages per status code
  - JSON response structure validation
  - Rate limiting awareness (429 handling)
  - Server error handling (5xx codes)

#### Testing Infrastructure
- Created comprehensive test suite in `tests/` directory
- `test_validation.py` - Standalone validation tests (no MISP environment needed)
- `test_akamai_ioc.py` - Full unit tests with pytest
- `tests/README.md` - Testing documentation
- `validate_module.sh` - Pre-deployment validation script

#### Improved Error Handling
- Better exception handling with specific error types
- Try-catch blocks for API calls
- Graceful degradation for optional API calls (changes, DNS activities)
- Detailed error logging with context

#### Documentation
- Created `CLAUDE.md` - Claude Code guidance document
- Updated `README.md` with new features and troubleshooting
- Added `CHANGELOG.md` - This file
- Added `tests/README.md` - Testing guide
- Comprehensive inline code documentation

### Changed

#### Dependencies
- Updated `pymisp` from `~=2.4.184.2` to `>=2.5.32` (MISP 2.5.32+ compatible)
- Updated `requests` from `~=2.31.0` to `>=2.31.0`
- Added `edgegrid-python>=1.3.1` to requirements.txt
- Created `requirements-dev.txt` with testing dependencies:
  - `pytest>=8.0.0`
  - `pytest-mock>=3.12.0`
  - `pytest-cov>=4.1.0`
  - `responses>=0.24.0`
  - `ruff>=0.1.0`
  - `mypy>=1.8.0`
  - `bandit>=1.7.5`

#### Code Quality
- Added type hints preparation (imported `re` and `urlparse`)
- Improved code organization with validation functions
- Enhanced logging with contextual information
- Better variable naming and code readability

#### Handler Function
- Complete rewrite with comprehensive validation
- Better error messages for all failure scenarios
- Input sanitization and validation
- Proper exception handling with specific error types

### Fixed

#### API Compatibility
- Fixed compatibility with Akamai ETP Reporting API v3
- Corrected threat metadata endpoint structure (path param → query param)
- Updated DNS activities endpoint to v3

#### Error Handling
- Fixed missing error handling for API failures
- Added validation to prevent crashes on invalid input
- Improved handling of optional/missing data in API responses

#### Logging
- Fixed log levels for different scenarios
- Added error context to log messages
- Improved debugging information

### Security

#### Input Validation
- Domain format validation prevents injection attacks
- URL validation ensures HTTPS-only connections
- Credential validation prevents empty/invalid credentials
- API response validation prevents malformed data processing

#### Dependency Updates
- Updated to latest secure versions of dependencies
- Added security scanning tools (bandit) to dev dependencies

### Compatibility

#### MISP Versions
- Minimum: MISP 2.4.x
- Recommended: MISP 2.5.32+
- Tested with: pymisp 2.5.32

#### Python Versions
- Minimum: Python 3.6
- Recommended: Python 3.10+

#### API Versions
- Akamai ETP Reporting API v3
- API Documentation: https://techdocs.akamai.com/etp-reporting/reference/api

### Known Issues

#### Threat Metadata Endpoint
The threat metadata endpoint changed from v1 to v3:
- v1: `/configs/{configId}/threats/{threatId}` (path parameter)
- v3: `/configs/{configId}/threats/threat-meta?threatId={id}` (query parameter)

The v3 endpoint structure may require additional testing to verify the response format matches expectations. The module includes a comment noting this change at line 129.

### Migration Notes

#### For Existing Users

1. **Update Dependencies**:
   ```bash
   pip install -r requirements.txt --upgrade
   ```

2. **Test Before Deployment**:
   ```bash
   ./validate_module.sh
   ```

3. **Backup Configuration**: Your existing MISP configuration settings remain compatible.

4. **Monitor Logs**: Check `akamai.log` after deployment for any API compatibility issues.

5. **Verify API Endpoints**: Ensure your Akamai API credentials have access to v3 endpoints.

#### Breaking Changes

- API endpoints changed from v1/v2 to v3 (handled automatically by the module)
- Requires pymisp 2.5.32+ (may require MISP platform upgrade)
- Python 3.6+ now strictly required (was recommended before)

### Contributors

Original Authors:
- Shiran Guez
- Jordan Garzon
- Avishai Katz
- Asaf Nadler

2026 Updates:
- API v3 migration
- Validation and testing additions
- Documentation improvements

---

## [1.0.0] - 2020-12-01

### Initial Release

- MISP expansion module for Akamai ETP Intelligence
- IOC enrichment for domains and hostnames
- WHOIS data retrieval
- Threat information with MISP galaxy tags
- DNS activity tracking
- Timeline of IOC changes
- Akamai ETP Reporting API v1 integration
