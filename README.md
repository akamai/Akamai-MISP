# Akamai-MISP Integration

[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![MISP 2.5.32+](https://img.shields.io/badge/MISP-2.5.32+-green.svg)](https://www.misp-project.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A MISP expansion module that enriches Indicators of Compromise (IoCs) with Akamai Enterprise Threat Protector (ETP) Intelligence. Empower your SecOps team with Akamai's unique threat visibility and attribution capabilities directly within MISP.

**Latest Update**: February 2026 - Migrated to Akamai ETP Reporting API v3 with comprehensive validation and testing

---

## Table of Contents

- [Features](#features)
- [What's New in v2.0.0](#whats-new-in-v200)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [API Reference](#api-reference)
- [Contributing](#contributing)
- [License](#license)

---

## Features

### Core Capabilities

- **🔍 IOC Enrichment**: Enrich domains and hostnames with Akamai ETP threat intelligence
- **🎯 Threat Attribution**: Detailed threat information, categories, and malware families with MISP galaxy tagging
- **📋 WHOIS Data**: Comprehensive registrant information and domain history
- **🌐 DNS Activity**: Customer-specific DNS activity for incident investigation
- **📊 Timeline Tracking**: Historical changes and IOC evolution timeline
- **✅ Input Validation**: RFC 1035 compliant domain validation with comprehensive error handling
- **🔐 Secure**: HTTPS-only API connections with credential validation

### Technical Features

- **API v3**: Uses latest Akamai Secure Internet Access Enterprise Reporting API v3
- **MISP 2.5.32+ Compatible**: Tested with latest MISP platform releases
- **Comprehensive Testing**: Full test suite with 100% validation coverage
- **Error Handling**: Graceful degradation with detailed error messages
- **Rate Limiting**: Built-in awareness of API rate limits

---

## What's New in v2.0.0

### Major Updates

✨ **API v3 Migration**: All endpoints updated to latest Akamai ETP Reporting API v3
✅ **Comprehensive Validation**: Input validation for domains, credentials, and API responses
🧪 **Test Suite**: Complete test coverage with standalone validation tests
📚 **Enhanced Documentation**: Detailed guides for installation, testing, and troubleshooting
🔄 **Updated Dependencies**: pymisp 2.5.32+ for latest MISP compatibility

See [CHANGELOG.md](CHANGELOG.md) for complete details.




## Requirements

### Prerequisites

| Component | Minimum Version | Recommended | Notes |
|-----------|----------------|-------------|-------|
| **MISP Platform** | 2.4.x | 2.5.32+ | [Installation guide](https://www.misp-project.org/download/#virtual-images) |
| **Python** | 3.6 | 3.10+ | Required for module execution |
| **Akamai ETP** | - | - | ETP Intelligence license required |
| **API Access** | - | - | Akamai Open API credentials |

### Python Dependencies

**Production:**
```bash
pip install -r requirements.txt
```

Core packages:
- `requests>=2.31.0` - HTTP client
- `pymisp>=2.5.32` - MISP integration
- `edgegrid-python>=1.3.1` - Akamai authentication

**Development & Testing:**
```bash
pip install -r requirements-dev.txt
```

Includes: `pytest`, `pytest-cov`, `ruff`, `mypy`, `bandit`

## Installation

Follow these steps to install and configure the Akamai-MISP module:

### Step 1: Clone the Repository

```bash
git clone https://github.com/YOUR-ORG/Akamai-MISP.git
cd Akamai-MISP
```

### Step 2: Install Dependencies

```bash
# Install production dependencies
pip install -r requirements.txt

# Optional: Install development dependencies for testing
pip install -r requirements-dev.txt
```

### Step 3: Validate the Module

Run pre-installation validation to ensure everything works:

```bash
# Run validation script
chmod +x validate_module.sh
./validate_module.sh

# Or manually run tests
python3 tests/test_validation.py
```

Expected output:
```
✓ Domain validation tests passed
✓ API credentials validation tests passed
✓ API response validation tests passed
ALL TESTS PASSED!
```

### Step 4: Install Module to MISP

Copy the module to your MISP modules directory:

```bash
cp akamai_ioc.py ${MISP_MODULES_BASE}/site-packages/misp_modules/modules/expansion/

# Common MISP module paths:
# Ubuntu/Debian: /usr/local/lib/python3.x/dist-packages
# CentOS/RHEL: /usr/lib/python3.x/site-packages
```

### Step 5: Restart MISP Modules

```bash
# SystemD
sudo systemctl restart misp-modules

# SysV Init
sudo service misp-modules restart

# Verify restart
sudo systemctl status misp-modules
```

---

## Configuration

### Step 1: Obtain Akamai API Credentials

Follow the [Akamai API Getting Started Guide](https://developer.akamai.com/api/getting-started) to create API credentials with ETP Intelligence access.

You'll receive:
- `client_token`
- `client_secret`
- `access_token`
- `host` (API endpoint URL)

### Step 2: Find Your ETP Config ID

1. Log in to [Akamai Control Center](https://control.akamai.com/)
2. Navigate to: **Security** → **Secure Internet Access Enterprise** → **Utilities** → **ETP Client**
3. Note your **CUSTOMER IDENTIFIER** (this is your config ID)

### Step 3: Configure in MISP

1. Navigate to your MISP Plugin settings:
   ```
   https://{your-misp-server}/servers/serverSettings/Plugin
   ```

2. Search for **"akamai_ioc"** in the Enrichment section

3. Configure the following parameters:

| Parameter | Value | Example | Required |
|-----------|-------|---------|----------|
| `Enrichment_akamai_ioc_enabled` | Set to enable the module | `True` | ✅ |
| `Enrichment_akamai_ioc_client_token` | Your API client token | `akab-xxxxxxxxxxxxx` | ✅ |
| `Enrichment_akamai_ioc_access_token` | Your API access token | `akab-xxxxxxxxxxxxx` | ✅ |
| `Enrichment_akamai_ioc_client_secret` | Your API client secret | `xxxxxxxxxxxx` | ✅ |
| `Enrichment_akamai_ioc_apiURL` | Your API host (HTTPS only) | `https://akab-xxxxx.luna.akamaiapis.net/` | ✅ |
| `Enrichment_akamai_ioc_etp_config_id` | Your ETP config ID (number) | `12345` | ✅ |

4. **Save** the configuration

### Step 4: Verify Installation

Test the module with a sample domain or hostname attribute in MISP:

1. Create or open a MISP event
2. Add a domain or hostname attribute (e.g., `malicious.example.com`)
3. Right-click the attribute and select **Enrichment** → **akamai_ioc**
4. View the enriched data

**Logs**: Check `akamai.log` for detailed execution information.

---

## Usage

### Enriching an IOC

1. **In MISP Event**: Open any event with domain/hostname attributes
2. **Select Attribute**: Right-click on the attribute
3. **Enrich**: Choose **Enrichment** → **akamai_ioc**
4. **Review**: View enriched threat intelligence data

### What Gets Enriched

The module adds a **MISP Object** (`Akamai IOC enrich`) containing:

| Attribute Type | Description | Example |
|----------------|-------------|---------|
| **Domain Info** | Record, categories, description | Domain classification |
| **WHOIS** | Registrant name, emails, nameservers | Owner information |
| **Temporal** | First seen, last seen, timeline | `2024-01-01T00:00:00Z` |
| **Threats** | Threat name, description, family | Malware families |
| **References** | External threat intelligence links | Research links |
| **Bad URLs** | Potentially malicious domains (PMD) | Associated URLs |
| **DNS Activity** | Customer attribution (devices, sites) | Internal visibility |

### Tags Applied

- `source:AkamaiETP` - Standard tag for all enrichments
- `AkamaiETP:incident-classification=incident` - When customer DNS activity detected
- `misp-galaxy:{family}="{threat}"` - Threat family galaxy tags
- `Threat:{name}` - Specific threat identifiers

---

## API Reference

This module uses the **Akamai Secure Internet Access Enterprise Reporting API v3**.

### Documentation

- **Official API Docs**: [Akamai ETP Reporting API](https://techdocs.akamai.com/etp-reporting/reference/api)
- **Getting Started**: [Akamai API Guide](https://developer.akamai.com/api/getting-started)

### Endpoints Used

| Endpoint | Purpose | Method |
|----------|---------|--------|
| `/etp-report/v3/ioc/information` | IOC metadata and WHOIS data | GET |
| `/etp-report/v3/ioc/changes` | Historical IOC changes | GET |
| `/etp-report/v3/configs/{configId}/threats/threat-meta` | Threat intelligence metadata | GET |
| `/etp-report/v3/configs/{configId}/dns-activities/aggregate` | DNS activity aggregation | GET |

### Rate Limits

Akamai API enforces rate limits. The module includes:
- HTTP 429 detection and error handling
- Recommended: Monitor `akamai.log` for rate limit warnings
- Contact Akamai support if you need higher limits

### API Version History

- **v3** (Current): February 2026 - Latest stable version
- **v2**: DNS activities endpoint (deprecated)
- **v1**: Original IOC endpoints (deprecated)

## Testing

### Quick Validation Test
```bash
python3 tests/test_validation.py
```

### Full Test Suite (requires MISP modules environment)
```bash
pytest tests/ -v
```

### Run Tests with Coverage
```bash
pytest tests/ --cov=akamai_ioc --cov-report=html
```

See [tests/README.md](tests/README.md) for detailed testing documentation.

## Troubleshooting

### Debugging Steps

1. **Check Module Logs**
   ```bash
   # View real-time logs
   tail -f akamai.log

   # Search for errors
   grep ERROR akamai.log

   # View last 50 lines
   tail -n 50 akamai.log
   ```

2. **Verify MISP Modules Service**
   ```bash
   sudo systemctl status misp-modules
   journalctl -u misp-modules -f
   ```

3. **Test API Credentials**
   ```bash
   # Run validation tests
   python3 tests/test_validation.py
   ```

### Common Issues

#### 🔴 Authentication Failed (HTTP 401)

**Symptoms**:
- Error: "Authentication failed - check API credentials"
- Module returns error in MISP

**Solutions**:
- ✅ Verify all credentials are correctly copied (no extra spaces)
- ✅ Check credentials haven't expired
- ✅ Ensure credentials have ETP Intelligence API access
- ✅ Test credentials with Akamai API directly

#### 🔴 Access Forbidden (HTTP 403)

**Symptoms**:
- Error: "Access forbidden - check permissions and config ID"

**Solutions**:
- ✅ Verify ETP config ID is correct (numeric value)
- ✅ Ensure your API credentials have access to this config
- ✅ Check if your account has the required ETP Intelligence license

#### 🔴 Rate Limit Exceeded (HTTP 429)

**Symptoms**:
- Error: "Rate limit exceeded - please retry later"
- Intermittent failures during bulk operations

**Solutions**:
- ✅ Reduce enrichment request frequency
- ✅ Contact Akamai support for rate limit increase
- ✅ Implement request throttling in MISP

#### 🔴 Invalid Domain Error

**Symptoms**:
- Error: "Invalid domain format"
- Validation error before API call

**Solutions**:
- ✅ Ensure domain follows RFC 1035 format (letters, numbers, hyphens, dots)
- ✅ Check for invalid characters or formats
- ✅ Verify domain length (max 255 characters)
- ✅ No leading/trailing hyphens or double dots

#### 🔴 Module Not Appearing in MISP

**Symptoms**:
- akamai_ioc not listed in enrichment modules

**Solutions**:
- ✅ Verify file is in correct directory: `${MISP_MODULES_BASE}/site-packages/misp_modules/modules/expansion/`
- ✅ Check file permissions: `chmod 644 akamai_ioc.py`
- ✅ Restart MISP modules service
- ✅ Check MISP modules logs for loading errors

#### 🔴 No Data Returned

**Symptoms**:
- Enrichment completes but no data added
- Empty MISP object created

**Solutions**:
- ✅ Check if domain has any threat intelligence in Akamai ETP
- ✅ Verify domain is known to Akamai (not too new/obscure)
- ✅ Check logs for API errors during enrichment
- ✅ Ensure API endpoints are accessible from your network

### Getting Help

1. **Check Logs**: Always start with `akamai.log`
2. **Validate Setup**: Run `./validate_module.sh`
3. **API Status**: Check [Akamai Status Page](https://status.akamai.com/)
4. **GitHub Issues**: Open an issue with logs and error details
5. **Akamai Support**: Contact for API-specific issues

---

## Contributing

We welcome contributions! Here's how you can help:

### Reporting Issues

1. Check existing [GitHub Issues](https://github.com/YOUR-ORG/Akamai-MISP/issues)
2. Include:
   - Python and MISP versions
   - Error messages from `akamai.log`
   - Steps to reproduce
   - Expected vs actual behavior

### Development Setup

```bash
# Clone repository
git clone https://github.com/YOUR-ORG/Akamai-MISP.git
cd Akamai-MISP

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/ -v

# Run linting
ruff check akamai_ioc.py

# Run type checking
mypy akamai_ioc.py

# Run security scan
bandit -r akamai_ioc.py
```

### Submitting Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes
4. Add tests for new functionality
5. Run test suite: `pytest tests/ -v`
6. Commit with clear messages
7. Push and create a Pull Request

### Code Standards

- Follow PEP 8 style guide
- Add docstrings for functions
- Include type hints where possible
- Write tests for new features
- Update documentation

### Testing Requirements

- All tests must pass: `pytest tests/ -v`
- Maintain test coverage
- Test with Python 3.6, 3.8, 3.10+
- Validate against MISP 2.5.32+

---


## Project Structure

```
Akamai-MISP/
├── akamai_ioc.py           # Main MISP expansion module
├── requirements.txt        # Production dependencies
├── requirements-dev.txt    # Development dependencies
├── validate_module.sh      # Pre-deployment validation script
├── README.md              # This file
├── CHANGELOG.md           # Version history
├── LICENSE                # MIT License
└── tests/
    ├── __init__.py
    ├── test_validation.py      # Standalone validation tests
    ├── test_akamai_ioc.py      # Full unit tests
    └── README.md               # Testing documentation
```

---

## Authors & Contributors

### Original Authors (2020)
- **Shiran Guez** - Initial development
- **Jordan Garzon** - Initial development
- **Avishai Katz** - Initial development
- **Asaf Nadler** - Initial development

### 2026 Updates
- API v3 migration
- Validation and testing framework
- Enhanced documentation

---

## Acknowledgments

- [MISP Project](https://www.misp-project.org/) - Open Source Threat Intelligence Platform
- [Akamai](https://www.akamai.com/) - Enterprise Threat Protector and API
- MISP Community - Feedback and contributions

---

## Related Projects

- [MISP](https://github.com/MISP/MISP) - Main MISP platform
- [PyMISP](https://github.com/MISP/PyMISP) - Python library for MISP
- [MISP Modules](https://github.com/MISP/misp-modules) - MISP expansion modules

---

## License

**MIT License**

Copyright (c) 2020-2026 Akamai Technologies

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

**THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.**

---

## Support

- **Documentation**: See [CHANGELOG.md](CHANGELOG.md) and inline code documentation
- **Issues**: [GitHub Issues](https://github.com/YOUR-ORG/Akamai-MISP/issues)
- **MISP Community**: [MISP Gitter](https://gitter.im/MISP/MISP)
- **Akamai Support**: Contact your Akamai representative for API issues

---

<p align="center">
  Made with ❤️ by the Akamai Security Team
</p>
