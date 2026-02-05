# Akamai MISP Module Tests

This directory contains tests for the Akamai IOC enrichment module.

## Test Files

### test_validation.py
Standalone validation tests that can run without MISP modules environment.

**Run with:**
```bash
python tests/test_validation.py
```

Tests cover:
- Domain format validation
- API credentials validation
- API response validation

### test_akamai_ioc.py
Complete unit tests requiring MISP modules environment.

**Run with:**
```bash
pytest tests/test_akamai_ioc.py -v
```

Tests cover:
- All validation functions
- Handler function
- Module metadata functions
- Integration scenarios

## Running Tests

### Standalone Validation Tests (No Dependencies)
```bash
cd /path/to/Akamai-MISP
python tests/test_validation.py
```

### Full Test Suite (Requires MISP Modules)
```bash
# Install dev dependencies first
pip install -r requirements-dev.txt

# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=akamai_ioc --cov-report=html

# Run specific test file
pytest tests/test_akamai_ioc.py -v
```

## Test Coverage

The tests verify:
- ✓ Input validation (domains, credentials)
- ✓ API response handling
- ✓ Error conditions
- ✓ Module metadata
- ✓ Handler function logic

## CI/CD Integration

These tests can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run tests
  run: |
    pip install -r requirements.txt -r requirements-dev.txt
    pytest tests/test_validation.py -v
```

## Manual Testing

To manually test the module in MISP:

1. Install the module in MISP modules path
2. Configure API credentials in MISP settings
3. Test enrichment on a domain/hostname attribute
4. Check `akamai.log` for detailed execution logs
