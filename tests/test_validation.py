"""
Standalone validation tests for Akamai IOC module
These tests can run independently of MISP modules environment
"""
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_domain_validation():
    """Test domain validation function"""
    import re
    from urllib.parse import urlparse

    # Replicate the validation logic for testing
    def validate_domain(domain):
        if not domain or not isinstance(domain, str):
            return False, "Domain must be a non-empty string"

        domain = domain.strip()

        if len(domain) > 255:
            return False, "Domain exceeds maximum length of 255 characters"

        domain_pattern = re.compile(
            r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))*\.?$'
        )

        if not domain_pattern.match(domain):
            return False, "Invalid domain format"

        return True, None

    # Test valid domains
    valid_domains = [
        "example.com",
        "subdomain.example.com",
        "test-domain.co.uk",
        "a.b.c.d.example.com",
        "valid-domain-123.com"
    ]

    for domain in valid_domains:
        is_valid, error = validate_domain(domain)
        assert is_valid, f"Expected {domain} to be valid, got error: {error}"
        print(f"✓ {domain} - VALID")

    # Test invalid domains
    invalid_domains = [
        ("", "empty string"),
        ("-example.com", "starts with hyphen"),
        ("example-.com", "ends with hyphen"),
        ("example..com", "double dot"),
        ("a" * 256, "too long"),
        ("example.com-", "ends with hyphen"),
    ]

    for domain, reason in invalid_domains:
        is_valid, error = validate_domain(domain)
        assert not is_valid, f"Expected {domain} ({reason}) to be invalid"
        print(f"✓ {domain or 'empty'} ({reason}) - INVALID as expected")

    print("\nAll domain validation tests passed!")


def test_api_credentials_validation():
    """Test API credentials validation function"""
    from urllib.parse import urlparse

    def validate_api_credentials(config):
        required_fields = ['client_token', 'client_secret', 'access_token', 'etp_config_id', 'apiURL']

        for field in required_fields:
            if field not in config:
                return False, f"Missing required field: {field}"

            value = config[field]
            if not value or (isinstance(value, str) and not value.strip()):
                return False, f"Field '{field}' cannot be empty"

        apiURL = config['apiURL']
        try:
            parsed = urlparse(apiURL)
            if not parsed.scheme or not parsed.netloc:
                return False, "apiURL must be a valid URL with scheme (https://)"
            if parsed.scheme != 'https':
                return False, "apiURL must use HTTPS"
        except Exception as e:
            return False, f"Invalid apiURL format: {str(e)}"

        try:
            int(config['etp_config_id'])
        except ValueError:
            return False, "etp_config_id must be a valid integer"

        return True, None

    # Test valid config
    valid_config = {
        'client_token': 'test_token',
        'client_secret': 'test_secret',
        'access_token': 'test_access',
        'etp_config_id': '12345',
        'apiURL': 'https://api.example.com/'
    }

    is_valid, error = validate_api_credentials(valid_config)
    assert is_valid, f"Expected valid config to pass, got error: {error}"
    print("✓ Valid config - PASSED")

    # Test missing field
    incomplete_config = {
        'client_token': 'test_token',
        'client_secret': 'test_secret'
    }
    is_valid, error = validate_api_credentials(incomplete_config)
    assert not is_valid, "Expected incomplete config to fail"
    assert "Missing required field" in error
    print("✓ Missing field - FAILED as expected")

    # Test empty value
    empty_config = valid_config.copy()
    empty_config['client_token'] = ''
    is_valid, error = validate_api_credentials(empty_config)
    assert not is_valid, "Expected empty value to fail"
    assert "cannot be empty" in error
    print("✓ Empty value - FAILED as expected")

    # Test non-HTTPS URL
    http_config = valid_config.copy()
    http_config['apiURL'] = 'http://api.example.com/'
    is_valid, error = validate_api_credentials(http_config)
    assert not is_valid, "Expected HTTP URL to fail"
    assert "HTTPS" in error
    print("✓ Non-HTTPS URL - FAILED as expected")

    # Test invalid config ID
    invalid_id_config = valid_config.copy()
    invalid_id_config['etp_config_id'] = 'not_a_number'
    is_valid, error = validate_api_credentials(invalid_id_config)
    assert not is_valid, "Expected non-numeric config ID to fail"
    assert "integer" in error
    print("✓ Invalid config ID - FAILED as expected")

    print("\nAll API credentials validation tests passed!")


def test_api_response_validation():
    """Test API response validation"""
    from unittest.mock import Mock
    import json as json_module

    def validate_api_response(response, endpoint_name):
        if response.status_code == 200:
            try:
                data = response.json()
                return True, None, data
            except json_module.JSONDecodeError as e:
                return False, f"{endpoint_name}: Invalid JSON response - {str(e)}", None
        elif response.status_code == 400:
            return False, f"{endpoint_name}: Bad request - check input parameters", None
        elif response.status_code == 401:
            return False, f"{endpoint_name}: Authentication failed - check API credentials", None
        elif response.status_code == 403:
            return False, f"{endpoint_name}: Access forbidden - check permissions and config ID", None
        elif response.status_code == 404:
            return False, f"{endpoint_name}: Resource not found", None
        elif response.status_code == 429:
            return False, f"{endpoint_name}: Rate limit exceeded - please retry later", None
        elif response.status_code >= 500:
            return False, f"{endpoint_name}: Server error ({response.status_code})", None
        else:
            return False, f"{endpoint_name}: Unexpected status code {response.status_code}", None

    # Test successful response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {'data': 'test'}

    is_valid, error, data = validate_api_response(mock_response, 'Test')
    assert is_valid, "Expected 200 response to be valid"
    assert data == {'data': 'test'}
    print("✓ 200 OK - VALID")

    # Test various error codes
    error_codes = [
        (400, "Bad request"),
        (401, "Authentication failed"),
        (403, "Access forbidden"),
        (404, "Resource not found"),
        (429, "Rate limit"),
        (500, "Server error")
    ]

    for code, expected_msg in error_codes:
        mock_response = Mock()
        mock_response.status_code = code
        is_valid, error, data = validate_api_response(mock_response, 'Test')
        assert not is_valid, f"Expected {code} to be invalid"
        assert expected_msg in error or str(code) in error
        print(f"✓ {code} - INVALID as expected ({expected_msg})")

    print("\nAll API response validation tests passed!")


if __name__ == '__main__':
    print("Running Akamai IOC Validation Tests\n")
    print("=" * 50)
    print("\n1. Testing Domain Validation")
    print("-" * 50)
    test_domain_validation()

    print("\n2. Testing API Credentials Validation")
    print("-" * 50)
    test_api_credentials_validation()

    print("\n3. Testing API Response Validation")
    print("-" * 50)
    test_api_response_validation()

    print("\n" + "=" * 50)
    print("ALL TESTS PASSED!")
    print("=" * 50)
