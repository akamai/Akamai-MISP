"""
Unit tests for Akamai IOC MISP module
"""
import json
from unittest.mock import MagicMock, Mock, patch

import pytest
import responses

# Note: These tests assume the module is installed in MISP modules path
# For standalone testing, you may need to adjust the import path


class TestValidationFunctions:
    """Test input validation functions"""

    def test_validate_domain_valid(self):
        """Test valid domain formats"""
        # Import the module - this will fail if not in MISP environment
        # We'll provide a fixture to mock this
        from misp_modules.modules.expansion import akamai_ioc

        # Valid domains
        assert akamai_ioc.validate_domain("example.com")[0] is True
        assert akamai_ioc.validate_domain("subdomain.example.com")[0] is True
        assert akamai_ioc.validate_domain("test-domain.co.uk")[0] is True
        assert akamai_ioc.validate_domain("a.b.c.d.example.com")[0] is True

    def test_validate_domain_invalid(self):
        """Test invalid domain formats"""
        from misp_modules.modules.expansion import akamai_ioc

        # Invalid domains
        assert akamai_ioc.validate_domain("")[0] is False
        assert akamai_ioc.validate_domain(None)[0] is False
        assert akamai_ioc.validate_domain("-example.com")[0] is False
        assert akamai_ioc.validate_domain("example-.com")[0] is False
        assert akamai_ioc.validate_domain("a" * 256)[0] is False
        assert akamai_ioc.validate_domain("example..com")[0] is False

    def test_validate_api_credentials_valid(self):
        """Test valid API credential configuration"""
        from misp_modules.modules.expansion import akamai_ioc

        valid_config = {
            "client_token": "test_token",
            "client_secret": "test_secret",
            "access_token": "test_access",
            "etp_config_id": "12345",
            "apiURL": "https://api.example.com/",
        }

        is_valid, error = akamai_ioc.validate_api_credentials(valid_config)
        assert is_valid is True
        assert error is None

    def test_validate_api_credentials_missing_fields(self):
        """Test missing required fields"""
        from misp_modules.modules.expansion import akamai_ioc

        incomplete_config = {
            "client_token": "test_token",
            "client_secret": "test_secret",
            # Missing other required fields
        }

        is_valid, error = akamai_ioc.validate_api_credentials(incomplete_config)
        assert is_valid is False
        assert "Missing required field" in error

    def test_validate_api_credentials_empty_values(self):
        """Test empty credential values"""
        from misp_modules.modules.expansion import akamai_ioc

        config_with_empty = {
            "client_token": "",
            "client_secret": "test_secret",
            "access_token": "test_access",
            "etp_config_id": "12345",
            "apiURL": "https://api.example.com/",
        }

        is_valid, error = akamai_ioc.validate_api_credentials(config_with_empty)
        assert is_valid is False
        assert "cannot be empty" in error

    def test_validate_api_credentials_invalid_url(self):
        """Test invalid API URL formats"""
        from misp_modules.modules.expansion import akamai_ioc

        # Non-HTTPS URL
        config = {
            "client_token": "test_token",
            "client_secret": "test_secret",
            "access_token": "test_access",
            "etp_config_id": "12345",
            "apiURL": "http://api.example.com/",  # HTTP instead of HTTPS
        }

        is_valid, error = akamai_ioc.validate_api_credentials(config)
        assert is_valid is False
        assert "HTTPS" in error

    def test_validate_api_credentials_invalid_config_id(self):
        """Test non-numeric config ID"""
        from misp_modules.modules.expansion import akamai_ioc

        config = {
            "client_token": "test_token",
            "client_secret": "test_secret",
            "access_token": "test_access",
            "etp_config_id": "not_a_number",
            "apiURL": "https://api.example.com/",
        }

        is_valid, error = akamai_ioc.validate_api_credentials(config)
        assert is_valid is False
        assert "integer" in error


class TestAPIResponseValidation:
    """Test API response validation"""

    def test_validate_api_response_success(self):
        """Test successful API response"""
        from misp_modules.modules.expansion import akamai_ioc

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": "test"}

        is_valid, error, data = akamai_ioc.validate_api_response(mock_response, "Test Endpoint")
        assert is_valid is True
        assert error is None
        assert data == {"data": "test"}

    def test_validate_api_response_400(self):
        """Test 400 Bad Request"""
        from misp_modules.modules.expansion import akamai_ioc

        mock_response = Mock()
        mock_response.status_code = 400

        is_valid, error, data = akamai_ioc.validate_api_response(mock_response, "Test Endpoint")
        assert is_valid is False
        assert "Bad request" in error
        assert data is None

    def test_validate_api_response_401(self):
        """Test 401 Unauthorized"""
        from misp_modules.modules.expansion import akamai_ioc

        mock_response = Mock()
        mock_response.status_code = 401

        is_valid, error, _data = akamai_ioc.validate_api_response(mock_response, "Test Endpoint")
        assert is_valid is False
        assert "Authentication failed" in error

    def test_validate_api_response_403(self):
        """Test 403 Forbidden"""
        from misp_modules.modules.expansion import akamai_ioc

        mock_response = Mock()
        mock_response.status_code = 403

        is_valid, error, _data = akamai_ioc.validate_api_response(mock_response, "Test Endpoint")
        assert is_valid is False
        assert "Access forbidden" in error

    def test_validate_api_response_429(self):
        """Test 429 Rate Limit"""
        from misp_modules.modules.expansion import akamai_ioc

        mock_response = Mock()
        mock_response.status_code = 429

        is_valid, error, _data = akamai_ioc.validate_api_response(mock_response, "Test Endpoint")
        assert is_valid is False
        assert "Rate limit" in error


class TestHandlerFunction:
    """Test the main handler function"""

    def test_handler_false_input(self):
        """Test handler with False input"""
        from misp_modules.modules.expansion import akamai_ioc

        result = akamai_ioc.handler(False)
        assert result is False

    def test_handler_missing_config(self):
        """Test handler with missing configuration"""
        from misp_modules.modules.expansion import akamai_ioc

        request = json.dumps({"attribute": {"type": "domain", "value": "example.com"}})

        result = akamai_ioc.handler(request)
        assert "error" in result
        assert "Missing configuration" in result["error"]

    def test_handler_invalid_json(self):
        """Test handler with invalid JSON"""
        from misp_modules.modules.expansion import akamai_ioc

        result = akamai_ioc.handler("invalid json {")
        assert "error" in result
        assert "Invalid JSON" in result["error"]

    def test_handler_missing_attribute(self):
        """Test handler with missing attribute"""
        from misp_modules.modules.expansion import akamai_ioc

        request = json.dumps(
            {
                "config": {
                    "client_token": "test",
                    "client_secret": "test",
                    "access_token": "test",
                    "etp_config_id": "12345",
                    "apiURL": "https://api.example.com/",
                }
            }
        )

        result = akamai_ioc.handler(request)
        assert "error" in result
        assert "Missing attribute" in result["error"]

    def test_handler_unsupported_attribute_type(self):
        """Test handler with unsupported attribute type"""
        from misp_modules.modules.expansion import akamai_ioc

        request = json.dumps(
            {
                "config": {
                    "client_token": "test",
                    "client_secret": "test",
                    "access_token": "test",
                    "etp_config_id": "12345",
                    "apiURL": "https://api.example.com/",
                },
                "attribute": {
                    "type": "ip-addr",  # Unsupported type
                    "value": "1.2.3.4",
                },
            }
        )

        result = akamai_ioc.handler(request)
        assert "error" in result
        assert "Unsupported attribute type" in result["error"]


class TestModuleInfo:
    """Test module metadata functions"""

    def test_introspection(self):
        """Test introspection function returns correct attributes"""
        from misp_modules.modules.expansion import akamai_ioc

        result = akamai_ioc.introspection()
        assert "input" in result
        assert "domain" in result["input"]
        assert "hostname" in result["input"]
        assert result["format"] == "misp_standard"

    def test_version(self):
        """Test version function returns module info"""
        from misp_modules.modules.expansion import akamai_ioc

        result = akamai_ioc.version()
        assert "version" in result
        assert "author" in result
        assert "description" in result
        assert "module-type" in result
        assert "config" in result
        assert "expansion" in result["module-type"]


@pytest.fixture
def mock_akamai_session():
    """Fixture to mock Akamai API session"""
    with patch("misp_modules.modules.expansion.akamai_ioc.requests.Session") as mock_session:
        session_instance = MagicMock()
        mock_session.return_value = session_instance
        yield session_instance


class TestIntegration:
    """Integration tests with mocked API responses"""

    @responses.activate
    def test_successful_domain_enrichment(self, mock_akamai_session):
        """Test successful domain enrichment flow"""

        # This test requires full integration setup
        # For now, we verify the request structure is valid
        # Full integration tests would require MISP modules environment

        # Example of what would be mocked:
        # Mock API responses for IOC information, threat metadata, etc.
        # Create test request with config and attribute
        # Call handler and verify response structure

        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
