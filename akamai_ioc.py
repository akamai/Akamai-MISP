#!/usr/bin/env python3
"""
Module (type "expansion") from Akamai to provide IOC analysis.
Date : 12/1/2020
Authors: ["Shiran Guez","Jordan Garzon","Avishai Katz","Asaf Nadler"]
Updated: 2026 - Added v3 API support, validation, and testing
"""
import json
import logging
import os
import re
import time
from urllib.parse import urljoin, urlparse

import requests
from akamai.edgegrid import EdgeGridAuth
from pymisp import MISPEvent, MISPObject
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Log to a module-specific logger only. Never configure the root logger: this
# module runs inside the shared misp-modules process. The log file path can be
# overridden with AKAMAI_IOC_LOG_FILE. If the file cannot be opened (e.g. the
# service's working directory is not writable), fall back to propagating to the
# misp-modules loggers instead of failing at import time.
LOG_FILE = os.environ.get("AKAMAI_IOC_LOG_FILE", "akamai.log")
log = logging.getLogger("akamai_ioc")
log.setLevel(logging.DEBUG)
if not log.handlers:
    try:
        _file_handler = logging.FileHandler(LOG_FILE, mode="a")
        _file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s", datefmt="%H:%M:%S"
            )
        )
        log.addHandler(_file_handler)
    except OSError:
        pass

misperrors = {
    "error": "Error",
}

mispattributes = {
    "input": [
        "domain",
        "hostname",
    ],
    "format": "misp_standard",
}

moduleinfo = {
    "version": "2.0.0",
    "author": "Akamai Team",
    "description": "Enrich domains and hostnames with Akamai ETP (SIA) threat intelligence "
    "via the ETP Reporting API v3.",
    "module-type": ["expansion"],
}

moduleconfig = ["client_secret", "apiURL", "access_token", "client_token", "etp_config_id"]


# Custom Exception Hierarchy
class AkamaiMISPError(Exception):
    """Base exception for Akamai MISP module errors"""

    pass


class ValidationError(AkamaiMISPError):
    """Raised when input validation fails"""

    def __init__(self, field, message):
        self.field = field
        self.message = message
        super().__init__(f"Validation error for {field}: {message}")


class APIError(AkamaiMISPError):
    """Raised when API request fails"""

    def __init__(self, endpoint, status_code, message):
        self.endpoint = endpoint
        self.status_code = status_code
        self.message = message
        super().__init__(f"API error at {endpoint} ({status_code}): {message}")


class AuthenticationError(APIError):
    """Raised when API authentication fails (401)"""

    pass


class RateLimitError(APIError):
    """Raised when API rate limit is exceeded (429)"""

    pass


# API Configuration Constants
API_TIMEOUT = 30  # Request timeout in seconds
API_MAX_RETRIES = 3  # Maximum number of retries
API_BACKOFF_FACTOR = 1  # Exponential backoff factor (wait 1s, 2s, 4s, etc.)


def create_resilient_session(client_token, client_secret, access_token):
    """
    Create HTTP session with retry logic, timeout configuration, and connection pooling.

    Implements exponential backoff retry strategy for transient failures.
    Follows api-client-development skill guidelines for resilience.

    Args:
        client_token: Akamai API client token
        client_secret: Akamai API client secret
        access_token: Akamai API access token

    Returns:
        requests.Session: Configured session with retry logic
    """
    session = requests.Session()

    # Configure retry strategy with exponential backoff
    retry_strategy = Retry(
        total=API_MAX_RETRIES,
        backoff_factor=API_BACKOFF_FACTOR,
        status_forcelist=[429, 500, 502, 503, 504],  # Retry on these HTTP status codes
        allowed_methods=["GET"],  # Only retry safe GET requests
        raise_on_status=False,  # Don't raise exceptions, let our code handle status codes
    )

    # Configure HTTP adapter with retry strategy and connection pooling
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=10,  # Connection pool size
        pool_maxsize=10,  # Maximum pool size
    )

    # Mount adapter for HTTPS requests
    session.mount("https://", adapter)

    # Configure Akamai EdgeGrid authentication
    session.auth = EdgeGridAuth(
        client_token=client_token, client_secret=client_secret, access_token=access_token
    )

    log.debug("Created resilient HTTP session with retry logic and connection pooling")
    return session


def validate_domain(domain):
    """
    Validate domain/hostname format.

    Args:
        domain: Domain or hostname string to validate

    Returns:
        tuple: (is_valid, error_message)
    """
    if not domain or not isinstance(domain, str):
        return False, "Domain must be a non-empty string"

    domain = domain.strip()

    # Check length
    if len(domain) > 255:
        return False, "Domain exceeds maximum length of 255 characters"

    # Basic domain pattern validation (RFC 1035)
    # Allows: letters, numbers, hyphens, dots
    # Must not start or end with hyphen or dot
    domain_pattern = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))*\.?$")

    if not domain_pattern.match(domain):
        return False, "Invalid domain format"

    return True, None


def validate_api_credentials(config):
    """
    Validate Akamai API credentials.

    Args:
        config: Dictionary containing API credentials

    Returns:
        tuple: (is_valid, error_message)
    """
    required_fields = ["client_token", "client_secret", "access_token", "etp_config_id", "apiURL"]

    for field in required_fields:
        if field not in config:
            return False, f"Missing required field: {field}"

        value = config[field]
        if not value or (isinstance(value, str) and not value.strip()):
            return False, f"Field '{field}' cannot be empty"

    # Validate URL format
    apiURL = config["apiURL"]
    try:
        parsed = urlparse(apiURL)
        if not parsed.scheme or not parsed.netloc:
            return False, "apiURL must be a valid URL with scheme (https://)"
        if parsed.scheme != "https":
            return False, "apiURL must use HTTPS"
    except Exception as e:
        return False, f"Invalid apiURL format: {e!s}"

    # Validate config ID is numeric
    try:
        int(config["etp_config_id"])
    except ValueError:
        return False, "etp_config_id must be a valid integer"

    return True, None


def validate_api_response(response, endpoint_name):
    """
    Validate API response and provide detailed error information.

    Args:
        response: requests.Response object
        endpoint_name: Name of the endpoint for error messages

    Returns:
        tuple: (is_valid, error_message, data)
    """
    if response.status_code == 200:
        try:
            data = response.json()
            return True, None, data
        except json.JSONDecodeError as e:
            return False, f"{endpoint_name}: Invalid JSON response - {e!s}", None
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


SOURCE_TAG = "source:AkamaiETP"
INCIDENT_TAG = "AkamaiETP:incident-classification=incident"

# WHOIS fields from /ioc/information that are rendered into the free-text summary
WHOIS_TEXT_FIELDS = (
    "registrarName",
    "registrantOrganization",
    "registrantCity",
    "registrantState",
    "nameServerNames",
    "registrantAddress",
    "registrantCountry",
    "whoisServer",
)


class APIAKAOpenParser:
    def __init__(self, ctoken, csecret, atoken, configID, baseurl, rrecord):
        self.misp_event = MISPEvent()
        self.ctoken = ctoken
        self.csecret = csecret
        self.atoken = atoken
        self.baseurl = baseurl
        self.configID = configID
        self.rrecord = rrecord
        self.incident_flag = False
        self._session = None

    def _get_session(self):
        """Create the resilient session once and reuse it for every request."""
        if self._session is None:
            self._session = create_resilient_session(self.ctoken, self.csecret, self.atoken)
        return self._session

    def _api_get(self, path, params):
        """GET an ETP endpoint; query parameters are URL-encoded by requests."""
        return self._get_session().get(
            urljoin(self.baseurl, path), params=params, timeout=API_TIMEOUT
        )

    def get_results(self):
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ("Attribute", "Object") if (event.get(key))}
        return {"results": results}

    def parse_domain(self, rrecord):
        if isinstance(rrecord, str):
            rrecord = rrecord.strip()

        # Validate domain format
        is_valid, error_msg = validate_domain(rrecord)
        if not is_valid:
            log.error(f"Domain validation failed: {error_msg}")
            raise ValueError(f"Invalid domain: {error_msg}")

        aka_object = MISPObject("Akamai IOC enrich")

        # Get IOC information. A 404 means Akamai has no intel on this record,
        # which is a valid "no data" outcome rather than an error.
        result = self._api_get("/etp-report/v3/ioc/information", {"record": rrecord})
        if result.status_code == 404:
            log.info(f"No Akamai IOC information for {rrecord}")
            q = {}
        else:
            is_valid, error_msg, q = validate_api_response(result, "IOC Information")
            if not is_valid:
                log.error(f"API error: {error_msg}")
                raise Exception(error_msg)
            if not isinstance(q, dict):
                log.warning("IOC Information: unexpected response shape, ignoring body")
                q = {}

        # Customer DNS attribution runs first so the incident tag is known
        self._get_dns_info(rrecord)
        tagval = [SOURCE_TAG]
        if self.incident_flag:
            tagval.append(INCIDENT_TAG)

        to_enrich = ""
        for key in ("record", "description", "categories"):
            if q.get(key):
                to_enrich += str(q[key]) + "\n"

        whois_info = ""
        for key in WHOIS_TEXT_FIELDS:
            if q.get(key):
                whois_info += f"{key}: {q[key]}\n"

        if q.get("registrantName"):
            aka_object.add_attribute(
                "Registrant name", type="whois-registrant-name", value=str(q["registrantName"])
            )

        emails = q.get("registrantEmails")
        if emails:
            for email in emails if isinstance(emails, list) else [emails]:
                if email:
                    aka_object.add_attribute(
                        "Registrant Emails", type="whois-registrant-email", value=str(email)
                    )

        for entry in q.get("badUrls") or []:
            if not isinstance(entry, dict):
                continue
            for item in entry.get("badUrls") or []:
                url = item.get("url") if isinstance(item, dict) else None
                if url:
                    aka_object.add_attribute("PMD", type="url", value=url)

        if q.get("createdDate"):
            aka_object.add_attribute(
                "first-seen", type="datetime", value=q["createdDate"], disable_correlation=True
            )
        if q.get("lastModifiedDate"):
            aka_object.add_attribute(
                "last-seen", type="datetime", value=q["lastModifiedDate"], disable_correlation=True
            )

        seen_threats = set()
        for item in q.get("threatInformation") or []:
            threat_id = item.get("threatId") if isinstance(item, dict) else None
            if threat_id is None or threat_id in seen_threats:
                continue
            seen_threats.add(threat_id)
            self._add_threat_info(aka_object, threat_id, tagval)

        if whois_info:
            to_enrich += "\nWhois Information: \n" + whois_info + "\n"

        self._add_ioc_changes(aka_object, rrecord)

        if to_enrich:
            aka_object.add_attribute(
                "Domain Threat Info",
                type="text",
                value=to_enrich,
                Tag=list(tagval),
                disable_correlation=True,
            )
        if aka_object.attributes:
            self.misp_event.add_object(**aka_object)

    def _add_threat_info(self, aka_object, threat_id, tagval):
        """Add threat metadata for one threat ID. Failures are logged and skipped."""
        try:
            response = self._api_get(
                f"/etp-report/v3/configs/{self.configID}/threats/threat-meta",
                {"threatId": threat_id},
            )
        except requests.RequestException as e:
            log.warning(f"Failed to get threat metadata for {threat_id}: {e}")
            return
        is_valid, error_msg, d = validate_api_response(response, "Threat Metadata")
        if not is_valid or not isinstance(d, dict):
            log.warning(f"Failed to get threat metadata for {threat_id}: {error_msg}")
            return

        threat_name = d.get("threatName")
        family_name = d.get("familyName")
        description = d.get("description") or ""
        threat_info = f"\nThreat Name: {threat_name or 'unknown'}\nDescription: {description} "

        if family_name and threat_name:
            threat_tag = f'misp-galaxy:{family_name}="{threat_name}"'
        elif threat_name:
            threat_tag = f"Threat:{threat_name}"
        else:
            threat_tag = "Threat:unknown"
        # Fresh list per threat so tags never leak between threats or into tagval
        threat_tags = [*tagval, threat_tag]

        aka_object.add_attribute(
            "Threat Info",
            type="text",
            value=threat_info,
            Tag=list(threat_tags),
            disable_correlation=True,
        )
        for link in d.get("externalLinks") or []:
            if link:
                aka_object.add_attribute(
                    "reference",
                    type="link",
                    value=link,
                    Tag=list(threat_tags),
                    disable_correlation=True,
                )

    def _add_ioc_changes(self, aka_object, rrecord):
        """Add the IOC change timeline. Failures are logged and skipped."""
        try:
            changes_result = self._api_get("/etp-report/v3/ioc/changes", {"record": rrecord})
            is_valid, error_msg, changes = validate_api_response(changes_result, "IOC Changes")
            if not is_valid or not isinstance(changes, list):
                log.info(f"Could not get IOC changes: {error_msg}")
                return
            for change in changes:
                if not isinstance(change, dict) or not change.get("date"):
                    continue
                aka_object.add_attribute(
                    "timeline",
                    type="datetime",
                    value=change["date"],
                    comment=str(change.get("description", "")),
                    disable_correlation=True,
                )
        except Exception as e:
            log.info(f"Exception getting IOC changes: {e}")

    def _get_dns_info(self, rrecord):
        """Add one 'misc' object with customer DNS attribution across all dimensions."""
        end_time = int(time.time())
        start_time = end_time - 3600 * 24 * 30  # last 30 days
        filters = json.dumps({"domain": {"in": [rrecord]}}, separators=(",", ":"))
        text = ""

        for dimension in ("deviceId", "site"):
            params = {
                "cardinality": 2500,
                "dimension": dimension,
                "endTimeSec": end_time,
                "filters": filters,
                "startTimeSec": start_time,
            }
            try:
                dns_response = self._api_get(
                    f"/etp-report/v3/configs/{self.configID}/dns-activities/aggregate", params
                )
            except requests.RequestException as e:
                log.warning(f"DNS activities request failed for dimension {dimension}: {e}")
                continue
            is_valid, error_msg, result = validate_api_response(
                dns_response, f"DNS Activities ({dimension})"
            )
            if not is_valid:
                log.warning(f"DNS activities API error for dimension {dimension}: {error_msg}")
                continue
            if not isinstance(result, dict):
                continue
            total = (result.get("dimension") or {}).get("total", 0)
            if not total:
                continue

            self.incident_flag = True
            text += f"{dimension} involved\n\n"
            for el in result.get("aggregations") or []:
                if isinstance(el, dict):
                    text += f"{el.get('name')} : {el.get('total')} connections \n"
            text += "\n"

        if text:
            aka_cust_object = MISPObject("misc")
            aka_cust_object.add_attribute(
                "Customer Attribution",
                type="text",
                value=text,
                Tag=[SOURCE_TAG],
                disable_correlation=True,
            )
            self.misp_event.add_object(**aka_cust_object)


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo


def handler(q=False):
    if q is False:
        return False

    try:
        request = json.loads(q)
    except json.JSONDecodeError as e:
        misperrors["error"] = f"Invalid JSON input: {e!s}"
        return misperrors

    # Validate configuration
    if not request.get("config"):
        misperrors["error"] = "Missing configuration"
        return misperrors

    is_valid, error_msg = validate_api_credentials(request["config"])
    if not is_valid:
        misperrors["error"] = f"Configuration validation failed: {error_msg}"
        return misperrors

    # Validate attribute
    if "attribute" not in request:
        misperrors["error"] = "Missing attribute in request"
        return misperrors

    attribute = request["attribute"]

    if "type" not in attribute:
        misperrors["error"] = "Missing attribute type"
        return misperrors

    if attribute["type"] not in ["domain", "hostname"]:
        misperrors["error"] = f"Unsupported attribute type: {attribute['type']}"
        return misperrors

    # Extract values
    ctoken = str(request["config"]["client_token"])
    csecret = str(request["config"]["client_secret"])
    atoken = str(request["config"]["access_token"])
    configID = str(request["config"]["etp_config_id"])
    baseurl = str(request["config"]["apiURL"])
    rrecord = attribute.get("value") or attribute.get("value1")

    if not rrecord:
        misperrors["error"] = "Missing attribute value"
        return misperrors

    # Map attribute type to parser method
    mapping = {"domain": "parse_domain", "hostname": "parse_domain"}

    try:
        aka_parser = APIAKAOpenParser(ctoken, csecret, atoken, configID, baseurl, rrecord)
        attribute_value = attribute.get("value") or attribute.get("value1")
        getattr(aka_parser, mapping[attribute["type"]])(attribute_value)
        return aka_parser.get_results()
    except ValueError as e:
        misperrors["error"] = f"Validation error: {e!s}"
        log.error(f"Validation error: {e!s}")
        return misperrors
    except Exception as e:
        misperrors["error"] = f"Processing error: {e!s}"
        log.error(f"Processing error: {e!s}")
        return misperrors
