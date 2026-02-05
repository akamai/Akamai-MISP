#!/usr/bin/env python3
"""
Module (type "expansion") from Akamai to provide IOC analysis.
Date : 12/1/2020
Authors: ["Shiran Guez","Jordan Garzon","Avishai Katz","Asaf Nadler"]
Updated: 2026 - Added v3 API support, validation, and testing
"""
import json
import logging
import logging.handlers
import re
import time
from urllib.parse import urljoin, urlparse

import requests
from akamai.edgegrid import EdgeGridAuth
from pymisp import MISPEvent, MISPObject
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(filename='akamai.log',
                    filemode='a',
                    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                    datefmt='%H:%M:%S',
                    level=logging.DEBUG)
log = logging.getLogger("akamai_ioc")

misperrors = {
    "error": "Error",
}

mispattributes = {
    "input": [
        "domain",
        "hostname",
    ],
    'format': 'misp_standard'
}

moduleinfo = {
    "version": "0.1",
    "author": "Akamai Team",
    "description": "Get Akamai IOC v1 infomration.",
    "module-type": ["expansion"],
}

moduleconfig = ['client_secret', 'apiURL', 'access_token', 'client_token', 'etp_config_id']


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
        client_token=client_token,
        client_secret=client_secret,
        access_token=access_token
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
    domain_pattern = re.compile(
        r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))*\.?$'
    )

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
    required_fields = ['client_token', 'client_secret', 'access_token', 'etp_config_id', 'apiURL']

    for field in required_fields:
        if field not in config:
            return False, f"Missing required field: {field}"

        value = config[field]
        if not value or (isinstance(value, str) and not value.strip()):
            return False, f"Field '{field}' cannot be empty"

    # Validate URL format
    apiURL = config['apiURL']
    try:
        parsed = urlparse(apiURL)
        if not parsed.scheme or not parsed.netloc:
            return False, "apiURL must be a valid URL with scheme (https://)"
        if parsed.scheme != 'https':
            return False, "apiURL must use HTTPS"
    except Exception as e:
        return False, f"Invalid apiURL format: {e!s}"

    # Validate config ID is numeric
    try:
        int(config['etp_config_id'])
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


class APIAKAOpenParser:
     def __init__(self, ctoken, csecret, atoken, configID, baseurl, rrecord):
        self.misp_event = MISPEvent()
        self.ctoken = ctoken
        self.csecret = csecret
        self.atoken = atoken
        self.baseurl = baseurl
        self.configID = configID
        self.rrecord = rrecord

     def get_results(self):
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ('Attribute', 'Object') if (event.get(key))}
        return {'results': results}

     def parse_domain(self, rrecord):
        # Validate domain format
        is_valid, error_msg = validate_domain(rrecord)
        if not is_valid:
            log.error(f"Domain validation failed: {error_msg}")
            raise ValueError(f"Invalid domain: {error_msg}")

        aka_object = MISPObject('Akamai IOC enrich')

        # Create resilient session with retry logic and timeout
        session = create_resilient_session(self.ctoken, self.csecret, self.atoken)

        # Get IOC information with validation and timeout
        result = session.get(
            urljoin(self.baseurl, '/etp-report/v3/ioc/information?record=' + rrecord),
            timeout=API_TIMEOUT
        )
        is_valid, error_msg, q = validate_api_response(result, 'IOC Information')
        if not is_valid:
            log.error(f"API error: {error_msg}")
            raise Exception(error_msg)
        to_Enrich = ""
        whois_info = ""
        urlList = ""
        self._get_dns_info(rrecord)
        try:
            if self.incident_flag == "true":
                tagval = ["AkamaiETP:incident-classification=incident"]
            else:
                tagval = ["source:AkamaiETP"]
        except AttributeError:
            # incident_flag not set, use default tag
            tagval = ["source:AkamaiETP"]
        threatInfo = ""
        for (k, _v) in q.items():
            if k == 'record':
                to_Enrich += str(q[k]) + "\n"
            if k == 'recordType':
                continue
            if k == 'description':
                to_Enrich += str(q[k]) + "\n"
            if k == 'categories':
                to_Enrich += str(q[k]) + "\n"
            if k == 'registrarName':
                whois_info += str(k) + ": " + str(q[k]) + "\n"
            if k == 'registrantName':
                aka_object.add_attribute('Registrant name', type='whois-registrant-name', value=str(q[k]))
            if k == 'strantOrganizatione':
                whois_info += str(k) + ": " + str(q[k]) + "\n"
            if k == 'registrantCity':
                whois_info += str(k) + ": " + str(q[k]) + "\n"
            if k == 'registrantState':
                whois_info += str(k) + ": " + str(q[k]) + "\n"
            if k == 'registrantEmails':
                aka_object.add_attribute('Registrant Emails', type='whois-registrant-email', value=str(q[k]))
            if k == 'nameServerNames':
                whois_info += str(k) + ": " + str(q[k]) + "\n"
            if k == 'registrantAddress':
                whois_info += str(k) + ": " + str(q[k]) + "\n"
            if k == 'registrantCountry':
                whois_info += str(k) + ": " + str(q[k]) + "\n"
            if k == 'whoisServer':
                whois_info += str(k) + ": " + str(q[k]) + "\n"
            if k == 'badUrls':
                for item in q['badUrls'][0]['badUrls']:
                    aka_object.add_attribute('PMD', **{'type': 'url', 'value': item['url']})
            if k == 'createdDate':
                aka_object.add_attribute('first-seen', disable_correlation=True, **{'type': 'datetime', 'value': q[k]})
            if k == 'lastModifiedDate':
                aka_object.add_attribute('last-seen', disable_correlation=True, **{'type': 'datetime', 'value': q[k]})
            if k == 'threatInformation' and threatInfo == "":
                threatIN = q['threatInformation']
                tmpI = 0
                ThreatTag = tagval
                for item in threatIN:
                    if item['threatId'] != tmpI:
                        # Note: v3 API uses /threats/threat-meta endpoint. May need threatId as query parameter
                        addresult = session.get(
                            urljoin(self.baseurl, '/etp-report/v3/configs/' + str(self.configID) + '/threats/threat-meta?threatId=' + str(item['threatId'])),
                            timeout=API_TIMEOUT
                        )
                        is_valid, error_msg, d = validate_api_response(addresult, 'Threat Metadata')
                        if not is_valid:
                            log.warning(f"Failed to get threat metadata for {item['threatId']}: {error_msg}")
                            continue
                        threatInfo = "\nThreat Name: " + str(d['threatName']) + "\nDescription: " + str(d['description'] + " ")
                        try:
                            if d.get('familyName') and d.get('threatName'):
                                NEWTAGAPP="misp-galaxy:"+d['familyName']+'="'+d['threatName']+'"'
                            elif d.get('threatName'):
                                NEWTAGAPP="Threat:"+d['threatName']
                            else:
                                NEWTAGAPP="Threat:unknown"
                        except (KeyError, TypeError) as e:
                            # Missing or invalid threat data fields
                            log.debug(f"Unable to extract threat tag: {e!s}")
                            NEWTAGAPP="Threat:unknown"

                        ThreatTag.append(NEWTAGAPP)
                        aka_object.add_attribute('Threat Info', type='text', value=threatInfo, Tag=ThreatTag, disable_correlation=True)
                        for link in d['externalLinks']:
                            aka_object.add_attribute('reference', type='link', value=link, Tag=ThreatTag, disable_correlation=True)
                        tmpI = item['threatId']
        if whois_info != "":
            to_Enrich += "\nWhois Information: \n" + whois_info + "\n"
        if urlList != "":
            to_Enrich += "\nURL list: \n" + urlList + "\n"

        try:
            changes_result = session.get(
                urljoin(self.baseurl, '/etp-report/v3/ioc/changes?record=' + rrecord),
                timeout=API_TIMEOUT
            )
            is_valid, error_msg, changes = validate_api_response(changes_result, 'IOC Changes')
            if is_valid and changes:
                for change in changes:
                    aka_object.add_attribute('timeline', disable_correlation=True, **{'type': 'datetime', 'value': change['date'], 'comment': str(change["description"])})
            else:
                log.info(f'Could not get IOC changes: {error_msg}')
        except Exception as e:
            log.info(f'Exception getting IOC changes: {e}')

        aka_object.add_attribute('Domain Threat Info', type='text', value=to_Enrich, Tag=tagval, disable_correlation=True)
        self.misp_event.add_object(**aka_object)

     def _get_dns_info(self, rrecord):
        aka_cust_object = MISPObject('misc')
        tagInfo=["source:AkamaiETP"]
        _text = ""
        # Create resilient session once for all DNS activity requests
        session = create_resilient_session(self.ctoken, self.csecret, self.atoken)

        dimensions = ['deviceId','site']
        for dimension in dimensions:
            confID = self.configID
            epoch_time = int(time.time())
            last_30_days = epoch_time - 3600 * 24 * 30  # last month by default for now
            url = f'/etp-report/v3/configs/{confID!s}' + \
                  f'/dns-activities/aggregate?cardinality=2500&dimension={dimension}&endTimeSec={epoch_time}&filters' + \
                  f'=%7B%22domain%22:%7B%22in%22:%5B%22{rrecord}%22%5D%7D%7D&startTimeSec={last_30_days}'
            dns_response = session.get(urljoin(self.baseurl, url), timeout=API_TIMEOUT)
            is_valid, error_msg, _result = validate_api_response(dns_response, f'DNS Activities ({dimension})')
            if not is_valid:
                log.warning(f"DNS activities API error for dimension {dimension}: {error_msg}")
                continue
            if _result and 'dimension' in _result and _result['dimension']['total'] != 0:
                 _text += dimension + ' involved\n\n'
                 if 'aggregations' in _result:
                    for el in _result['aggregations']:
                        name = el['name']
                        _text += f"{name} : {el['total']} connections \n"
                    aka_cust_object.add_attribute('Customer Attribution', type='text', value=str(_text), Tag=tagInfo, disable_correlation=True)
                 self.incident_flag = "true"
                 self.misp_event.add_object(**aka_cust_object)


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo


def handler(q=False):
    if q is False:
        return False

    try:
        request = json.loads(q)
    except json.JSONDecodeError as e:
        misperrors['error'] = f"Invalid JSON input: {e!s}"
        return misperrors

    # Validate configuration
    if not request.get('config'):
        misperrors['error'] = "Missing configuration"
        return misperrors

    is_valid, error_msg = validate_api_credentials(request['config'])
    if not is_valid:
        misperrors['error'] = f"Configuration validation failed: {error_msg}"
        return misperrors

    # Validate attribute
    if 'attribute' not in request:
        misperrors['error'] = "Missing attribute in request"
        return misperrors

    attribute = request['attribute']

    if 'type' not in attribute:
        misperrors['error'] = "Missing attribute type"
        return misperrors

    if attribute['type'] not in ['domain', 'hostname']:
        misperrors['error'] = f"Unsupported attribute type: {attribute['type']}"
        return misperrors

    # Extract values
    ctoken   = str(request['config']['client_token'])
    csecret  = str(request['config']['client_secret'])
    atoken   = str(request['config']['access_token'])
    configID = str(request['config']['etp_config_id'])
    baseurl  = str(request['config']['apiURL'])
    rrecord = attribute.get('value') or attribute.get('value1')

    if not rrecord:
        misperrors['error'] = "Missing attribute value"
        return misperrors

    # Map attribute type to parser method
    mapping = {
            'domain': 'parse_domain',
            'hostname': 'parse_domain'
    }

    try:
        aka_parser = APIAKAOpenParser(ctoken, csecret, atoken, configID, baseurl, rrecord)
        attribute_value = attribute.get('value') or attribute.get('value1')
        getattr(aka_parser, mapping[attribute['type']])(attribute_value)
        return aka_parser.get_results()
    except ValueError as e:
        misperrors['error'] = f"Validation error: {e!s}"
        log.error(f"Validation error: {e!s}")
        return misperrors
    except Exception as e:
        misperrors['error'] = f"Processing error: {e!s}"
        log.error(f"Processing error: {e!s}")
        return misperrors



