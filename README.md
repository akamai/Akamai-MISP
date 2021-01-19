# Akamai-MISP
The MISP and Akamai integration empower SecOps teams access the Akamai enrichment module directly within MISP to curate IoC in a single location benefits of Akamai unique visibility and IoC attribution.




## Installation Requierments

* ETP Intelligence license
* Open API credentials
* MISP Platform [installed](https://www.misp-project.org/download/#virtual-images)
* Python 3.6 and above with [akamai.edgegrid](https://github.com/akamai/AkamaiOPEN-edgegrid-python) package installed

## Installation

1. Add akamai_ioc.py to ${MISP_MODULES_BASE}/site-packages/misp_modules/modules/expansion/
```
cp /local/path/akamai_ioc.py ${MISP_MODULES_BASE}/site-packages/misp_modules/modules/expansion/
```
2. reload MISP modules 
3. Configure Akamai credentials to MISP expansion module:
  * How to start with Akamai API https://developer.akamai.com/api/getting-started 
  * Once you have the Akamai API credentials you will need to browse to you Plugin setup page https://{misp-server-hostname}/servers/serverSettings/Plugin
  * From the "Enrichment" search for akamai_ioc
  * Enter the detail information from the Akamai API
    * Enrichment_akamai_ioc_enabled
    * Enrichment_akamai_ioc_client_token from API client_token
    * Enrichment_akamai_ioc_access_token from API access_token
    * Enrichment_akamai_ioc_apiURL from from API host , make sure to add https://<host>/
    * Enrichment_akamai_ioc_client_secret from API client_secret
    * Enrichment_akamai_ioc_enabled set to True
    * Enrichment_akamai_ioc_etp_config_id - Akamai customer config ID is a number represent the customer identfier can be viewed from multiple places in the luna control dashboard like from Utilities -> ETP Client Tab CUSTOMER IDENTIFIER: xxxxx


# Disclaimer of Warranty
Unless required by applicable law or agreed to in writing, Licensor provides the Work (and each Contributor provides its Contributions) on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied, including, without limitation, any warranties or conditions of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A PARTICULAR PURPOSE. You are solely responsible for determining the appropriateness of using or redistributing the Work and assume any risks associated with Your exercise of permissions under this License.

# MIT License

Copyright (c) 2020 Akamai

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
