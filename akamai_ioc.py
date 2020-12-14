#!/usr/bin/env python3
"""
Module (type "expansion") from Akamai to provide IOC analysis.
Date : 12/1/2020
Authers: ["Shiran Guez","Jordan Garzon","Avishai Katz","Asaf Nadler"]
"""
import json
import time
import requests
from urllib.parse import urljoin
from akamai.edgegrid import EdgeGridAuth
from . import check_input_attribute, checking_error, standard_error_message
from pymisp import MISPAttribute, MISPEvent, MISPObject
import logging
import logging.handlers

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

class APIAKAOpenParser():
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
        results = {key: event[key] for key in ('Attribute', 'Object') if (key in event and event[key])}
        return {'results': results}

     def parse_domain(self, rrecord):
        aka_object = MISPObject('Akamai IOC enrich')
        session  = requests.Session()
        session.auth = EdgeGridAuth(
        client_token  = self.ctoken,
        client_secret = self.csecret,
        access_token  = self.atoken
        )
        result = session.get(urljoin(self.baseurl, '/etp-report/v1/ioc/information?record=' + rrecord))  
        q = result.json()
        to_Enrich = ""
        whois_info = ""
        urlList = ""
        commentval = "Akamai IOC enrich"
        tagval = ["source:AkamaiETP"]
        threatInfo = ""
        for (k, v) in q.items():
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
                aka_object.add_attribute('first-seen', **{'type': 'datetime', 'value': q[k]})
            if k == 'lastModifiedDate':
                aka_object.add_attribute('last-seen', **{'type': 'datetime', 'value': q[k]})
            if k == 'threatInformation' and threatInfo == "":
                threatIN = q['threatInformation']
                tmpI = 0
                ThreatTag = tagval
                for item in threatIN:
                    if item['threatId'] != tmpI:
                        addresult = session.get(urljoin(self.baseurl, '/etp-report/v1/configs/' + str(self.configID) + '/threats/' + str(item['threatId'])))
                        d = addresult.json()
                        threatInfo = "\nThreat Name: " + str(d['threatName']) + "\nDescription: " + str(d['description'] + " ")
                        try:
                            if d['familyName'] != "" and d['threatName'] != "":
                                NEWTAGAPP="misp-galaxy:"+d['familyName']+'="'+d['threatName']+'"'
                            else:
                                NEWTAGAPP="Threat:"+d['threatName']
                        except:
                            NEWTAGAPP="Threat:unknown"

                        ThreatTag.append(NEWTAGAPP)
                        aka_object.add_attribute('Threat Info', type='text', value=threatInfo, Tag=ThreatTag)
                        for link in d['externalLinks']:
                            aka_object.add_attribute('reference', type='link', value=link, Tag=ThreatTag)
                        tmpI = item['threatId']
        if whois_info != "":
            to_Enrich += "\nWhois Information: \n" + whois_info + "\n"
        if urlList != "":
            to_Enrich += "\nURL list: \n" + urlList + "\n"
        self._get_dns_info(rrecord)
        
        try:
            changes_result = session.get(urljoin(self.baseurl, '/etp-report/v1/ioc/changes?record=' + rrecord))
            changes = changes_result.json()
            for change in changes:
                aka_object.add_attribute('timeline', **{'type': 'datetime', 'value': change['date'], 'comment': str(change["description"])})
        except Exception as e:
            log.info('Exception in custom info {}'.format(e))

        aka_object.add_attribute('Domain Threat Info', type='text', value=to_Enrich, Tag=tagval)
        self.misp_event.add_object(**aka_object)
        
     def _get_dns_info(self, rrecord):
        aka_cust_object = MISPObject('misc')
        tagInfo=["source:AkamaiETP"]
        _text = ""
        dimensions = ['deviceId','site']
        for dimension in dimensions:
            #_result = self._run_custom_request(self, rrecord, dimension)
            session  = requests.Session()
            session.auth = EdgeGridAuth(
               client_token  = self.ctoken,
               client_secret = self.csecret,
               access_token  = self.atoken
            )
            confID = self.configID
            epoch_time = int(time.time())
            last_30_days = epoch_time - 3600 * 24 * 30  # last month by default for now
            url = f'/etp-report/v2/configs/{str(confID)}' + \
                  f'/dns-activities/aggregate?cardinality=2500&dimension={dimension}&endTimeSec={epoch_time}&filters' + \
                  f'=%7B%22domain%22:%7B%22in%22:%5B%22{rrecord}%22%5D%7D%7D&startTimeSec={last_30_days}'
            _result = session.get(urljoin(self.baseurl, url)).json()
            if _result['dimension']['total'] != 0:
                 _text += dimension + ' involved\n\n'
                 if 'aggregations' in _result:
                    for el in _result['aggregations']:
                        name = el['name']
                        _text += f"{name} : {el['total']} connections \n"
                    aka_cust_object.add_attribute('Customer Attribution', type='text', value=str(_text), Tag=tagInfo)
                 self.misp_event.add_object(**aka_cust_object)


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo


def handler(q=False):
    if q is False:
        return False
    request  = json.loads(q)
    attribute = request['attribute']
    ctoken   = str(request['config']['client_token'])
    csecret  = str(request['config']['client_secret'])
    atoken   = str(request['config']['access_token'])
    configID = str(request['config']['etp_config_id'])
    baseurl  = str(request['config']['apiURL'])
    rrecord = str(attribute['value'])
    mapping = {
            'domain': 'parse_domain'
    }
    aka_parser = APIAKAOpenParser(ctoken, csecret, atoken, configID, baseurl, rrecord)
    attribute_value = attribute['value'] if 'value' in attribute else attribute['value1']
    getattr(aka_parser, mapping[attribute['type']])(attribute_value)
    return aka_parser.get_results()



