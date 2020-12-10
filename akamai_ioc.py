#!/usr/bin/env python3
"""
Module (type "expansion") from Akamai to provide IOC analysis.
Date : 12/1/2020
Authers: ["Shiran Guez","Jordan Garzon","Avishai Katz","Asaf Nadler"]
Converted to MISP Obj
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
        log.info('EVENT Raw {}'.format(event))
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
        log.info('Restuls Raw {}'.format(q))
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
                whois_info += str(k) + ": " + str(q[k]) + "\n"
            if k == 'strantOrganizatione':
                whois_info += str(k) + ": " + str(q[k]) + "\n"
            if k == 'registrantCity':
                whois_info += str(k) + ": " + str(q[k]) + "\n"
            if k == 'registrantState':
                whois_info += str(k) + ": " + str(q[k]) + "\n"
            if k == 'registrantEmails':
                whois_info += str(k) + ": " + str(q[k]) + "\n"
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
                    urlList += str(item['url']) + "\n"
            if k == 'createdDate':
                to_Enrich += "Record Created: " + str(q[k]) + "\n"
            if k == 'lastModifiedDate':
                to_Enrich += "Record Last Modified: " + str(q[k]) + "\n"
            ''' 
            if k == 'threatInformation' and threatInfo == "":
                addresult = session.get(urljoin(self.baseurl, '/etp-report/v1/configs/' + str(
                    self.configID) + '/threats/' + str(q['threatInformation'][0]['threatId'])))
                d = addresult.json()
                log.info('Restuls Raw TINFO {}'.format(d))
                threatInfo = "\nThreat Name: " + str(d['threatName']) + "\nLinks: " + str(
                    d['externalLinks']) + "\nDescription: " + str(d['description'] + " ")
                commentval += threatInfo
            '''
        #formatted_changes = get_ioc_changes(session, self.baseurl, rrecord)
        #to_Enrich += "\nIOC Changes: \n" + formatted_changes + "\n"
        if whois_info != "":
            to_Enrich += "\nWhois Information: \n" + whois_info + "\n"
        if urlList != "":
            to_Enrich += "\nURL list: \n" + urlList + "\n"
        #try:
        #    custom_info = get_customize_info(session, self.baseurl, request)
        #    to_Enrich += custom_info
        #except Exception as e:
        #    log.info('Exception in custom info {}'.format(e))
        
        aka_object.add_attribute('Domain Threat Info', type='text', value=to_Enrich, Tag=tagval)
        self.misp_event.add_object(**aka_object)
        

    

def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo


def handler(q=False):
    if q is False:
        return False
    request  = json.loads(q)
    log.info('request raw: {}'.format(request))
    attribute = request['attribute']
    ctoken   = str(request['config']['client_token'])
    csecret  = str(request['config']['client_secret'])
    atoken   = str(request['config']['access_token'])
    configID = str(request['config']['etp_config_id'])
    baseurl  = str(request['config']['apiURL'])
    rrecord = str(attribute['value'])
    log.info('record request {}'.format(rrecord))
    mapping = {
            'domain': 'parse_domain'
    }
    aka_parser = APIAKAOpenParser(ctoken, csecret, atoken, configID, baseurl, rrecord)
    log.info('aka_parser {}'.format(aka_parser))
    attribute_value = attribute['value'] if 'value' in attribute else attribute['value1']
    log.info('attribute_value {}'.format(attribute_value))
    getattr(aka_parser, mapping[attribute['type']])(attribute_value)
    return aka_parser.get_results()


def get_customize_info(session, baseurl, request):
    machines_text = '\n\n'
    user_text = '\n\n'
    machine_result = run_custom_request(session, baseurl, request, dimension='deviceId')
    if machine_result['dimension']['total'] != 0:
      machines_text += 'Machines involved\n\n'
      if 'aggregations' in machine_result:
         for el in machine_result['aggregations']:
            name = el['name']
            if "Not" in name:
                name = 'No machine name attributed'
            machines_text += f"{name} : {el['total']} connections \n"

    user_result = run_custom_request(session, baseurl, request, dimension='encryptedUserName')
    if user_result['dimension']['total'] != 0:
      if 'aggregations' in user_result:
         user_text += 'Users involved : \n\n'
         for el in user_result['aggregations']:
            name = el['name']
            if len(name) < 2:
                name = 'No user name attributed'
            user_text += f"{name} : {el['total']} connections \n"
    return machines_text + user_text


def run_custom_request(session, baseurl, request, dimension):
    start, end = get_epoch_range()
    url = f'/etp-report/v2/configs/{str(request["config"]["etp_config_id"])}' + \
          f'/threat-events/aggregate?cardinality=2500&dimension={dimension}&endTimeSec={end}&filters' + \
          f'=%7B%22domain%22:%7B%22in%22:%5B%22{rrecord}%22%5D%7D%7D&startTimeSec={start}'
    result = session.get(urljoin(baseurl, url)).json()
    return result


def get_epoch_range():
    epoch_time = int(time.time())
    last_30_days = epoch_time - 3600 * 24 * 30  # last month by default for now
    return last_30_days, epoch_time


def get_ioc_changes(session, baseurl, domain):
    changes_result = session.get(urljoin(baseurl, '/etp-report/v1/ioc/changes?record=' + domain))
    changes = changes_result.json()
    reduced_changes = [{"date": str(change["date"]), "description": str(change["description"])} for change in changes]
    return '\n'.join([str(change) for change in reduced_changes])
