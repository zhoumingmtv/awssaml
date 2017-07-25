# -*- coding: utf-8 -*-

import base64
import boto3
import re
import requests
import sys
from getpass import getpass
from bs4 import BeautifulSoup
from urlparse import urlparse
import xml.etree.ElementTree as ET

def get_sts(username, password):
    # If you write an invalid fqdn that ends on mongodb.com it redirects you to www.mongodb.com so the session.get will work but for the wrong page
    idpentryurl = 'https://idp.mongodb.com/simplesaml/saml2/idp/SSOService.php?spentityid=urn:amazon:webservices:ops'

    sslverification = True
    
    # The session object will be needed to get the form and to submit it later
    session = requests.Session()
    try:
        formresponse = session.get(idpentryurl, verify=sslverification)
    except requests.exceptions.RequestException as e:
        print("Error: {}").format(e)
        session.close()
        sys.exit(1)
        
    # with requests.Session() as s:
    #     formresponse = session.get(idpentryurl, verify=sslverification)
    # if formresponse.status_code != 200:
    #     raise Exception(str(formresponse.reason))

    idpauthformsubmiturl = formresponse.url
    formsoup = BeautifulSoup(formresponse.text.decode('utf8'), "html.parser")

    payload = {}
    for inputtag in formsoup.find_all(re.compile('(INPUT|input)')):
        name = inputtag.get('name','')
        value = inputtag.get('value','')
        if "user" in name.lower():
            payload[name] = username
        elif "email" in name.lower():
            payload[name] = username
        elif "pass" in name.lower():
            payload[name] = password
        else:
            payload[name] = value

    '''
    for inputtag in formsoup.find_all(re.compile('(FORM|form)')):
        action = inputtag.get('action')
        if action and action != "?":
            parsedurl = urlparse(idpentryurl)
            idpauthformsubmiturl = parsedurl.scheme + "://" + parsedurl.netloc + action
    '''

    response = session.post(idpauthformsubmiturl, data=payload, verify=sslverification)
    soup = BeautifulSoup(response.text.decode('utf8'), "html.parser")
    for inputtag in soup.find_all(re.compile('(INPUT|input)')):
        if inputtag.get('name') == 'SAMLResponse':
            assertion = inputtag.get('value')
            break
    else:
        raise Exception('Response did not contain a valid SAML assertion')
    assert all([ord(c) < 128 for c in assertion]), 'SAML assertion is not valid'

    awsroles = []
    root = ET.fromstring(base64.b64decode(assertion))

    for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
        if saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role':
            for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                awsroles.append(saml2attributevalue.text)

    for index, awsrole in enumerate(awsroles):
        chunks = awsrole.split(',')
        if 'saml-provider' in chunks[0]:
            newawsrole = chunks[1] + ',' + chunks[0]
            awsroles.insert(index, newawsrole)
            awsroles.remove(awsrole)

    print ""
    if len(awsroles) > 1:
        i = 0
        print "Please choose the role you would like to assume:"
        for awsrole in awsroles:
            print '[', i, ']: ', awsrole.split(',')[0]
            i += 1

        print "Selection: ",
        selectedroleindex = raw_input()

        # Basic sanity check of input
        if int(selectedroleindex) > (len(awsroles) - 1):
            print 'You selected an invalid role index, please try again'
            sys.exit(0)

        role_arn = awsroles[int(selectedroleindex)].split(',')[0]
        principal_arn = awsroles[int(selectedroleindex)].split(',')[1]

    else:
        role_arn = awsroles[0].split(',')[0]
        principal_arn = awsroles[0].split(',')[1]
        print role_arn, principal_arn

    # Use the assertion to get an AWS STS token using Assume Role with SAML
    client = boto3.client('sts')
    # If DurationSeconds has a higher than 3600 it will raise botocore.exceptions.ClientError (ValidationError)
    token = client.assume_role_with_saml(RoleArn=role_arn, PrincipalArn=principal_arn, SAMLAssertion=assertion, DurationSeconds=3600)
    return token

if __name__ == "__main__":
    username = sys.argv[1]
    password = getpass()
    token = get_sts(username, password)
    for k, v in iter(token.items()):
        print k, ':', v
    print
    for k, v in iter(token.get('Credentials').items()):
        print k, ':', v
