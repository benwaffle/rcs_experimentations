import requests
import logging
import xml.etree.ElementTree as ET
from my_secrets import imsi, imei, msisdn
import uuid
import random
import hashlib
import re
import sys

tree = ET.parse('wap-provisioningdoc.xml')
root = tree.getroot()

# --- XPath Query for Realm ---
realm = root.find('.//characteristic[@type="APPAUTH"]/parm[@name="Realm"]').get('value')
username = root.find('.//characteristic[@type="APPAUTH"]/parm[@name="UserName"]').get('value')
userpwd = root.find('.//characteristic[@type="APPAUTH"]/parm[@name="UserPwd"]').get('value')
pcscf = root.find('.//characteristic[@type="LBO_P-CSCF_Address"]/parm[@name="Address"]').get('value')
token = root.find('.//characteristic[@type="TOKEN"]/parm[@name="token"]').get('value')
private_user_identity = root.find('.//characteristic[@type="APPLICATION"]/parm[@name="Private_User_Identity"]').get('value')
fthttpcsuri = root.find('.//characteristic[@type="IM"]/parm[@name="ftHTTPCSURI"]').get('value')
fthttpcsuser = root.find('.//characteristic[@type="IM"]/parm[@name="ftHTTPCSUser"]').get('value')
fthttpcspass = root.find('.//characteristic[@type="IM"]/parm[@name="ftHTTPCSPwd"]').get('value')

form = {
    'tid': (None, str(uuid.uuid4())),
    'File': ('hello.jpg', open('pic.jpg', 'rb'))
}

auth = requests.auth.HTTPBasicAuth(fthttpcsuser, fthttpcspass)
response = requests.post(fthttpcsuri, auth=auth, files=form, allow_redirects=True)
print("--request--")
print(response.request.headers)
print(response.request.body)
print("--response--")
print(response.headers)
print(response.text)
print(response.status_code)
form['File'][1].close()
