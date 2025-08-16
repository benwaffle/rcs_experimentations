import requests
import uuid
import sys
from my_secrets import imsi, imei, msisdn
from pathlib import Path
import xml.etree.ElementTree as ET
from utils import detect_rcs_url

url = detect_rcs_url(imsi)

common_headers = {
    'client_channel': 'PUBLIC',
    'User-Agent': 'IM-client/OMA1.0 Google/Pixel_3-14 Goog/messages.android_20240603_01_rc01',
    'Accept-Language': 'fr-FR',
    'Connection': 'Keep-Alive'
}

tree = ET.parse('wap-provisioningdoc.xml')                                                                
root = tree.getroot()
token = root.find('.//characteristic[@type="TOKEN"]/parm[@name="token"]').get('value')
vers = root.find('.//characteristic[@type="VERS"]/parm[@name="version"]').get('value')

params_1 = {
    'vers': vers,
    'rcs_state': vers,
    'IMSI': imsi,
    'IMEI': imei,
    'terminal_model': 'Pixel 3',
    'terminal_vendor': 'Goog',
    'terminal_sw_version': '12',
    'client_vendor': 'Goog',
    'client_version': '20240603-01.01',
    'rcs_profile': 'UP_T',
    'rcs_version': '5.1B',
    'token': token,
    'SMS_port': '0'
}

response_1 = requests.get(url, headers=common_headers, params=params_1)

print(response_1)
with open('wap-provisioningdoc-refresh.xml', 'w') as f:
    f.write(response_1.text)
# Note we should probably write over wap-provisioningdoc.xml as vers could have updated
