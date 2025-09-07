import requests
import uuid
import sys
from my_secrets import imsi, imei, msisdn
from pathlib import Path

session = requests.Session()

#config_url = 'https://config.rcs.mnc010.mcc208.pub.3gppnetwork.org/'
mcc = imsi[:3]
config_url = 'https://rcs-acs-tmo-us.jibe.google.com' #f'https://config.rcs.mnc010.mcc{mcc}.jibecloud.net/'
urls = []

p = Path("wap-provisioningdoc.xml")
if p.exists():
    print("Looks like you're already authed. If you're sure, delete wap-provisioningdoc.xml")
    sys.exit(0)

#for url_format in ['https://rsc-acs-tmo-us.jibe.google.com', 'https://config.rcs.mnc{mnc}.mcc{mcc}.pub.3gppnetwork.org/', 'https://config.rcs.mnc{mnc}.mcc{mcc}.jibecloud.net/']:
#    for mnc in [imsi[3:5], '0' + imsi[3:5], imsi[3:6]]:
#        try:
#            url = url_format.format(mcc = mcc, mnc = mnc)
#            req = requests.head(url)
#            # No matter the return code let's consider it a success
#            # Jibe returns 405 - method not recognized
#            config_url = url
#            break
#        except:
#            pass

print("Successful url", config_url)


common_headers = {
    'client_channel': 'PUBLIC',
    'User-Agent': 'IM-client/OMA1.0 Google/Pixel_3-14 Goog/messages.android_20240603_01_rc01',
    'Accept-Language': 'fr-FR',
    'Connection': 'Keep-Alive'
}

params_1 = {
    'vers': '0',
    'rcs_state': '0',
    'IMSI': imsi,
    'IMEI': imei,
    'terminal_model': 'Pixel 3',
    'terminal_vendor': 'Goog',
    'terminal_sw_version': '12',
    'client_vendor': 'Goog',
    'client_version': '20240603-01.01',
    'rcs_profile': 'UP_T',
    'rcs_version': '5.1B',
    'token': '',
    'SMS_port': '0'
}

response_1 = session.get(config_url, headers=common_headers, params=params_1)

print(response_1)
print(response_1.text)
print(response_1.cookies)


params_2 = params_1.copy()
params_2.update({
    'msisdn': msisdn,
})

headers_2 = common_headers.copy()
headers_2.update({
    'msisdn_source': 'msisdn_source_sim'
})

response_2 = session.get(config_url, headers=headers_2, params=params_2)
print(response_2)
print(response_2.text)
print(response_2.__dict__)

if response_2.status_code != 200 and response_2.status_code != 511:
    print('Error: ', response_2.status_code)
    sys.exit(0)

cookies = response_2.cookies
print(cookies)

otp = input("Please enter the OTP: ")

params_3 = params_2.copy()
params_3 = {
    'OTP': otp
}

response_3 = session.get(config_url, headers=common_headers, params=params_3)
print(response_3)
print(response_3.text)
with open('wap-provisioningdoc.xml', 'w') as f:
    f.write(response_3.text)
