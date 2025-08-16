import requests

def detect_rcs_url(imsi):
    mcc = imsi[:3]
    config_url = None
    urls = []
    for url_format in ['https://config.rcs.mnc{mnc}.mcc{mcc}.pub.3gppnetwork.org/', 'https://config.rcs.mnc{mnc}.mcc{mcc}.jibecloud.net/']:
        for mnc in [imsi[3:5], '0' + imsi[3:5], imsi[3:6]]:
            try:
                url = url_format.format(mcc = mcc, mnc = mnc)
                req = requests.head(url)
                # No matter the return code let's consider it a success
                # Jibe returns 405 - method not recognized
                config_url = url
                break
            except:
                pass
    return config_url
