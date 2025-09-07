import socket
import ssl
import xml.etree.ElementTree as ET
from my_secrets import imsi, imei, msisdn
import uuid
import random
import hashlib
import re

tree = ET.parse('wap-provisioningdoc.xml')
root = tree.getroot()

# --- XPath Query for Realm ---
realm = root.find('.//characteristic[@type="APPAUTH"]/parm[@name="Realm"]').get('value')
username = root.find('.//characteristic[@type="APPAUTH"]/parm[@name="UserName"]').get('value')
userpwd = root.find('.//characteristic[@type="APPAUTH"]/parm[@name="UserPwd"]').get('value')
pcscf = root.find('.//characteristic[@type="LBO_P-CSCF_Address"]/parm[@name="Address"]').get('value')
del tree
del root

callid = uuid.uuid4()
sessionid = f'{random.getrandbits(128):x}'

def calculate_digest_auth(username, password, realm, method, uri, nonce, qop=None, nc=None, cnonce=None):
    def md5(s):
        return hashlib.md5(s.encode()).hexdigest()
    ha1 = f"{username}:{realm}:{password}"
    print(ha1)
    ha1 = md5(ha1)
    ha2 = f"{method}:{uri}"
    print(ha2)
    ha2 = md5(ha2)
    if qop:
        response = md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
        return f'Digest username="{username}", realm="{realm}", nonce="{nonce}", uri="{uri}", response="{response}", algorithm=MD5, qop={qop}, cnonce="{cnonce}",nc={nc}'
    else:
        response = f"{ha1}:{nonce}:{ha2}"
        print(response)
        response = md5(response)
        return f'Digest username="{username}", realm="{realm}", nonce="{nonce}", uri="{uri}", response="{response}", algorithm=MD5'


def create_ipv4_connection(address, timeout=None):
    host, port = address
    # Resolve address to IPv4 only
    addrinfo = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    # addrinfo[0] contains the first IPv4 result
    family, type, proto, canonname, sockaddr = addrinfo[0]
    print("connecting to", sockaddr)
    return socket.create_connection(sockaddr, timeout=timeout)

# Global shared TLS socket
SSOCK = None

def get_shared_ssock():
    global SSOCK
    if SSOCK is None:
        ssl_context = ssl.create_default_context()
        base_sock = create_ipv4_connection((pcscf, 5061), timeout=30)
        SSOCK = ssl_context.wrap_socket(base_sock, server_hostname=pcscf)
        print(f"Successfully connected to {pcscf}:{5061} using TLS.")
        print(f"Cipher used: {SSOCK.cipher()}")
    return SSOCK

def recv_sip_message(sock):
    buf = b""
    headers_parsed = False
    total_needed = None
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            # Connection closed by peer
            break
        buf += chunk
        if not headers_parsed:
            hdr_end = buf.find(b"\r\n\r\n")
            if hdr_end != -1:
                headers_parsed = True
                headers = buf[:hdr_end].decode('utf-8', errors='ignore')
                m = re.search(r"\r\nContent-Length:\s*(\d+)", headers, re.IGNORECASE)
                cl = int(m.group(1)) if m else 0
                total_needed = hdr_end + 4 + cl
        if headers_parsed and total_needed is not None and len(buf) >= total_needed:
            break
    return buf.decode('utf-8', errors='ignore')

def req(msg):
    msg = msg.strip().rstrip()
    msg = "\r\n".join(msg.split("\n"))
    msg += '\r\n\r\n'

    print("########## Sending ################\n-------------------------------")
    print(msg)
    print("---------------------------------")

    ssock = get_shared_ssock()
    with open('msg', 'w') as f:
        f.write(msg)

    ssock.sendall(msg.encode('utf-8'))

    # Receive exactly one SIP message based on headers and Content-Length
    print("######### Receiving ##############\n------------------------------")
    resp = recv_sip_message(ssock)
    print(resp)
    print("------------------------------")
    return resp

def main():
    branch = f'z9hG4bK{random.getrandbits(48):x}'
    tag = f'{random.getrandbits(48):x}'
    msg = f"""
REGISTER sip:{realm} SIP/2.0
Call-ID: {callid}
Session-ID: {sessionid}
Expires: 600000
CSeq: 3 REGISTER
Contact: <sip:{username}@192.168.42.42:4242;transport=tls;user=phone>;+g.3gpp.iari-ref="urn%3Aurn-7%3A3gpp-application.ims.iari.rcse.im,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.fthttp,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geopush,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geosms";+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session";+g.gsma.rcs.telephony="none";+sip.instance="<urn:uuid:B1FCAFE1-073E-4D6A-B0A6-929AB8E449DF>"
Allow: ACK,BYE,CANCEL,INFO,INVITE,MESSAGE,NOTIFY,OPTIONS,PRACK,REFER,UPDATE
Max-Forwards: 70
Authorization: Digest username="{username}", realm="{realm}", uri="sip:{realm}", response=""
Supported: 100rel,path,gruu,replaces
From: <sip:{username}@{realm}>;tag={tag}
To: <sip:{username}@{realm}>
Via: SIP/2.0/TLS 192.168.42.42:4242;branch={branch};keep;rport
P-Access-Network-Info: IEEE-802.11;i-wlan-node-id=ffffffffffff
Content-Length: 0
User-Agent: IM-client/OMA1.0
"""

# User-Agent: iOS iPhone

    answer_401 = req(msg)
    tmp = [re.match(r'WWW-Authenticate.*nonce="([^"]*)".*', x) for x in answer_401.split('\n')]
    tmp = [x for x in tmp if x]
    tmp = tmp[0]
    nonce = tmp.group(1)
    #digest = calculate_digest_auth(f"{username}", userpwd, realm, "REGISTER", f"sip:{realm}", nonce, qop='auth',cnonce='coucou',nc='00000001')
    #digest = calculate_digest_auth(f"{username}@{realm}", userpwd, realm, "REGISTER", f"sip:{realm}", nonce)
    digest = calculate_digest_auth(username, userpwd, realm, "REGISTER", f"sip:{realm}", nonce)

    branch = f'z9hG4bK{random.getrandbits(48):x}'
    # tag = f'{random.getrandbits(48):x}'
    msg = f"""
REGISTER sip:{realm} SIP/2.0
Expires: 600000
Call-ID: {callid}
Session-ID: {sessionid}
CSeq: 4 REGISTER
Contact: <sip:{username}@192.168.42.42:4242;transport=tls;user=phone>;+g.3gpp.iari-ref="urn%3Aurn-7%3A3gpp-application.ims.iari.rcse.im,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.fthttp,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geopush,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geosms";+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session";+g.gsma.rcs.telephony="none";+sip.instance="<urn:uuid:B1FCAFE1-073E-4D6A-B0A6-929AB8E449DF>"
Allow: ACK,BYE,CANCEL,INFO,INVITE,MESSAGE,NOTIFY,OPTIONS,PRACK,REFER,UPDATE
Authorization: {digest}
Supported: 100rel,path,replaces,gruu
From: <sip:{username}@{realm}>;tag={tag}
To: <sip:{username}@{realm}>
Via: SIP/2.0/TLS 192.168.42.42:4242;branch={branch};keep;rport
User-Agent: IM-client/OMA1.0
Max-Forwards: 70
P-Access-Network-Info: IEEE-802.11;i-wlan-node-id=ffffffffffff
Content-Length: 0
"""
    answer_register = req(msg)


if __name__ == "__main__":
    main()
