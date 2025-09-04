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
tag = f'{random.getrandbits(48):x}'
branch = f'z9hG4bK-{random.getrandbits(48):x}'

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

def req(msg):
    msg = msg.strip().rstrip()
    msg = "\r\n".join(msg.split("\n"))
    msg += '\r\n\r\n'

    ssl_context = ssl.create_default_context()
    #with socket.create_connection((pcscf, 5601), timeout=30) as sock:
    # Workaround vpn
    with create_ipv4_connection((pcscf, 5061), timeout=30) as sock:
        # Wrap the socket with SSL/TLS, specifying the SNI
        with ssl_context.wrap_socket(sock, server_hostname=pcscf) as ssock:
            print(f"Successfully connected to {pcscf}:{5061} using TLS.")
            print(f"Cipher used: {ssock.cipher()}")
            with open('msg', 'w') as f:
                f.write(msg)

            ssock.sendall(msg.encode('utf-8'))

            # Receive and print all data from the server until it closes the connection
            print("\nReceived from server:")
            response = b""
            while True:
                data = ssock.recv(4096)
                if not data:
                    break
                response += data
            
            resp = response.decode('utf-8', errors='ignore')
            print(resp)
            return resp

def main():
    msg = f"""
REGISTER sip:{realm} SIP/2.0
Call-ID: {callid}
CSeq: 0 REGISTER
Contact: <sip:{username}@192.168.42.42:4242;transport=tcp>;+sip.instance="<urn:uuid:6f474eac-f1a1-4085-b654-c9ed5c9cf1c3>";+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session,urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session.group,urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.msg,urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.largemsg,urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.systemmsg,urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.filetransfer";+g.3gpp.iari-ref="urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.ftthumb,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.fthttp,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.ftsms,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.chatbot.sa,urn%3Aurn-7%3A3gpp-application.ims.iari.rcse.im,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geopush,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geosm";+g.gsma.rcs.cpm.pager-large;+g.gsma.rcs.botversion="#=1,#=2";reg-id=0;expires=60000
Allow: NOTIFY, OPTIONS, INVITE, UPDATE, CANCEL, BYE, ACK, MESSAGE
Authorization: Digest username="{username}@{realm}", realm="{realm}", uri="sip:{realm}", response=""
Supported: path,gruu
Accept-Encoding: gzip
From: <sip:{username}@{realm}>;tag={tag}
To: <sip:{username}@{realm}>
Via: SIP/2.0/TLS 192.168.42.42:4242;branch={branch}
User-Agent: IM-client/OMA1.0 Samsung/Pixel_3-12 Samsung-RCS/6.0 3gpp-gba
"""
    print(msg)
    answer_401 = req(msg)
    tmp = [re.match(r'WWW-Authenticate.*nonce="([^"]*)".*', x) for x in answer_401.split('\n')]
    tmp = [x for x in tmp if x]
    tmp = tmp[0]
    nonce = tmp.group(1)
    #digest = calculate_digest_auth(f"{username}", userpwd, realm, "REGISTER", f"sip:{realm}", nonce, qop='auth',cnonce='coucou',nc='00000001')
    digest = calculate_digest_auth(f"{username}@{realm}", userpwd, realm, "REGISTER", f"sip:{realm}", nonce)

    msg = f"""
REGISTER sip:{realm} SIP/2.0
Call-ID: {callid}
CSeq: 1 REGISTER
Contact: <sip:{username}@192.168.42.42:4242;transport=tcp>;+sip.instance="<urn:uuid:6f474eac-f1a1-4085-b654-c9ed5c9cf1c3>";+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session,urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session.group,urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.msg,urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.largemsg,urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.systemmsg,urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.filetransfer";+g.3gpp.iari-ref="urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.ftthumb,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.fthttp,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.ftsms,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.chatbot.sa,urn%3Aurn-7%3A3gpp-application.ims.iari.rcse.im,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geopush,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geosm";+g.gsma.rcs.cpm.pager-large;+g.gsma.rcs.botversion="#=1,#=2";reg-id=0;expires=60000
Allow: NOTIFY, OPTIONS, INVITE, UPDATE, CANCEL, BYE, ACK, MESSAGE
Authorization: {digest}
Supported: path,gruu
Accept-Encoding: gzip
From: <sip:{username}@{realm}>;tag={tag}
To: <sip:{username}@{realm}>
Via: SIP/2.0/TLS 192.168.42.42:4242;branch={branch}
User-Agent: IM-client/OMA1.0 Samsung/Pixel_3-12 Samsung-RCS/6.0 3gpp-gba
"""
    print(msg)
    answer_register = req(msg)


if __name__ == "__main__":
    main()
