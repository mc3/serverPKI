

"""
Certificate generation module.
"""

import sys
from OpenSSL import crypto
from pki.config import Pathes
from pathlib import Path

from pki.utils import sli, sln, sle, options


TYPE_RSA = crypto.TYPE_RSA
TYPE_DSA = crypto.TYPE_DSA

class Serial(object):
    __value = 0
    
    def __new__(cls, *a, **k):
        if not hasattr(cls, '_inst'):
            cls._inst = super(Serial, cls).__new__(cls, *a, **k)
        return cls._inst
    
    def next(self):
        had_error = False
        if self.__value == 0:
            try:
                fd = Path.open(Pathes.ca_serial, "r")
                self.__value = int(fd.read())
            except:
                print('%Serial number not found in db or not readable: ' + str(Pathes.ca_serial))
            fd.close()
        self.__value += 1
        try:
            fd = Path.open(Pathes.ca_serial, "w")
            fd.write(str(self.__value)+'\n')
        except IOError:
            print('?Could not update serial in db: ' + str(Pathes.ca_serial))
            sys.exit(1)
        fd.close()
        if options.debug: print('[New serial is {}]'.format(self.__value))
        return self.__value

def createKeyPair(type, bits):
    """
    Create a public/private key pair.

    Arguments: type - Key type, must be one of TYPE_RSA and TYPE_DSA
               bits - Number of bits to use in the key
    Returns:   The public/private key pair in a PKey object
    """
    pkey = crypto.PKey()
    pkey.generate_key(type, bits)
    return pkey

def createCertRequest(pkey, digest, name_dict):
    """
    Create a certificate request.

    Arguments: pkey   - The key to associate with the request
               digest - Digestion method to use for signing, default is md5
               **name - The name of the subject of the request, possible
                        arguments are:
                          C     - Country name
                          ST    - State or province name
                          L     - Locality name
                          O     - Organization name
                          OU    - Organizational unit name
                          CN    - Common name
                          emailAddress - E-mail address
    Returns:   The certificate request in an X509Req object
    """
    req = crypto.X509Req()
    subj = req.get_subject()

    for (key,value) in name_dict.items():
        setattr(subj, key, value)

    req.set_pubkey(pkey)
    req.sign(pkey, digest)
    return req

def createCertificate(req, host_type, issuerCert, issuerKey, serial, notBefore, notAfter, alt_names, digest="sha1"):
    """
    Generate a certificate given a certificate request.

    Arguments: req        - Certificate request to use
               issuerCert - The certificate of the issuer
               issuerKey  - The private key of the issuer
               serial     - Serial number for the certificate
               notBefore  - Timestamp (relative to now) when the certificate
                            starts being valid
               notAfter   - Timestamp (relative to now) when the certificate
                            stops being valid
               digest     - Digest method to use for signing, default is md5
    Returns:   The signed certificate in an X509 object
    """
    cert = crypto.X509()
    cert.set_version(2)         # X509.v3
    cert.set_serial_number(serial)
    try:
    	assert cert.get_serial_number()==serial		# something is wrong here
    except AssertionError:
    	print('?Internal inconsitency: serial is %d/%x but should be %d/%x', (
    		cert.get_serial_number(), cert.get_serial_number(), serial, serial))
    cert.gmtime_adj_notBefore(notBefore)
    cert.gmtime_adj_notAfter(notAfter)
    cert.set_issuer(issuerCert.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())
    
    subj_altnames = ''
    delim = ''
    for alt_name in alt_names:
        subj_altnames += delim + 'DNS:' + alt_name
        delim = ','
    cert.add_extensions((
        # If critical=True then gives error: error 26 at 0 depth lookup:unsupported certificate purpose
        crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=issuerCert),
        crypto.X509Extension(b'basicConstraints', True, b'CA:false', subject=issuerCert),
        crypto.X509Extension(b'keyUsage', True, b'digitalSignature,keyEncipherment' 
                                    if host_type == 'server' else b'digitalSignature'),
        crypto.X509Extension(b'extendedKeyUsage', True, b'serverAuth'
                                    if host_type  == 'server' else b'clientAuth'),
        crypto.X509Extension(b'subjectAltName', True, bytes(subj_altnames, 'ascii'))))
    try:
        cert.sign(issuerKey, digest)
    except Exception:
        print('?Wrong pass phrase')
        sys.exit(1) 
    return cert

