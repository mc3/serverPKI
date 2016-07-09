

"""
Certificate storage module.
"""

from OpenSSL import crypto
from pathlib import Path
from hashlib import sha256
from os import chdir,chmod

from pki.config import Pathes
from pki.utils import options as opts

def key_name(subject, subject_type):
    return Path(str('%s_%s_key.pem' % (subject, subject_type)))

def cert_name(subject, subject_type):
    return Path(str('%s_%s_cert.pem' % (subject, subject_type)))

def cert_cacert_name(subject, subject_type):
    return Path(str('%s_%s_cert_cacert.pem' % (subject, subject_type)))

def key_cert_name(subject, subject_type):
    return Path(str('%s_%s_key_cert.pem' % (subject, subject_type)))



class MyException(Exception):
    pass

def store(subject, subject_type, cacert_text, cert, pkey, theCertificate):
    """
    Store cert, private key and descendants on disk for later distribution.
    
    @param subject:     subject of cerificate
    @type subject:      string
    @param subject_type:type of subject ('server' or 'client')
    @type subject_type: string
    @param cacert_text: our CA certificate in text form
    @type cacert_text:  string
    @param cert:        certificate to store on disk
    @type cert:         crypto.X509
    @param pkey:        corresponding private key
    @type pkey:         crypto.PKey
    @rtype: 
    @exceptions:
    exceptions.SerializationError,
    """
    
    key_text = crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)
    cert_text = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    
    # test, if hash has only to be done with server cert, no ca_cert.
    ##tlsa_hash = hashlib.sha256(crypto.dump_certificate(crypto.FILETYPE_ASN1, cert) +
    ##
    
    tlsa_hash = sha256(crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)).hexdigest()
    
    cert_plus_cacert_text = cert_text + cacert_text
    key_plus_cert_text = key_text + cert_text
    
    make_cert_dir(subject)
    
    chdir(str(Pathes.work / subject))
    
    (key_name(subject, subject_type)).open(mode = 'wb').write(key_text)
    chmod(str(key_name(subject, subject_type)),0o600)

    (cert_name(subject, subject_type)).open(mode = 'wb').write(cert_text)
    (cert_cacert_name(subject, subject_type)).open(mode = 'wb').write(cert_plus_cacert_text)

    (key_cert_name(subject, subject_type)).open(mode = 'wb').write(key_plus_cert_text)
    chmod(str(key_cert_name(subject, subject_type)),0o600)
    
    chdir(str(Pathes.work))
    
    store_TLSAs(subject, tlsa_hash, theCertificate)

    chdir(str(Pathes.work))


def fqdnsFromTLSA(theCertificate):
    """
    Return list of FQDNs for which TLSA RR are needed.
    
    @param theCertificate:     Cerificate instance
    @type subject:             Cerificate
    @rtype:             list of strings
    @exceptions:        None
    """
    fqdns = []
        
    if len(theCertificate.tlsaprefixes) > 0:
        fqdns = [theCertificate.name] + theCertificate.altnames
    if opts.debug: print('[fqdnsFromTLSA: fqdns: {}]'.format(fqdns))
    return fqdns

def store_TLSAs(subject, tlsa_hash, theCertificate):
    """
    Store TLSA RR on disk for later distribution.
    
    @param subject:     subject of cerificate
    @type subject:      string
    @param tlsa_hash:   hexdigest of sha256 hash of DER presentation of cert
    @type subject:      string
    @rtype: 
    @exceptions:
    """
    ## ***TBD*** Needing 2 hashes during rollover
    
    for fqdn in fqdnsFromTLSA(theCertificate):
        rr = ''             # Resource Record
        for prefix in theCertificate.tlsaprefixes:
            rr += str(prefix.format(fqdn) + tlsa_hash + '\n')
        filename = Path(fqdn + '.tlsa')
        fqdn_tags = subject.split(sep='.')
        dirname = '.'.join(fqdn_tags[-2::]) # collect hosts in domain dir
        subdir = Pathes.work_tlsa / dirname
        if not subdir.exists() or not subdir.is_dir():
            clean_cert_dir(subdir)
        chdir(str(subdir))
        if opts.debug: print('[Writing \n\r{}into {}]'.format(rr, str(subdir / filename)))
        filename.open(mode = 'w').write(rr)

def TLSA_pathes(theCertificate):
    """
    Retrieve pathes of TLSA RRs.
    
    @param theCertificate:     cerificate
    @type theCertificate:      Certificate
    @rtype:                    List of file pathes (may be empty)
    @exceptions:
    """
    retval = []
    
    for fqdn in theCertificate.tlsaprefixes:
        filename = Path(fqdn + '.tlsa')
        fqdn_tags = subject.split(sep='.')
        dirname = '.'.join(fqdn_tags[-2::])
        subdir = Pathes.work_tlsa / dirname
        if not (subdir.exists() and subdir.is_dir()):
            raise MyException('?Missing TLSA RR for {}. Create it first.'.format(subject))
        retval.append(subdir / filename)
    return retval
    
def make_cert_dir(subject):
    """
    Create directory for certificate storage.
    
    @param subject:     subject of cerificate
    @type subject:      string
    @rtype: 
    @exceptions:
    """
    subdir = Pathes.work / subject
    if subdir.exists() and subdir.is_dir():
        return
    if opts.verbose: print('[Creating directory {}]'.format(subdir))
    subdir.mkdir(mode = 0o700)

def clean_cert_dir(dir):
    """
    Remove and create directory for certificate storage.
    
    @param dir:     directory to remove/create
    @type dir:      pathlib.Path instance
    @rtype: 
    @exceptions:
    """
    if dir.exists():
        if dir.is_dir():
            print('[Removing directory {}]'.format(dir))
            for x in dir.iterdir():
                x.unlink()
            dir.rmdir()
        else:
            dir.unlink()
    if opts.verbose: print('[Creating directory {}]'.format(dir))
    dir.mkdir(mode = 0o700, parents=True)


def cert_and_key_pathes(subject, subject_type, place, what):
    """
    Retrieve pathes of certificate and key files.
    
    @param subject:     subject of cerificate
    @type subject:      string
    @param subject_type:type of subject ('server' or 'client')
    @type subject_type: string
    @rtype:             Tuple of file pathes
    @exceptions:
    """
    retval = []
    subdir = Pathes.work / subject
    if not (subdir.exists() and subdir.is_dir()):
        raise MyException('?Missing certificate or key for {}. Create it first.'.format(subject))
    if 'combined_cert_key' in place and place['combined_cert_key']:
        retval.append(key_cert_name(subject, subject_type))
    else:
        if 'k' in what: retval.append(key_name(subject, subject_type))
        if 'combined_cert_cacert' in place and place['combined_cert_cacert']:
            retval.append(cert_cacert_name(subject, subject_type))
        else:
            if 'c' in what: retval.append(cert_name(subject, subject_type))
    return retval