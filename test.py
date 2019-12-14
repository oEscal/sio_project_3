import os
import PyKCS11
import binascii
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import ocsp
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
import requests
import urllib.parse as urlparse

ATTR = "CITIZEN AUTHENTICATION CERTIFICATE"


lib = '/usr/local/lib/libpteidpkcs11.so'
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)
slots = pkcs11.getSlotList()
slot = slots[0]

all_attr = list(PyKCS11.CKA.keys())
all_attr = [e for e in all_attr if isinstance(e, int)]

session = pkcs11.openSession(slot)


cert_cc = x509.load_der_x509_certificate(
    bytes(session.findObjects([(PyKCS11.CKA_LABEL, ATTR)])[0].to_dict()['CKA_VALUE']),
    default_backend()
)
# print(cert_cc.subject)
# print(cert_cc.issuer)


def validate_certificate(certificate):
    dates = get_certificate_dates(certificate)

    if datetime.now().timestamp() < dates[0] or datetime.now().timestamp() > dates[1]:
        return False

    return True


def get_certificate_dates(certificate):
    dates = (certificate.not_valid_before.timestamp(),
             certificate.not_valid_after.timestamp())
    return dates


def read_cert(file_name):
   with open(file_name, 'rb') as file:
      pem_data = file.read()
   return x509.load_pem_x509_certificate(pem_data, default_backend())

path = "cc_certificates/"
all_files = [f"{path}{n}" for n in os.listdir(path) if ".pem" in n]

certificates = {}
for fn in all_files:
   cert = read_cert(fn)
   certificates[cert.subject.rfc4514_string()] = cert

def build_issuers(chain, cert):
    chain.append(cert)

    issuer = cert.issuer.rfc4514_string()
    subject = cert.subject.rfc4514_string()

    if issuer == subject and subject in certificates:
        return True

    if issuer in certificates:
        return build_issuers(chain, certificates[issuer])
    
    return False
    


chain = []
chain_completed = build_issuers(chain, cert_cc)
if chain_completed:
    for i in range(1, len(chain)):
        try:
            subject = chain[i - 1]
            issuer = chain[i]
            issuer_public_key = issuer.public_key()
            issuer_public_key.verify(
                subject.signature,
                subject.tbs_certificate_bytes,
                # Depends on the algorithm used to create the certificate
                padding.PKCS1v15(),
                subject.signature_hash_algorithm,
            )
        except InvalidSignature:
            print("Um dos certificados da cadeia não foi assinado pelo seu issuer")
            break
    
    
    
    for i in range(1, len(chain)):
        subject = chain[i - 1]
        issuer = chain[i]
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(subject, issuer, subject.signature_hash_algorithm)
        req = builder.build()
        data = req.public_bytes(serialization.Encoding.DER)
        for i in subject.extensions:
            try:     
                url = i.value._descriptions[0].access_location.value
                headers = {"Content-Type": "application/ocsp-request"}
                r = requests.post(url, data = data , headers = headers )
                ocsp_resp = ocsp.load_der_ocsp_response(r.content)
                print(ocsp_resp.response_status)
                
                if ocsp_resp.certificate_status != ocsp.OCSPCertStatus.GOOD:
                    print("RIP")
            except Exception as e:
                continue


    for cert in chain:
        # print(cert.extensions.get_extension_for_class(ExtensionOID.OCSP_NO_CHECK))
        # print(cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).__dict__)

        """
        o primeiro pode ter:
         - digital_signature
         - key_agreement
         - key_encipherment
         - content_commitment
        os outros podem ter:
         - key_cert_sign
         - crl_sign
        """

        print(hasattr(cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value, "key_agreement"))
        print(cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value)

"""
mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)
private_key = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),(PyKCS11.CKA_LABEL,'CITIZEN AUTHENTICATION KEY')])[0]
text = b'text to sign'
signature = bytes(session.sign(private_key, text, mechanism))
# print(signature)
issuer_public_key = cert_cc.public_key()
issuer_public_key.verify(
                signature,
                text,
                # Depends on the algorithm used to create the certificate
                padding.PKCS1v15(),
                hashes.SHA1(),
            )
"""