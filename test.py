import os
import PyKCS11
import binascii
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding

from cryptography.exceptions import InvalidSignature

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

roots = {}
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


"""
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
issuer_public_key = load_pem_public_key(pem_issuer_public_key, default_backend())
cert_to_check = x509.load_pem_x509_certificate(pem_data_to_check, default_backend())
issuer_public_key.verify(
    cert_to_check.signature,
    cert_to_check.tbs_certificate_bytes,
    # Depends on the algorithm used to create the certificate
    padding.PKCS1v15(),
    cert_to_check.signature_hash_algorithm,
)
"""