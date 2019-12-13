import os
import PyKCS11
import binascii
from cryptography import x509
from cryptography.hazmat.backends import default_backend


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
print(cert_cc.subject)
print(cert_cc.issuer)


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

path = "cc_certificates/roots/"
all_root_files = [f"{path}{n}" for n in os.listdir(path) if ".pem" in n]
path = "cc_certificates/"
all_files = [f"{path}{n}" for n in os.listdir(path) if ".pem" in n]

roots = {}
certificates = {}
for fn in all_root_files:
   cert = read_cert(fn)
   roots[cert.subject.rfc4514_string()] = cert
   certificates[cert.subject.rfc4514_string()] = cert

for fn in all_files:
   cert = read_cert(fn)
   certificates[cert.subject.rfc4514_string()] = cert

def build_issuers(chain, cert):
    chain.append(cert)

    issuer = cert.issuer.rfc4514_string()
    subject = cert.subject.rfc4514_string()

    if issuer == subject and subject in roots:
        return True

    if issuer in certificates:
        return build_issuers(chain, certificates[issuer])
    
    return False
    


chain = []
print(build_issuers(chain, cert_cc))


