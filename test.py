import PyKCS11
import binascii
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.backends import default_backend


lib = '/usr/local/lib/libpteidpkcs11.so'
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)
slots = pkcs11.getSlotList()

ATTR = "CITIZEN AUTHENTICATION CERTIFICATE"

for slot in slots:
    #print(pkcs11.getTokenInfo(slot))

    all_attr = list(PyKCS11.CKA.keys())
    all_attr = [e for e in all_attr if isinstance(e, int)]

    session = pkcs11.openSession(slot)
    cert = load_der_x509_certificate(
        bytes(session.findObjects([(PyKCS11.CKA_LABEL, ATTR)])[0].to_dict()['CKA_VALUE']),
        default_backend()
    )
    print(cert.subject)
    print(cert.issuer)

    #for obj in session.findObjects():
    #    attr = session.getAttributeValue(obj, all_attr)
    #    attr = dict(zip(map(PyKCS11.CKA.get, all_attr), attr))
#
    #    if attr['CKA_LABEL'] == ATTR.encode():
    #        print('Label:', attr['CKA_LABEL'])
    #        try:
    #            # print(bytes(attr['CKA_VALUE']))
    #            cert = load_der_x509_certificate(bytes(attr['CKA_VALUE']), default_backend())
    #            print(cert.subject)
    #            print(cert.issuer)
    #        except:
    #            pass
    #        
            # print(attr['CKA_CERTIFICATE_TYPE'])


