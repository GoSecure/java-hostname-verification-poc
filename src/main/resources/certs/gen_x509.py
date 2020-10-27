from OpenSSL import crypto, SSL
from six import b

"""
This sample script was used to generate certificate with special Unicode characters
"""

def create_self_signed_cert(cn,filename,useSubjectAltName=False):

    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 1024)

    # create a self-signed cert
    cert = crypto.X509()
    cert.set_version(2)
    cert.get_subject().C = "CA"
    cert.get_subject().ST = "Montreal"
    cert.get_subject().O = "Hex Stream Inc"
    cert.get_subject().OU = "Hex Stream Inc"
    cert.get_subject().CN = cn
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)

    if(useSubjectAltName):
        sans = ', '.join('DNS:{}'.format(d) for d in [cn])
        exts = [crypto.X509Extension(b"subjectAltName", False, sans.encode("UTF-8"))]
        cert.add_extensions(exts)

    cert.sign(k, 'sha1')

    print("Generating {} and {}".format(filename,filename+".key"))

    with open(filename, "wb") as f:
       f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open(filename+".key", "wb") as f:
       f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

create_self_signed_cert("montrehac\u212A.ca","evil.cert")
