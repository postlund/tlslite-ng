
from .python_rsakey import Python_RSAKey
from .python_ecdsakey import Python_ECDSAKey
from .pem import dePem, pemSniff
from .asn1parser import ASN1Parser
from .cryptomath import bytesToNumber
from ecdsa.curves import NIST256p
from ecdsa.keys import SigningKey, VerifyingKey

class Python_Key(object):

    @staticmethod
    def parsePEM(s, passwordCallback=None):
        """Parse a string containing a PEM-encoded <privateKey>."""

        if pemSniff(s, "PRIVATE KEY"):
            bytes = dePem(s, "PRIVATE KEY")
            return Python_Key._parsePKCS8(bytes)
        elif pemSniff(s, "RSA PRIVATE KEY"):
            bytes = dePem(s, "RSA PRIVATE KEY")
            return Python_Key._parseSSLeay(bytes)
        elif pemSniff(s, "EC PRIVATE KEY"):
            bytes = dePem(s, "EC PRIVATE KEY")
            return Python_Key._parseECSSLeay(bytes)
        else:
            raise SyntaxError("Not a PEM private key file")

    @staticmethod
    def _parsePKCS8(bytes):
        p = ASN1Parser(bytes)

        # first element in PrivateKeyInfo is an INTEGER
        version = p.getChild(0).value
        if bytesToNumber(version) != 0:
            raise SyntaxError("Unrecognized PKCS8 version")

        # second element in PrivateKeyInfo is a SEQUENCE of type
        # AlgorithmIdentifier
        algIdent = p.getChild(1)
        seqLen = algIdent.getChildCount()
        # first item of AlgorithmIdentifier is an OBJECT (OID)
        oid = algIdent.getChild(0)
        if list(oid.value) == [42, 134, 72, 134, 247, 13, 1, 1, 1]:
            keyType = "rsa"
        elif list(oid.value) == [42, 134, 72, 134, 247, 13, 1, 1, 10]:
            keyType = "rsa-pss"
        elif list(oid.value) == [42, 134, 72, 206, 61, 2, 1]:
            keyType = "ecdsa"
        else:
            raise SyntaxError("Unrecognized AlgorithmIdentifier: {0}"
                              .format(list(oid.value)))
        # second item of AlgorithmIdentifier are parameters (defined by
        # above algorithm)
        if keyType == "rsa":
            if seqLen != 2:
                raise SyntaxError("Missing parameters for RSA algorithm ID")
            parameters = algIdent.getChild(1)
            if parameters.value != bytearray(0):
                raise SyntaxError("RSA parameters are not NULL")
        elif keyType == "ecdsa":
            if seqLen != 2:
                raise SyntaxError("Invalid encoding of algorithm identifier")
            curveID = algIdent.getChild(1)
            if list(curveID.value) == [42, 134, 72, 206, 61, 3, 1, 7]:
                curve = NIST256p
            else:
                raise SyntaxError("Unknown curve")
        else:  # rsa-pss
            pass  # ignore parameters - don't apply restrictions

        if seqLen > 2:
            raise SyntaxError("Invalid encoding of AlgorithmIdentifier")

        #Get the privateKey
        privateKeyP = p.getChild(2)

        #Adjust for OCTET STRING encapsulation
        privateKeyP = ASN1Parser(privateKeyP.value)

        if keyType == "ecdsa":
            return Python_Key._parseECDSAPrivateKey(privateKeyP,
                                                    curve)
        else:
            return Python_Key._parseASN1PrivateKey(privateKeyP)

    @staticmethod
    def _parseSSLeay(bytes):
        privateKeyP = ASN1Parser(bytes)
        return Python_Key._parseASN1PrivateKey(privateKeyP)

    @staticmethod
    def _parseECSSLeay(bytes):
        return Python_ECDSAKey(None, SigningKey.from_der(bytes))

    @staticmethod
    def _parseECDSAPrivateKey(private, curve):
        ver = private.getChild(0)
        if ver.value != b'\x01':
            raise SyntaxError("Unexpect EC key version")
        private_key = private.getChild(1)
        public_key = private.getChild(2)
        # first two bytes are the ASN.1 custom type and the length of payload
        # while the latter two bytes are just specification of the public
        # key encoding (uncompressed)
        if list(public_key.value[:1]) != [3] or \
                list(public_key.value[2:4]) != [0, 4]:
            raise SyntaxError("Invalid or unsupported encoding of public key")
        return Python_ECDSAKey(VerifyingKey.from_string(public_key.value[4:],
                                                        curve),
                               SigningKey.from_string(private_key.value,
                                                      curve))

    @staticmethod
    def _parseASN1PrivateKey(privateKeyP):
        version = privateKeyP.getChild(0).value[0]
        if version != 0:
            raise SyntaxError("Unrecognized RSAPrivateKey version")
        n = bytesToNumber(privateKeyP.getChild(1).value)
        e = bytesToNumber(privateKeyP.getChild(2).value)
        d = bytesToNumber(privateKeyP.getChild(3).value)
        p = bytesToNumber(privateKeyP.getChild(4).value)
        q = bytesToNumber(privateKeyP.getChild(5).value)
        dP = bytesToNumber(privateKeyP.getChild(6).value)
        dQ = bytesToNumber(privateKeyP.getChild(7).value)
        qInv = bytesToNumber(privateKeyP.getChild(8).value)
        return Python_RSAKey(n, e, d, p, q, dP, dQ, qInv)

