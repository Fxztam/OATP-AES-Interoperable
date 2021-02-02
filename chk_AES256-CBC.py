import binascii

from Cryptodome.Cipher import AES
from Cryptodome.Util import Padding

# --- 30.01.2021 ------------------------------------------------------------
# Interoperability: OracleATP - Web Crypto API (JS) - Golang - Java - Python
# Result: 01eb8015f319bda885939d265c4a38a0
# Friedhold Matz - 2021-JAN
#
# ---------------------------------------------------------------------------

key = '12345678123456781234567812345678'.encode('UTF-8')
iv  = b'1234567812345678'  # the same : .encode('UTF-8')
plaintext = "Hello, World!"
# decrypted Result :: 01eb8015f319bda885939d265c4a38a0

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

def encr(p_plaintext):
   raw = pad(p_plaintext)
   encryptor = AES.new(key, AES.MODE_CBC, iv)
   encryptdata = encryptor.encrypt(raw.encode())
   print(binascii.hexlify(bytearray(encryptdata)).decode())
   return encryptdata

def decr(p_encryptdata):
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    decryptdata = encryptor.decrypt(p_encryptdata)
    return decryptdata

if __name__ == '__main__':

    encrdata = encr(plaintext)
    decrdata = decr(encrdata)

    print(Padding.unpad(decrdata, BS).decode('UTF-8'))


