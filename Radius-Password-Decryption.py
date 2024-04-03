# Based on RFC2865 : https://datatracker.ietf.org/doc/html/rfc2865#section-5.2
# Get more information on my related post : https://matias-fmx.fr/posts/decrypting-radius-passwords/

from hashlib import md5
import binascii

clearPassword = "ClientPassword"
sharedSecret = bytes("RadiusPassword","utf-8")
authenticator = bytearray.fromhex("abcdef0123456789abcdef0123456789")
encryptedPwd = "EncryptedPasswordHash"

def xor(hash, line):
    return bytes([_a ^ _b for _a, _b in zip(hash, line)])

def hashFunc(chunks, result = authenticator):       # Returns MD5 hash of the shared secret + authenticator
    hash = md5(sharedSecret + result).digest()      # or the previous chunk result. Then xor the result  
    return xor(hash, chunks)                        # with the password

# Adding null bytes until it is a multiple of 16
bPassword = bytes(clearPassword,"utf-8")
nullBytesNb = 16 - (len(bPassword) % 16)
if nullBytesNb != 16:
    for _i in range(nullBytesNb): bPassword += bytes("\0","utf-8") # Adding null bytes

# We split the password in 16 bytes chunks if needed
chunks = []
if len(bPassword) > 16:
    _chPassword = bPassword
    while len(_chPassword) > 1:
        chunks.append(_chPassword[:16])
        _chPassword = _chPassword[16:]
else:
    chunks.append(bPassword)

print(f"The password was divided in {len(chunks)} chunks of 16 bytes.")

# First MD5 hash
result = hashFunc(chunks[0])

# Next MD5 hash if more than 1 chunk
if len(chunks) > 1:
    for chunk in chunks[1:]:
        result += hashFunc(chunk, result)

# Decode the result in a string value
result = binascii.hexlify(result).decode("utf-8")

# Printing results
print(f'The RADIUS encrypted password for "{clearPassword}" is : {result}')
print(f'The password matches !') if encryptedPwd == result else print(f'No match')