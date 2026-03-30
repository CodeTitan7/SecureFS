from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Generate ECC keys
def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

# Serialize public key to bytes
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Serialize private key to bytes
def serialize_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

# Load public key from bytes
def load_public_key(pem_bytes):
    return serialization.load_pem_public_key(pem_bytes)

# Load private key from bytes
def load_private_key(pem_bytes):
    return serialization.load_pem_private_key(pem_bytes, password=None)

# Derive AES key from ECC shared secret
def derive_key(private_key, peer_public_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'file-encryption'
    ).derive(shared_key)
    return derived_key

# Encrypt file
def encrypt_file(data, aes_key):
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce, ciphertext

# Decrypt file
def decrypt_file(nonce, ciphertext, aes_key):
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)