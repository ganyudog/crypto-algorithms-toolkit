import hashlib
import hmac
import base64
import os
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, utils
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


def _ensure_bytes(data):
    if isinstance(data, str):
        return data.encode('utf-8')
    return data


def _b64(data):
    return base64.b64encode(data).decode()


def _from_b64(s):
    return base64.b64decode(s)



class SymmetricCrypto:

    @staticmethod
    def aes_encrypt(plaintext, key=None, mode='CBC'):
        plaintext = _ensure_bytes(plaintext)
        if key is None:
            key = os.urandom(32)
        key = _ensure_bytes(key)
        if len(key) not in (16, 24, 32):
            key = hashlib.sha256(key).digest()

        iv = os.urandom(16)
        algo = algorithms.AES(key)

        mode_map = {
            'CBC': modes.CBC(iv),
            'ECB': modes.ECB(),
            'CFB': modes.CFB(iv),
            'OFB': modes.OFB(iv),
            'CTR': modes.CTR(iv),
        }
        cipher_mode = mode_map.get(mode.upper(), modes.CBC(iv))

        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()

        encryptor = Cipher(algo, cipher_mode, default_backend()).encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        return {
            'ciphertext': _b64(ciphertext),
            'key': _b64(key),
            'iv': _b64(iv) if mode.upper() != 'ECB' else None,
            'mode': mode.upper(),
            'algorithm': 'AES',
            'key_size': len(key) * 8,
        }

    @staticmethod
    def aes_decrypt(ciphertext, key, iv=None, mode='CBC'):
        ciphertext = _from_b64(ciphertext)
        key = _from_b64(key)
        if iv:
            iv = _from_b64(iv)
        else:
            iv = b'\x00' * 16

        algo = algorithms.AES(key)
        mode_map = {
            'CBC': modes.CBC(iv),
            'ECB': modes.ECB(),
            'CFB': modes.CFB(iv),
            'OFB': modes.OFB(iv),
            'CTR': modes.CTR(iv),
        }
        cipher_mode = mode_map.get(mode.upper(), modes.CBC(iv))

        decryptor = Cipher(algo, cipher_mode, default_backend()).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()

        return plaintext.decode('utf-8')

    @staticmethod
    def sm4_encrypt(plaintext, key=None, mode='ECB'):
        plaintext = _ensure_bytes(plaintext)
        if key is None:
            key = os.urandom(16)
        key = _ensure_bytes(key)
        if len(key) != 16:
            key = hashlib.sha256(key).digest()[:16]

        iv = os.urandom(16) if mode.upper() != 'ECB' else b'\x00' * 16
        algo = algorithms.SM4(key)

        if mode.upper() == 'CBC':
            cipher_mode = modes.CBC(iv)
        else:
            cipher_mode = modes.ECB()

        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()

        encryptor = Cipher(algo, cipher_mode, default_backend()).encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        return {
            'ciphertext': _b64(ciphertext),
            'key': _b64(key),
            'iv': _b64(iv) if mode.upper() != 'ECB' else None,
            'mode': mode.upper(),
            'algorithm': 'SM4',
            'key_size': 128,
        }

    @staticmethod
    def sm4_decrypt(ciphertext, key, iv=None, mode='ECB'):
        ciphertext = _from_b64(ciphertext)
        key = _from_b64(key)
        if iv:
            iv = _from_b64(iv)
        else:
            iv = b'\x00' * 16

        algo = algorithms.SM4(key)
        cipher_mode = modes.CBC(iv) if mode.upper() == 'CBC' else modes.ECB()

        decryptor = Cipher(algo, cipher_mode, default_backend()).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()

        return plaintext.decode('utf-8')

    _P32 = 0xB7E15163
    _Q32 = 0x9E3779B9

    @staticmethod
    def _rc6_key_schedule(key, rounds=20):
        key = _ensure_bytes(key)
        w = 32
        key_bytes = len(key)
        c = max(1, (key_bytes + 3) // 4)
        L = [0] * c
        for i in range(key_bytes - 1, -1, -1):
            L[i // 4] = (L[i // 4] << 8) + key[i]

        t = 2 * rounds + 4
        S = [SymmetricCrypto._P32]
        for i in range(1, t):
            S.append((S[i - 1] + SymmetricCrypto._Q32) & 0xFFFFFFFF)

        A = B = i = j = 0
        v = 3 * max(c, t)
        for _ in range(v):
            A = S[i] = (S[i] + A + B) & 0xFFFFFFFF
            A = SymmetricCrypto._rotl(A, 3)
            B = L[j] = (L[j] + A + B) & 0xFFFFFFFF
            shift_b = (A + B) & 0x1F
            B = SymmetricCrypto._rotl(B, shift_b)
            i = (i + 1) % t
            j = (j + 1) % c

        return S

    @staticmethod
    def _rotl(x, n):
        n &= 0x1F
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    @staticmethod
    def _rotr(x, n):
        n &= 0x1F
        x &= 0xFFFFFFFF
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

    @staticmethod
    def _rc6_block_encrypt(block, S, rounds):
        A = struct.unpack('<I', block[0:4])[0]
        B = struct.unpack('<I', block[4:8])[0]
        C = struct.unpack('<I', block[8:12])[0]
        D = struct.unpack('<I', block[12:16])[0]

        B = (B + S[0]) & 0xFFFFFFFF
        D = (D + S[1]) & 0xFFFFFFFF

        for i in range(1, rounds + 1):
            t_val = (B * (2 * B + 1)) & 0xFFFFFFFF
            t = SymmetricCrypto._rotl(t_val, 5)
            u_val = (D * (2 * D + 1)) & 0xFFFFFFFF
            u = SymmetricCrypto._rotl(u_val, 5)
            A = (SymmetricCrypto._rotl(A ^ t, u) + S[2 * i]) & 0xFFFFFFFF
            C = (SymmetricCrypto._rotl(C ^ u, t) + S[2 * i + 1]) & 0xFFFFFFFF
            A, B, C, D = B, C, D, A

        A = (A + S[2 * rounds + 2]) & 0xFFFFFFFF
        C = (C + S[2 * rounds + 3]) & 0xFFFFFFFF

        return struct.pack('<IIII', A, B, C, D)

    @staticmethod
    def _rc6_block_decrypt(block, S, rounds):
        A = struct.unpack('<I', block[0:4])[0]
        B = struct.unpack('<I', block[4:8])[0]
        C = struct.unpack('<I', block[8:12])[0]
        D = struct.unpack('<I', block[12:16])[0]

        C = (C - S[2 * rounds + 3]) & 0xFFFFFFFF
        A = (A - S[2 * rounds + 2]) & 0xFFFFFFFF

        for i in range(rounds, 0, -1):
            A, B, C, D = D, A, B, C
            u_val = (D * (2 * D + 1)) & 0xFFFFFFFF
            u = SymmetricCrypto._rotl(u_val, 5)
            t_val = (B * (2 * B + 1)) & 0xFFFFFFFF
            t = SymmetricCrypto._rotl(t_val, 5)
            C = SymmetricCrypto._rotr(C - S[2 * i + 1], t) & 0xFFFFFFFF
            C ^= u
            A = SymmetricCrypto._rotr(A - S[2 * i], u) & 0xFFFFFFFF
            A ^= t

        D = (D - S[1]) & 0xFFFFFFFF
        B = (B - S[0]) & 0xFFFFFFFF

        return struct.pack('<IIII', A, B, C, D)

    @staticmethod
    def rc6_encrypt(plaintext, key=None, rounds=20, mode='ECB'):
        plaintext = _ensure_bytes(plaintext)
        if key is None:
            key = os.urandom(16)
        key = _ensure_bytes(key)

        S = SymmetricCrypto._rc6_key_schedule(key, rounds)

        pad_len = 16 - len(plaintext) % 16
        padded = plaintext + bytes([pad_len] * pad_len)

        mode = mode.upper()
        iv = os.urandom(16) if mode == 'CBC' else None

        ciphertext = b''
        prev = iv
        for i in range(0, len(padded), 16):
            block = padded[i:i + 16]
            if mode == 'CBC' and prev is not None:
                block = bytes(a ^ b for a, b in zip(block, prev))
            encrypted = SymmetricCrypto._rc6_block_encrypt(block, S, rounds)
            ciphertext += encrypted
            prev = encrypted

        return {
            'ciphertext': _b64(ciphertext),
            'key': _b64(key),
            'iv': _b64(iv) if iv else None,
            'mode': mode,
            'rounds': rounds,
            'algorithm': 'RC6',
            'block_size': 128,
            'key_size': len(key) * 8,
        }

    @staticmethod
    def rc6_decrypt(ciphertext, key, iv=None, rounds=20, mode='ECB'):
        ciphertext = _from_b64(ciphertext)
        key = _from_b64(key)

        S = SymmetricCrypto._rc6_key_schedule(key, rounds)
        mode = mode.upper()

        plaintext = b''
        prev = _from_b64(iv) if iv else None
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i + 16]
            decrypted = SymmetricCrypto._rc6_block_decrypt(block, S, rounds)
            if mode == 'CBC' and prev is not None:
                decrypted = bytes(a ^ b for a, b in zip(decrypted, prev))
            plaintext += decrypted
            prev = block

        pad_len = plaintext[-1]
        plaintext = plaintext[:-pad_len]

        return plaintext.decode('utf-8')



class HashAlgorithms:
    """哈希算法: SHA1, SHA256, SHA3-256, RIPEMD160, HMAC, PBKDF2"""

    @staticmethod
    def sha1(data):
        data = _ensure_bytes(data)
        h = hashlib.sha1(data)
        return {'algorithm': 'SHA1', 'hash': h.hexdigest(), 'digest_size': 160}

    @staticmethod
    def sha256(data):
        data = _ensure_bytes(data)
        h = hashlib.sha256(data)
        return {'algorithm': 'SHA256', 'hash': h.hexdigest(), 'digest_size': 256}

    @staticmethod
    def sha3_256(data):
        data = _ensure_bytes(data)
        h = hashlib.sha3_256(data)
        return {'algorithm': 'SHA3-256', 'hash': h.hexdigest(), 'digest_size': 256}

    @staticmethod
    def ripemd160(data):
        data = _ensure_bytes(data)
        h = hashlib.new('ripemd160')
        h.update(data)
        return {'algorithm': 'RIPEMD160', 'hash': h.hexdigest(), 'digest_size': 160}

    @staticmethod
    def hmac_sha1(key, data):
        key = _ensure_bytes(key)
        data = _ensure_bytes(data)
        h = hmac.new(key, data, hashlib.sha1)
        return {'algorithm': 'HMAC-SHA1', 'hmac': h.hexdigest(), 'key': _b64(key)}

    @staticmethod
    def hmac_sha256(key, data):
        key = _ensure_bytes(key)
        data = _ensure_bytes(data)
        h = hmac.new(key, data, hashlib.sha256)
        return {'algorithm': 'HMAC-SHA256', 'hmac': h.hexdigest(), 'key': _b64(key)}

    @staticmethod
    def pbkdf2(password, salt=None, iterations=100000, key_len=32, hash_algo='sha256'):
        password = _ensure_bytes(password)
        if salt is None:
            salt = os.urandom(16)
        salt = _ensure_bytes(salt)

        algo_map = {
            'sha1': hashes.SHA1(),
            'sha256': hashes.SHA256(),
            'sha512': hashes.SHA512(),
        }
        algo = algo_map.get(hash_algo, hashes.SHA256())

        kdf = PBKDF2HMAC(
            algorithm=algo,
            length=key_len,
            salt=salt,
            iterations=iterations,
            backend=default_backend(),
        )
        derived_key = kdf.derive(password)
        return {
            'algorithm': f'PBKDF2-{hash_algo.upper()}',
            'derived_key': derived_key.hex(),
            'salt': _b64(salt),
            'iterations': iterations,
            'key_length': key_len * 8,
        }

    @staticmethod
    def pbkdf2_verify(password, salt, derived_key_hex, iterations=100000,
                       key_len=32, hash_algo='sha256'):
        salt = _from_b64(salt) if isinstance(salt, str) else salt
        result = HashAlgorithms.pbkdf2(password, salt, iterations, key_len, hash_algo)
        return result['derived_key'] == derived_key_hex



class CodecAlgorithms:
    """编解码: Base64, UTF-8"""

    @staticmethod
    def base64_encode(data):
        data = _ensure_bytes(data)
        return {
            'algorithm': 'Base64',
            'operation': 'encode',
            'original': data.decode('utf-8', errors='replace'),
            'encoded': base64.b64encode(data).decode(),
        }

    @staticmethod
    def base64_decode(encoded):
        decoded = base64.b64decode(encoded)
        return {
            'algorithm': 'Base64',
            'operation': 'decode',
            'encoded': encoded,
            'decoded': decoded.decode('utf-8', errors='replace'),
        }

    @staticmethod
    def utf8_encode(data):
        if isinstance(data, bytes):
            data = data.decode('utf-8', errors='replace')
        encoded = data.encode('utf-8')
        return {
            'algorithm': 'UTF-8',
            'operation': 'encode',
            'original': data,
            'encoded_hex': encoded.hex(),
            'byte_length': len(encoded),
        }

    @staticmethod
    def utf8_decode(hex_bytes):
        decoded = bytes.fromhex(hex_bytes).decode('utf-8', errors='replace')
        return {
            'algorithm': 'UTF-8',
            'operation': 'decode',
            'encoded_hex': hex_bytes,
            'decoded': decoded,
        }



class AsymmetricCrypto:
    """公钥密码: RSA-1024, ECC-160, ECDSA"""

    @staticmethod
    def rsa_generate_keypair(key_size=2048):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )
        public_key = private_key.public_key()

        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return {
            'private_key': priv_pem.decode(),
            'public_key': pub_pem.decode(),
            'key_size': key_size,
        }

    @staticmethod
    def rsa_encrypt(plaintext, public_key_pem):
        plaintext = _ensure_bytes(plaintext)
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem,
            backend=default_backend(),
        )
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None,
            ),
        )
        return {
            'algorithm': 'RSA-OAEP-SHA1',
            'ciphertext': _b64(ciphertext),
        }

    @staticmethod
    def rsa_decrypt(ciphertext, private_key_pem):
        ciphertext = _from_b64(ciphertext) if isinstance(ciphertext, str) else ciphertext
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode() if isinstance(private_key_pem, str) else private_key_pem,
            password=None,
            backend=default_backend(),
        )
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None,
            ),
        )
        return {
            'algorithm': 'RSA-OAEP-SHA1',
            'plaintext': plaintext.decode('utf-8', errors='replace'),
        }

    @staticmethod
    def rsa_sign(data, private_key_pem, hash_algo='sha1'):
        data = _ensure_bytes(data)
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode() if isinstance(private_key_pem, str) else private_key_pem,
            password=None,
            backend=default_backend(),
        )
        algo_map = {'sha1': hashes.SHA1(), 'sha256': hashes.SHA256()}
        algo = algo_map.get(hash_algo, hashes.SHA1())
        signature = private_key.sign(
            data,
            padding.PKCS1v15(),
            algo,
        )
        return {
            'algorithm': f'RSA-SHA1-PKCS1v15',
            'signature': _b64(signature),
        }

    @staticmethod
    def rsa_verify(data, signature, public_key_pem, hash_algo='sha1'):
        data = _ensure_bytes(data)
        signature = _from_b64(signature) if isinstance(signature, str) else signature
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem,
            backend=default_backend(),
        )
        algo_map = {'sha1': hashes.SHA1(), 'sha256': hashes.SHA256()}
        algo = algo_map.get(hash_algo, hashes.SHA1())
        try:
            public_key.verify(signature, data, padding.PKCS1v15(), algo)
            return {'verified': True}
        except InvalidSignature:
            return {'verified': False}

    @staticmethod
    def ecc_generate_keypair(curve='SECP192R1'):
        curve_map = {
            'SECP192R1': ec.SECP192R1(),
            'SECP256R1': ec.SECP256R1(),
            'SECP384R1': ec.SECP384R1(),
        }
        curve_obj = curve_map.get(curve.upper(), ec.SECP192R1())
        private_key = ec.generate_private_key(curve_obj, default_backend())
        public_key = private_key.public_key()

        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return {
            'private_key': priv_pem.decode(),
            'public_key': pub_pem.decode(),
            'curve': curve.upper(),
            'key_size': private_key.key_size,
        }

    @staticmethod
    def ecdh_compute_shared(own_private_pem, peer_public_pem):
        own_private = serialization.load_pem_private_key(
            own_private_pem.encode() if isinstance(own_private_pem, str) else own_private_pem,
            password=None,
            backend=default_backend(),
        )
        peer_public = serialization.load_pem_public_key(
            peer_public_pem.encode() if isinstance(peer_public_pem, str) else peer_public_pem,
            backend=default_backend(),
        )
        shared_key = own_private.exchange(ec.ECDH(), peer_public)
        return {
            'algorithm': 'ECDH',
            'shared_secret': shared_key.hex(),
            'shared_secret_length': len(shared_key) * 8,
        }

    @staticmethod
    def ecdsa_sign(data, private_key_pem):
        data = _ensure_bytes(data)
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode() if isinstance(private_key_pem, str) else private_key_pem,
            password=None,
            backend=default_backend(),
        )
        signature = private_key.sign(
            data,
            ec.ECDSA(hashes.SHA1()),
        )
        return {
            'algorithm': 'ECDSA-SHA1',
            'signature': _b64(signature),
        }

    @staticmethod
    def ecdsa_verify(data, signature, public_key_pem):
        data = _ensure_bytes(data)
        signature = _from_b64(signature) if isinstance(signature, str) else signature
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem,
            backend=default_backend(),
        )
        try:
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA1()))
            return {'verified': True}
        except InvalidSignature:
            return {'verified': False}



def _h_aes_encrypt(**p):
    return SymmetricCrypto.aes_encrypt(p['data'], p.get('key'), p.get('mode', 'CBC'))

def _h_aes_decrypt(**p):
    return {'plaintext': SymmetricCrypto.aes_decrypt(p['data'], p['key'], p.get('iv'), p.get('mode', 'CBC'))}

def _h_sm4_encrypt(**p):
    return SymmetricCrypto.sm4_encrypt(p['data'], p.get('key'), p.get('mode', 'ECB'))

def _h_sm4_decrypt(**p):
    return {'plaintext': SymmetricCrypto.sm4_decrypt(p['data'], p['key'], p.get('iv'), p.get('mode', 'ECB'))}

def _h_rc6_encrypt(**p):
    return SymmetricCrypto.rc6_encrypt(p['data'], p.get('key'), p.get('rounds', 20), p.get('mode', 'ECB'))

def _h_rc6_decrypt(**p):
    return {'plaintext': SymmetricCrypto.rc6_decrypt(p['data'], p['key'], p.get('iv'), p.get('rounds', 20), p.get('mode', 'ECB'))}

def _h_hash(algo_fn, **p):
    return algo_fn(p['data'])

def _h_hmac(algo_fn, **p):
    return algo_fn(p['key'], p['data'])

def _h_pbkdf2_derive(**p):
    return HashAlgorithms.pbkdf2(p['password'], p.get('salt'), p.get('iterations', 100000),
                                  p.get('key_len', 32), p.get('hash_algo', 'sha256'))

def _h_pbkdf2_verify(**p):
    return {'verified': HashAlgorithms.pbkdf2_verify(
        p['password'], p['salt'], p.get('derived_key', ''), p.get('iterations', 100000),
        p.get('key_len', 32), p.get('hash_algo', 'sha256'))}

def _h_base64_encode(**p):
    return CodecAlgorithms.base64_encode(p['data'])

def _h_base64_decode(**p):
    return CodecAlgorithms.base64_decode(p['data'])

def _h_utf8_encode(**p):
    return CodecAlgorithms.utf8_encode(p['data'])

def _h_utf8_decode(**p):
    return CodecAlgorithms.utf8_decode(p['data'])

def _h_rsa_generate(**p):
    return AsymmetricCrypto.rsa_generate_keypair(p.get('key_size', 2048))

def _h_rsa_encrypt(**p):
    return AsymmetricCrypto.rsa_encrypt(p['data'], p['public_key'])

def _h_rsa_decrypt(**p):
    return AsymmetricCrypto.rsa_decrypt(p['data'], p['private_key'])

def _h_rsa_sign(**p):
    return AsymmetricCrypto.rsa_sign(p['data'], p['private_key'], p.get('hash_algo', 'sha1'))

def _h_rsa_verify(**p):
    return AsymmetricCrypto.rsa_verify(p['data'], p['signature'], p['public_key'], p.get('hash_algo', 'sha1'))

def _h_ecc_generate(**p):
    return AsymmetricCrypto.ecc_generate_keypair(p.get('curve', 'SECP192R1'))

def _h_ecdh(**p):
    return AsymmetricCrypto.ecdh_compute_shared(p['own_private_key'], p['peer_public_key'])

def _h_ecdsa_sign(**p):
    return AsymmetricCrypto.ecdsa_sign(p['data'], p['private_key'])

def _h_ecdsa_verify(**p):
    return AsymmetricCrypto.ecdsa_verify(p['data'], p['signature'], p['public_key'])

_HANDLERS = {
    ('aes', 'encrypt'):        _h_aes_encrypt,
    ('aes', 'decrypt'):        _h_aes_decrypt,
    ('sm4', 'encrypt'):        _h_sm4_encrypt,
    ('sm4', 'decrypt'):        _h_sm4_decrypt,
    ('rc6', 'encrypt'):        _h_rc6_encrypt,
    ('rc6', 'decrypt'):        _h_rc6_decrypt,
    ('sha1', 'hash'):          lambda **p: _h_hash(HashAlgorithms.sha1, **p),
    ('sha256', 'hash'):        lambda **p: _h_hash(HashAlgorithms.sha256, **p),
    ('sha3', 'hash'):          lambda **p: _h_hash(HashAlgorithms.sha3_256, **p),
    ('ripemd160', 'hash'):     lambda **p: _h_hash(HashAlgorithms.ripemd160, **p),
    ('hmac-sha1', 'hmac'):     lambda **p: _h_hmac(HashAlgorithms.hmac_sha1, **p),
    ('hmac-sha256', 'hmac'):   lambda **p: _h_hmac(HashAlgorithms.hmac_sha256, **p),
    ('pbkdf2', 'derive'):      _h_pbkdf2_derive,
    ('pbkdf2', 'verify'):      _h_pbkdf2_verify,
    ('base64', 'encode'):      _h_base64_encode,
    ('base64', 'decode'):      _h_base64_decode,
    ('utf8', 'encode'):        _h_utf8_encode,
    ('utf8', 'decode'):        _h_utf8_decode,
    ('rsa', 'generate'):       _h_rsa_generate,
    ('rsa', 'encrypt'):        _h_rsa_encrypt,
    ('rsa', 'decrypt'):        _h_rsa_decrypt,
    ('rsa', 'sign'):           _h_rsa_sign,
    ('rsa', 'verify'):         _h_rsa_verify,
    ('ecc', 'generate'):       _h_ecc_generate,
    ('ecc', 'ecdh'):           _h_ecdh,
    ('ecdsa', 'sign'):         _h_ecdsa_sign,
    ('ecdsa', 'verify'):       _h_ecdsa_verify,
}


class CryptoAPI:
    """统一密码算法调用接口, 所有方法返回执行结果和状态码"""

    @staticmethod
    def execute(algorithm, action, **params):
        try:
            key = (algorithm.lower(), action.lower())
            handler = _HANDLERS.get(key)
            if handler is None:
                return {
                    'status': 'error',
                    'message': f'不支持的算法: {algorithm}.{action}',
                    'data': None,
                }
            data = handler(**params)
            return {
                'status': 'success',
                'message': f'{algorithm}.{action} 执行成功',
                'data': data,
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': f'{algorithm}.{action} 执行失败: {str(e)}',
                'data': None,
            }



if __name__ == '__main__':
    import sys
    sys.stdout.reconfigure(encoding='utf-8')

    print('=' * 70)
    print('网络信息安全密码算法编程 - 完整测试')
    print('=' * 70)

    api = CryptoAPI()
    test_text = 'Hello, 信息安全! This is a test message. 这是一条测试消息。'

    print('\n>>> 一、对称加密算法测试 <<<')
    for algo, mode in [('aes', 'CBC'), ('sm4', 'ECB'), ('rc6', 'ECB'), ('rc6', 'CBC')]:
        r = api.execute(algo, 'encrypt', data=test_text, mode=mode)
        print(f'\n--- {algo.upper()} 加密 ({mode}) ---')
        if r['status'] == 'success':
            d = r['data']
            print(f'  密文: {d["ciphertext"][:60]}...')
            print(f'  密钥: {d["key"][:40]}...')
            if algo == 'rc6':
                print(f'  轮数: {d.get("rounds", 20)}')

            dec_params = {'data': d['ciphertext'], 'key': d['key'], 'mode': mode}
            if d.get('iv'):
                dec_params['iv'] = d['iv']
            if algo == 'rc6':
                dec_params['rounds'] = d.get('rounds', 20)
            r2 = api.execute(algo, 'decrypt', **dec_params)
            if r2['status'] == 'success':
                print(f'  解密: {r2["data"]["plaintext"]}')
                assert r2['data']['plaintext'] == test_text
                print(f'  [OK] 加密/解密验证通过')
        else:
            print(f'  [FAIL] 失败: {r["message"]}')

    print('\n\n>>> 二、哈希/摘要算法测试 <<<')
    for algo_name in ['sha1', 'sha256', 'sha3', 'ripemd160']:
        r = api.execute(algo_name, 'hash', data=test_text)
        if r['status'] == 'success':
            d = r['data']
            print(f'  {d["algorithm"]:12s}: {d["hash"]} ({d["digest_size"]}bits)')

    for algo_name in ['hmac-sha1', 'hmac-sha256']:
        r = api.execute(algo_name, 'hmac', key='secret_key_12345', data=test_text)
        if r['status'] == 'success':
            print(f'  {r["data"]["algorithm"]:12s}: {r["data"]["hmac"]}')

    r = api.execute('pbkdf2', 'derive', password='user_password_123',
                    salt='random_salt_value', iterations=10000, key_len=32,
                    hash_algo='sha256')
    if r['status'] == 'success':
        d = r['data']
        print(f'  {d["algorithm"]:12s}: {d["derived_key"]}')
        r2 = api.execute('pbkdf2', 'verify', password='user_password_123',
                        salt=d['salt'], derived_key=d['derived_key'],
                        iterations=10000, key_len=32)
        print(f'  PBKDF2验证: {r2["data"]["verified"]}')

    print('\n\n>>> 三、编解码算法测试 <<<')
    r = api.execute('base64', 'encode', data=test_text)
    if r['status'] == 'success':
        encoded = r['data']['encoded']
        print(f'  Base64编码: {encoded[:60]}...')
        r2 = api.execute('base64', 'decode', data=encoded)
        print(f'  Base64解码: {r2["data"]["decoded"]}')

    r = api.execute('utf8', 'encode', data='你好世界Hello')
    if r['status'] == 'success':
        print(f'  UTF-8编码: {r["data"]["encoded_hex"]}')
        r2 = api.execute('utf8', 'decode', data=r['data']['encoded_hex'])
        print(f'  UTF-8解码: {r2["data"]["decoded"]}')

    print('\n\n>>> 四、公钥密码算法测试 <<<')

    r = api.execute('rsa', 'generate', key_size=2048)
    if r['status'] == 'success':
        rsa_keys = r['data']
        print(f'  RSA密钥生成: {rsa_keys["key_size"]}bits')

        r2 = api.execute('rsa', 'encrypt', data=test_text,
                        public_key=rsa_keys['public_key'])
        if r2['status'] == 'success':
            print(f'  RSA加密: {r2["data"]["ciphertext"][:60]}...')
            r3 = api.execute('rsa', 'decrypt', data=r2['data']['ciphertext'],
                            private_key=rsa_keys['private_key'])
            print(f'  RSA解密: {r3["data"]["plaintext"]}')

        r4 = api.execute('rsa', 'sign', data=test_text,
                        private_key=rsa_keys['private_key'])
        if r4['status'] == 'success':
            print(f'  RSA签名: {r4["data"]["signature"][:60]}...')
            r5 = api.execute('rsa', 'verify', data=test_text,
                            signature=r4['data']['signature'],
                            public_key=rsa_keys['public_key'])
            print(f'  RSA验签: {r5["data"]["verified"]}')

    r = api.execute('ecc', 'generate', curve='SECP192R1')
    if r['status'] == 'success':
        ecc_keys = r['data']
        print(f'\n  ECC密钥生成: {ecc_keys["curve"]} {ecc_keys["key_size"]}bits')

        alice = api.execute('ecc', 'generate', curve='SECP192R1')
        bob = api.execute('ecc', 'generate', curve='SECP192R1')
        if alice['status'] == 'success' and bob['status'] == 'success':
            shared_alice = api.execute('ecc', 'ecdh',
                                       own_private_key=alice['data']['private_key'],
                                       peer_public_key=bob['data']['public_key'])
            shared_bob = api.execute('ecc', 'ecdh',
                                     own_private_key=bob['data']['private_key'],
                                     peer_public_key=alice['data']['public_key'])
            if shared_alice['status'] == 'success' and shared_bob['status'] == 'success':
                match = shared_alice['data']['shared_secret'] == shared_bob['data']['shared_secret']
                print(f'  ECDH密钥交换: {"[OK] 一致" if match else "[FAIL] 不一致"}')

    r = api.execute('ecdsa', 'sign', data=test_text,
                    private_key=ecc_keys['private_key'])
    if r['status'] == 'success':
        print(f'\n  ECDSA签名: {r["data"]["signature"][:60]}...')
        r2 = api.execute('ecdsa', 'verify', data=test_text,
                        signature=r['data']['signature'],
                        public_key=ecc_keys['public_key'])
        print(f'  ECDSA验签: {r2["data"]["verified"]}')

    print('\n' + '=' * 70)
    print('所有测试完成!')
    print('=' * 70)
