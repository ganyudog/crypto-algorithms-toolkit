import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from crypto_algorithms import (
    SymmetricCrypto, HashAlgorithms, CodecAlgorithms, AsymmetricCrypto, CryptoAPI,
)


TEST_TEXT = 'Hello, 信息安全! test 测试。'
TEST_TEXT_LONG = 'A' * 1000 + '中文' + 'B' * 1000
TEST_TEXT_EMPTY = ''


class TestSymmetricCrypto:
    """对称加密: AES, SM4, RC6"""

    @pytest.mark.parametrize('mode', ['CBC', 'ECB', 'CFB', 'OFB', 'CTR'])
    def test_aes_encrypt_decrypt(self, mode):
        r = SymmetricCrypto.aes_encrypt(TEST_TEXT, mode=mode)
        plain = SymmetricCrypto.aes_decrypt(r['ciphertext'], r['key'], r.get('iv'), mode)
        assert plain == TEST_TEXT

    def test_aes_custom_key(self):
        key = b'0123456789abcdef'
        r = SymmetricCrypto.aes_encrypt(TEST_TEXT, key=key, mode='ECB')
        plain = SymmetricCrypto.aes_decrypt(r['ciphertext'], r['key'], r.get('iv'), 'ECB')
        assert plain == TEST_TEXT

    def test_aes_long_text(self):
        r = SymmetricCrypto.aes_encrypt(TEST_TEXT_LONG, mode='CBC')
        plain = SymmetricCrypto.aes_decrypt(r['ciphertext'], r['key'], r['iv'], 'CBC')
        assert plain == TEST_TEXT_LONG

    @pytest.mark.parametrize('mode', ['ECB', 'CBC'])
    def test_sm4_encrypt_decrypt(self, mode):
        r = SymmetricCrypto.sm4_encrypt(TEST_TEXT, mode=mode)
        plain = SymmetricCrypto.sm4_decrypt(r['ciphertext'], r['key'], r.get('iv'), mode)
        assert plain == TEST_TEXT

    @pytest.mark.parametrize('mode', ['ECB', 'CBC'])
    @pytest.mark.parametrize('rounds', [8, 20])
    def test_rc6_encrypt_decrypt(self, mode, rounds):
        r = SymmetricCrypto.rc6_encrypt(TEST_TEXT, rounds=rounds, mode=mode)
        assert r['rounds'] == rounds
        assert r['mode'] == mode
        if mode == 'CBC':
            assert r['iv'] is not None
        plain = SymmetricCrypto.rc6_decrypt(
            r['ciphertext'], r['key'], r.get('iv'), rounds, mode)
        assert plain == TEST_TEXT

    def test_rc6_long_text(self):
        r = SymmetricCrypto.rc6_encrypt(TEST_TEXT_LONG, rounds=20, mode='CBC')
        plain = SymmetricCrypto.rc6_decrypt(r['ciphertext'], r['key'], r['iv'], 20, 'CBC')
        assert plain == TEST_TEXT_LONG

    def test_rc6_cbc_iv_required(self):
        """CBC 模式下不同 IV 产生不同密文"""
        r1 = SymmetricCrypto.rc6_encrypt(TEST_TEXT, mode='CBC')
        r2 = SymmetricCrypto.rc6_encrypt(TEST_TEXT, mode='CBC')
        assert r1['ciphertext'] != r2['ciphertext']


class TestHashAlgorithms:
    """哈希/摘要: SHA1, SHA256, SHA3-256, RIPEMD160, HMAC, PBKDF2"""

    def test_sha1(self):
        r = HashAlgorithms.sha1(TEST_TEXT)
        assert len(r['hash']) == 40
        assert r['digest_size'] == 160

    def test_sha256(self):
        r = HashAlgorithms.sha256(TEST_TEXT)
        assert len(r['hash']) == 64
        assert r['digest_size'] == 256

    def test_sha3_256(self):
        r = HashAlgorithms.sha3_256(TEST_TEXT)
        assert len(r['hash']) == 64
        assert r['digest_size'] == 256

    def test_ripemd160(self):
        r = HashAlgorithms.ripemd160(TEST_TEXT)
        assert len(r['hash']) == 40
        assert r['digest_size'] == 160

    def test_hash_deterministic(self):
        for fn in [HashAlgorithms.sha1, HashAlgorithms.sha256, HashAlgorithms.sha3_256]:
            r1 = fn(TEST_TEXT)
            r2 = fn(TEST_TEXT)
            assert r1['hash'] == r2['hash']

    def test_hash_empty(self):
        for fn in [HashAlgorithms.sha1, HashAlgorithms.sha256, HashAlgorithms.sha3_256, HashAlgorithms.ripemd160]:
            r = fn('')
            assert r['hash']

    def test_hmac_sha1(self):
        r = HashAlgorithms.hmac_sha1('key123', TEST_TEXT)
        assert len(r['hmac']) == 40

    def test_hmac_sha256(self):
        r = HashAlgorithms.hmac_sha256('key123', TEST_TEXT)
        assert len(r['hmac']) == 64

    def test_hmac_different_key_different_result(self):
        r1 = HashAlgorithms.hmac_sha256('key1', TEST_TEXT)
        r2 = HashAlgorithms.hmac_sha256('key2', TEST_TEXT)
        assert r1['hmac'] != r2['hmac']

    def test_pbkdf2_derive_and_verify(self):
        r = HashAlgorithms.pbkdf2('password123', iterations=1000, key_len=16)
        assert len(r['derived_key']) == 32
        assert HashAlgorithms.pbkdf2_verify('password123', r['salt'], r['derived_key'], iterations=1000, key_len=16)

    def test_pbkdf2_verify_wrong_password(self):
        r = HashAlgorithms.pbkdf2('correct_password', iterations=1000, key_len=16)
        assert not HashAlgorithms.pbkdf2_verify('wrong_password', r['salt'], r['derived_key'], iterations=1000, key_len=16)

    def test_pbkdf2_different_salts(self):
        r1 = HashAlgorithms.pbkdf2('same_password')
        r2 = HashAlgorithms.pbkdf2('same_password')
        assert r1['derived_key'] != r2['derived_key']


class TestCodecAlgorithms:
    """编解码: Base64, UTF-8"""

    def test_base64_encode_decode(self):
        r = CodecAlgorithms.base64_encode(TEST_TEXT)
        r2 = CodecAlgorithms.base64_decode(r['encoded'])
        assert r2['decoded'] == TEST_TEXT

    def test_base64_empty(self):
        r = CodecAlgorithms.base64_encode('')
        assert r['encoded'] == ''
        r2 = CodecAlgorithms.base64_decode('')
        assert r2['decoded'] == ''

    def test_base64_binary(self):
        raw = bytes(range(256))
        r = CodecAlgorithms.base64_encode(raw)
        r2 = CodecAlgorithms.base64_decode(r['encoded'])
        assert r2['decoded'] == raw.decode('utf-8', errors='replace')

    def test_utf8_encode_decode(self):
        r = CodecAlgorithms.utf8_encode('你好世界Hello')
        r2 = CodecAlgorithms.utf8_decode(r['encoded_hex'])
        assert '你好世界Hello' in r2['decoded']


class TestAsymmetricCrypto:
    """公钥密码: RSA, ECC, ECDSA"""

    def test_rsa_generate_default(self):
        r = AsymmetricCrypto.rsa_generate_keypair()
        assert r['key_size'] == 2048
        assert '-----BEGIN PRIVATE KEY-----' in r['private_key']
        assert '-----BEGIN PUBLIC KEY-----' in r['public_key']

    def test_rsa_encrypt_decrypt(self):
        keys = AsymmetricCrypto.rsa_generate_keypair(2048)
        r = AsymmetricCrypto.rsa_encrypt(TEST_TEXT, keys['public_key'])
        r2 = AsymmetricCrypto.rsa_decrypt(r['ciphertext'], keys['private_key'])
        assert r2['plaintext'] == TEST_TEXT

    def test_rsa_sign_verify(self):
        keys = AsymmetricCrypto.rsa_generate_keypair(2048)
        r = AsymmetricCrypto.rsa_sign(TEST_TEXT, keys['private_key'])
        assert AsymmetricCrypto.rsa_verify(TEST_TEXT, r['signature'], keys['public_key'])['verified']

    def test_rsa_verify_tampered(self):
        keys = AsymmetricCrypto.rsa_generate_keypair(2048)
        r = AsymmetricCrypto.rsa_sign(TEST_TEXT, keys['private_key'])
        assert not AsymmetricCrypto.rsa_verify('tampered_data', r['signature'], keys['public_key'])['verified']

    def test_ecc_generate(self):
        r = AsymmetricCrypto.ecc_generate_keypair('SECP192R1')
        assert r['curve'] == 'SECP192R1'
        assert r['key_size'] == 192

    def test_ecdh_shared_secret(self):
        alice = AsymmetricCrypto.ecc_generate_keypair()
        bob = AsymmetricCrypto.ecc_generate_keypair()
        s1 = AsymmetricCrypto.ecdh_compute_shared(alice['private_key'], bob['public_key'])
        s2 = AsymmetricCrypto.ecdh_compute_shared(bob['private_key'], alice['public_key'])
        assert s1['shared_secret'] == s2['shared_secret']

    def test_ecdsa_sign_verify(self):
        keys = AsymmetricCrypto.ecc_generate_keypair()
        r = AsymmetricCrypto.ecdsa_sign(TEST_TEXT, keys['private_key'])
        assert AsymmetricCrypto.ecdsa_verify(TEST_TEXT, r['signature'], keys['public_key'])['verified']

    def test_ecdsa_verify_tampered(self):
        keys = AsymmetricCrypto.ecc_generate_keypair()
        r = AsymmetricCrypto.ecdsa_sign(TEST_TEXT, keys['private_key'])
        assert not AsymmetricCrypto.ecdsa_verify('tampered', r['signature'], keys['public_key'])['verified']


class TestCryptoAPI:
    """统一接口 + 错误处理"""

    def test_invalid_algorithm(self):
        r = CryptoAPI.execute('nonexistent', 'hash', data='test')
        assert r['status'] == 'error'
        assert '不支持' in r['message']

    def test_registry_completeness(self):
        """所有注册的 handler 都必须可调用"""
        from crypto_algorithms import _HANDLERS
        for (algo, action), handler in _HANDLERS.items():
            assert callable(handler), f'{algo}.{action} handler 不可调用'

    @pytest.mark.parametrize('algo,action,params', [
        ('aes', 'encrypt', {'data': 'hello', 'mode': 'CBC'}),
        ('sm4', 'encrypt', {'data': 'hello'}),
        ('rc6', 'encrypt', {'data': 'hello', 'mode': 'CBC', 'rounds': 20}),
        ('sha256', 'hash', {'data': 'hello'}),
        ('hmac-sha256', 'hmac', {'key': 'k', 'data': 'hello'}),
        ('base64', 'encode', {'data': 'hello'}),
        ('utf8', 'decode', {'data': 'e4bda0e5a5bd'}),
    ])
    def test_common_operations_success(self, algo, action, params):
        r = CryptoAPI.execute(algo, action, **params)
        assert r['status'] == 'success', f'{algo}.{action} failed: {r["message"]}'
