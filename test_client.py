import sys
import json
import urllib.request
import urllib.error

sys.stdout.reconfigure(encoding='utf-8')

BASE_URL = 'http://127.0.0.1:5000'
TEST_TEXT = 'Hello, 信息安全编程! This is a test. 密码算法测试消息。'


def call_api(algorithm, action, params=None, method='POST'):
    if action:
        url = f'{BASE_URL}/api/{algorithm}/{action}'
    else:
        url = f'{BASE_URL}/api/{algorithm}'
    try:
        if method == 'POST':
            data = json.dumps(params or {}).encode('utf-8')
            req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
        else:
            if params:
                query = '&'.join(f'{k}={v}' for k, v in params.items())
                url = f'{url}?{query}'
            req = urllib.request.Request(url)

        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode('utf-8'))
    except Exception as e:
        return {'status': 'error', 'message': str(e), 'data': None}


def test_section(title):
    print(f'\n{"=" * 60}')
    print(f'  {title}')
    print(f'{"=" * 60}')


def test_case(desc, result, expected_status='success'):
    status = result.get('status', 'error')
    ok = status == expected_status
    mark = '[OK]' if ok else '[FAIL]'
    print(f'  {mark} {desc}')
    if not ok:
        print(f'      错误: {result.get("message", "未知错误")}')
    return ok


def main():
    print('=' * 60)
    print('网络信息安全密码算法编程 - API 测试客户端')
    print('=' * 60)

    with urllib.request.urlopen(f'{BASE_URL}/api/health') as resp:
        health = json.loads(resp.read().decode('utf-8'))
    print(f'\n服务状态: {health.get("message", "未知")}')

    all_pass = True

    test_section('一、对称加密算法')

    r = call_api('aes', 'encrypt', {'data': TEST_TEXT, 'mode': 'CBC'})
    if test_case('AES/CBC 加密', r):
        d = r['data']
        r2 = call_api('aes', 'decrypt', {'data': d['ciphertext'], 'key': d['key'], 'iv': d['iv'], 'mode': 'CBC'})
        if test_case('AES/CBC 解密', r2):
            if r2['data']['plaintext'] != TEST_TEXT:
                print(f'      解密结果不匹配!')
                all_pass = False

    r = call_api('sm4', 'encrypt', {'data': TEST_TEXT})
    if test_case('SM4/ECB 加密', r):
        d = r['data']
        r2 = call_api('sm4', 'decrypt', {'data': d['ciphertext'], 'key': d['key']})
        if test_case('SM4/ECB 解密', r2):
            if r2['data']['plaintext'] != TEST_TEXT:
                print(f'      解密结果不匹配!')
                all_pass = False

    r = call_api('rc6', 'encrypt', {'data': TEST_TEXT, 'rounds': 20})
    if test_case('RC6 加密(20轮)', r):
        d = r['data']
        r2 = call_api('rc6', 'decrypt', {'data': d['ciphertext'], 'key': d['key'], 'rounds': 20})
        if test_case('RC6 解密(20轮)', r2):
            if r2['data']['plaintext'] != TEST_TEXT:
                print(f'      解密结果不匹配!')
                all_pass = False

    test_section('二、哈希/摘要算法')

    for algo in ['sha1', 'sha256', 'sha3', 'ripemd160']:
        r = call_api(algo, 'hash', {'data': TEST_TEXT})
        if test_case(f'{algo.upper()} 哈希', r):
            print(f'      {r["data"]["hash"][:48]}...')

    for algo in ['hmac-sha1', 'hmac-sha256']:
        r = call_api(algo, 'hmac', {'key': 'test_key_secret', 'data': TEST_TEXT})
        if test_case(f'{algo.upper()} HMAC', r):
            print(f'      {r["data"]["hmac"][:48]}...')

    r = call_api('pbkdf2', 'derive', {'password': 'my_password', 'iterations': 10000, 'key_len': 32, 'hash_algo': 'sha256'})
    if test_case('PBKDF2 密钥派生', r):
        d = r['data']
        r2 = call_api('pbkdf2', 'verify', {'password': 'my_password', 'salt': d['salt'], 'derived_key': d['derived_key'], 'iterations': 10000, 'key_len': 32, 'hash_algo': 'sha256'})
        test_case('PBKDF2 验证(正确密码)', r2)
        r3 = call_api('pbkdf2', 'verify', {'password': 'wrong_password', 'salt': d['salt'], 'derived_key': d['derived_key'], 'iterations': 10000, 'key_len': 32, 'hash_algo': 'sha256'})
        test_case('PBKDF2 验证(错误密码)', r3)

    test_section('三、编解码算法')

    r = call_api('base64', 'encode', {'data': TEST_TEXT})
    if test_case('Base64 编码', r):
        r2 = call_api('base64', 'decode', {'data': r['data']['encoded']})
        test_case('Base64 解码', r2)

    r = call_api('utf8', 'encode', {'data': '你好世界'})
    if test_case('UTF-8 编码', r):
        r2 = call_api('utf8', 'decode', {'data': r['data']['encoded_hex']})
        test_case('UTF-8 解码', r2)

    test_section('四、公钥密码算法')

    r = call_api('rsa', 'generate', {'key_size': 2048})
    if test_case('RSA-2048 密钥生成', r):
        keys = r['data']
        r2 = call_api('rsa', 'encrypt', {'data': TEST_TEXT, 'public_key': keys['public_key']})
        if test_case('RSA 公钥加密', r2):
            r3 = call_api('rsa', 'decrypt', {'data': r2['data']['ciphertext'], 'private_key': keys['private_key']})
            if test_case('RSA 私钥解密', r3):
                if r3['data']['plaintext'] != TEST_TEXT:
                    print(f'      解密结果不匹配!')
                    all_pass = False

        r4 = call_api('rsa', 'sign', {'data': TEST_TEXT, 'private_key': keys['private_key'], 'hash_algo': 'sha1'})
        if test_case('RSA 签名(SHA1)', r4):
            r5 = call_api('rsa', 'verify', {'data': TEST_TEXT, 'signature': r4['data']['signature'], 'public_key': keys['public_key'], 'hash_algo': 'sha1'})
            test_case('RSA 验签', r5)

    r = call_api('ecc', 'generate', {'curve': 'SECP192R1'})
    if test_case('ECC-192 密钥生成', r):
        ecc_keys = r['data']

        alice = call_api('ecc', 'generate', {'curve': 'SECP192R1'})
        bob = call_api('ecc', 'generate', {'curve': 'SECP192R1'})
        if alice['status'] == 'success' and bob['status'] == 'success':
            shared1 = call_api('ecc', 'ecdh', {'own_private_key': alice['data']['private_key'], 'peer_public_key': bob['data']['public_key']})
            shared2 = call_api('ecc', 'ecdh', {'own_private_key': bob['data']['private_key'], 'peer_public_key': alice['data']['public_key']})
            if shared1['status'] == 'success' and shared2['status'] == 'success':
                match = shared1['data']['shared_secret'] == shared2['data']['shared_secret']
                test_case('ECDH 密钥交换', {'status': 'success' if match else 'error'})

        r2 = call_api('ecdsa', 'sign', {'data': TEST_TEXT, 'private_key': ecc_keys['private_key']})
        if test_case('ECDSA 签名', r2):
            r3 = call_api('ecdsa', 'verify', {'data': TEST_TEXT, 'signature': r2['data']['signature'], 'public_key': ecc_keys['public_key']})
            test_case('ECDSA 验签', r3)

    print(f'\n{"=" * 60}')
    print('测试完成!')
    print(f'{"=" * 60}')
    return all_pass


if __name__ == '__main__':
    main()
