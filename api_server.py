import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify
from crypto_algorithms import CryptoAPI

app = Flask(__name__)
api = CryptoAPI()

_VALID_MODES = {'CBC', 'ECB', 'CFB', 'OFB', 'CTR'}
_VALID_CURVES = {'SECP192R1', 'SECP256R1', 'SECP384R1'}
_VALID_HASH_ALGOS = {'sha1', 'sha256', 'sha512'}

_REQUIRED_PARAMS = {
    ('aes', 'encrypt'): ['data'],
    ('aes', 'decrypt'): ['data', 'key'],
    ('sm4', 'encrypt'): ['data'],
    ('sm4', 'decrypt'): ['data', 'key'],
    ('rc6', 'encrypt'): ['data'],
    ('rc6', 'decrypt'): ['data', 'key'],
    ('sha1', 'hash'): ['data'],
    ('sha256', 'hash'): ['data'],
    ('sha3', 'hash'): ['data'],
    ('ripemd160', 'hash'): ['data'],
    ('hmac-sha1', 'hmac'): ['key', 'data'],
    ('hmac-sha256', 'hmac'): ['key', 'data'],
    ('pbkdf2', 'derive'): ['password'],
    ('pbkdf2', 'verify'): ['password', 'salt', 'derived_key'],
    ('base64', 'encode'): ['data'],
    ('base64', 'decode'): ['data'],
    ('utf8', 'encode'): ['data'],
    ('utf8', 'decode'): ['data'],
    ('rsa', 'generate'): [],
    ('rsa', 'encrypt'): ['data', 'public_key'],
    ('rsa', 'decrypt'): ['data', 'private_key'],
    ('rsa', 'sign'): ['data', 'private_key'],
    ('rsa', 'verify'): ['data', 'signature', 'public_key'],
    ('ecc', 'generate'): [],
    ('ecc', 'ecdh'): ['own_private_key', 'peer_public_key'],
    ('ecdsa', 'sign'): ['data', 'private_key'],
    ('ecdsa', 'verify'): ['data', 'signature', 'public_key'],
}


def _validate(algorithm, action, params):
    key = (algorithm.lower(), action.lower())
    if key not in _REQUIRED_PARAMS:
        return f'不支持的接口: {algorithm}/{action}'

    for field in _REQUIRED_PARAMS[key]:
        if field not in params or params[field] == '':
            return f'缺少必填参数: {field}'

    mode = params.get('mode')
    if mode is not None and mode.upper() not in _VALID_MODES:
        return f'不支持的模式: {mode}，可选: {", ".join(sorted(_VALID_MODES))}'

    curve = params.get('curve')
    if curve is not None and curve.upper() not in _VALID_CURVES:
        return f'不支持的曲线: {curve}，可选: {", ".join(sorted(_VALID_CURVES))}'

    hash_algo = params.get('hash_algo')
    if hash_algo is not None and hash_algo.lower() not in _VALID_HASH_ALGOS:
        return f'不支持的哈希算法: {hash_algo}，可选: {", ".join(sorted(_VALID_HASH_ALGOS))}'

    for int_field in ('key_size', 'rounds', 'iterations', 'key_len'):
        val = params.get(int_field)
        if val is not None:
            try:
                val = int(val)
            except (ValueError, TypeError):
                return f'{int_field} 必须是整数'
            if int_field == 'key_size' and val < 1024:
                return 'key_size 不能小于 1024'
            if int_field in ('rounds', 'iterations') and val < 1:
                return f'{int_field} 必须大于 0'
            if int_field == 'key_len' and val < 1:
                return 'key_len 必须大于 0'

    return None


@app.route('/')
def index():
    return jsonify({
        'service': 'crypto-api',
        'version': '1.0',
        'support': {
            'symmetric': ['aes', 'sm4', 'rc6'],
            'hash': ['sha1', 'sha256', 'sha3', 'ripemd160', 'hmac-sha1', 'hmac-sha256', 'pbkdf2'],
            'codec': ['base64', 'utf8'],
            'asymmetric': ['rsa', 'ecc', 'ecdsa'],
        }
    })


@app.route('/api/health')
def health():
    return jsonify({'status': 'ok'})


@app.route('/api/algorithms')
def list_algorithms():
    return jsonify({
        'symmetric': {
            'aes': {'actions': ['encrypt', 'decrypt'], 'modes': ['CBC', 'ECB', 'CFB', 'OFB', 'CTR']},
            'sm4': {'actions': ['encrypt', 'decrypt'], 'modes': ['ECB', 'CBC']},
            'rc6': {'actions': ['encrypt', 'decrypt'], 'rounds': 'default 20'},
        },
        'hash': {
            'sha1': {'actions': ['hash']},
            'sha256': {'actions': ['hash']},
            'sha3': {'actions': ['hash']},
            'ripemd160': {'actions': ['hash']},
            'hmac-sha1': {'actions': ['hmac']},
            'hmac-sha256': {'actions': ['hmac']},
            'pbkdf2': {'actions': ['derive', 'verify']},
        },
        'codec': {
            'base64': {'actions': ['encode', 'decode']},
            'utf8': {'actions': ['encode', 'decode']},
        },
        'asymmetric': {
            'rsa': {'actions': ['generate', 'encrypt', 'decrypt', 'sign', 'verify']},
            'ecc': {'actions': ['generate', 'ecdh']},
            'ecdsa': {'actions': ['sign', 'verify']},
        }
    })


@app.route('/api/<algorithm>/<action>', methods=['POST'])
def execute(algorithm, action):
    data = request.get_json(silent=True) or {}
    err = _validate(algorithm, action, data)
    if err:
        return jsonify({'status': 'error', 'message': err, 'data': None}), 400
    result = api.execute(algorithm, action, **data)
    status_code = 200 if result['status'] == 'success' else 400
    return jsonify(result), status_code


@app.route('/api/<algorithm>/<action>', methods=['GET'])
def execute_get(algorithm, action):
    params = {}
    for key in request.args:
        value = request.args.get(key)
        if key in ('key_size', 'rounds', 'iterations', 'key_len'):
            try:
                value = int(value)
            except ValueError:
                pass
        params[key] = value
    err = _validate(algorithm, action, params)
    if err:
        return jsonify({'status': 'error', 'message': err, 'data': None}), 400
    result = api.execute(algorithm, action, **params)
    status_code = 200 if result['status'] == 'success' else 400
    return jsonify(result), status_code


if __name__ == '__main__':
    print('crypto API server starting on http://127.0.0.1:5000')
    app.run(host='127.0.0.1', port=5000, debug=True)
