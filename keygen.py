import base64
import json
import math
import os
import random
import string
import time

from Crypto.Cipher import AES
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption, load_pem_private_key, load_pem_public_key
)

origin_public_key_pem = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0+LewWdwP5+D7izKjBZ2
SZiwcbJroRayDLLuOu+LUJcjewYyRUIi3APfPwwQROEYBNFbqoNeWS3ltCmHypoD
C/kEzxFd+9DQqAl7eoJsWHZ9cZKZetICLttUTUZhYJpJXHfaVdvWu9JX4SuuDB4k
+vzrQOwC1qXydo89CF5zIcIuPniH4GXFJlWbLJztwsDZuHMd/5B56nhC3RXpIF6X
ftqHEKml3LnD+dzvuVCMKwIQGv9BHRCuifBQMOIenvve3XtPwxeH83evyIIU/4fY
kriFIXg1nBtJxMaXoHnw9Y7KfaS1NWHmBSLM5PfcN1Eh4PCgtQzL6RYY7bRjCau8
pQIDAQAB
-----END PUBLIC KEY-----"""

private_key_pem = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCyH7xJSGtG2y+t
kv1qU5ws8fEmQavV1I3LRDgTrToj7uefl6Xgzapj85eSZtuEg5ustMLYhBnPPeRv
iu+jHH70IX+95ODnBsiYdzlhNDocZHMAbqTTuEjS+4mej/1+ZUiAtN2ofKN6i/fV
bDVy7vDBXUZExHIocDLgY2poRsNC9Tu3j0m7M4GKE+g6trsHEQyi/IrHh+5UeXkS
7EjihzS0WCBcbY9CvZbU3VCkei7GU7a95MordY9RN4jrsS0kVLrIjHY/NSJWwksw
dkGYCLE0FQejamw84yJgOLmaE9PZD3iY2S1VtMnsfcsvtiB31k4AOUtHXWTBDmQZ
Y85Z1KKLAgMBAAECggEAQenbd3TMecpnQMBZdUyeSMV4+rKnfzeqBtNmOuXJ0303
CggIcoE4scb0ylC0n7tB0q2LQqrTkCxziVEs7zt+wSFaT29QSD1q4nyP56f3bwU+
xySqasxRan15Rgs7f1fEdhg3w/7nUdRUsA3cU30W6z70X0MgiVVHhmBTgmXZIL/X
ovQ0Bz7TKtZzDN+EpojgsAS2IV8Vz2Crof8q999yUbhiTmwIXcSnSN4LALmxDd+K
KmUPF+foAu3cII/ZiDlzclBHYOq3z2IDZCIT7cfgSuWVtXU14N8SGkpfVR8EHftW
6Q7MD4qjIfjjM5MHNFdQ64HF4awEre9bBlms06DgYQKBgQDd1G/MYoZSVsnCSNql
PUexOdgu2qw79L9MYlMswPq7AG5lncQ8lMzlBYHs5WmHblOMyJIZFxyHK9a2sPJP
EVgiFqLY3vrZ7J2Q1q8WwjLCVGYjmpmRn+4CZ+GY+vaqNma4FzQ8bIUEcdZjGY1+
e/GGd3WVjOQ70q73nYvCQ6/IIQKBgQDNj9D9YZkQwqEFOQ89TeJ3sl14lCih8vlI
pqq9JbVuS5MrarNHkOfVC71JrOQJHPm6xapVW70DqVMr8N0xqq69ECOElpXDs/Ks
bPwsgoo6yOImWjQtc2orrZ6fS0+g6zNoJJBsk6IN+3AAV5UqxqCsoPT4icjZXDKP
nLPq0jllKwKBgQC8+hhP/vM9PBBfgh86O81Sjtu7drDZ1vQNR4piCvjOzFxAFzow
/fbbeGip/vp61KM6wTetRkIYaWFee7nBYB471BrhNHxxoKDO3gWFFuWVJb9pv2/q
XluuEv9eixYOBZBWbfYjL7PWCIDCJeejhEVK74PtZnyc9iv2aHHCilU64QKBgArG
+4INV+UVDzQi5bWlG7aC13u26Np0zrUMZ+86xuRdef3Qvk2GP2FgGDCArAP+TOmJ
64BGKwbCHeYz3qT3+elXq0UMUBXOnW6E2EPNJEoothKksA+h+XMIy0Q2wpoBOtS+
9gN7SgfJovmhneR8PXhPiAhv0OP0fYIiCRzKoM+5AoGBAMsurWbhAwdTfyZyqLGN
CtHNHF5YgfDt7IM0vwzhXF9NEdTJfWmfRA2vpnegF3Lkouwi6aevbEti8+H/lRUL
BLvn2Be7sOyZPIeuHaLVl3wi7XpqclLxkOyw5RJzsx0lKq/1q9s/WCv44ZCvIKU1
Vak4GZ72VMlpXY791VtJC7gs
-----END PRIVATE KEY-----"""

public_key_pem = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsh+8SUhrRtsvrZL9alOc
LPHxJkGr1dSNy0Q4E606I+7nn5el4M2qY/OXkmbbhIObrLTC2IQZzz3kb4rvoxx+
9CF/veTg5wbImHc5YTQ6HGRzAG6k07hI0vuJno/9fmVIgLTdqHyjeov31Ww1cu7w
wV1GRMRyKHAy4GNqaEbDQvU7t49JuzOBihPoOra7BxEMovyKx4fuVHl5EuxI4oc0
tFggXG2PQr2W1N1QpHouxlO2veTKK3WPUTeI67EtJFS6yIx2PzUiVsJLMHZBmAix
NBUHo2psPOMiYDi5mhPT2Q94mNktVbTJ7H3LL7Ygd9ZOADlLR11kwQ5kGWPOWdSi
iwIDAQAB
-----END PUBLIC KEY-----"""


def gen_keypair():
    # 生成私钥
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    # 从私钥导出公钥
    public_key = private_key.public_key()
    # 将私钥保存到文件
    pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )
    # with open('private_key.pem', 'wb') as f:
    #     f.write(pem)
    # 将公钥保存到文件
    pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    # with open('public_key.pem', 'wb') as f:
    #     f.write(pem)


def power_conf():
    origin_public_key = load_pem_public_key(origin_public_key_pem.encode())
    origin_n = origin_public_key.public_numbers().n
    public_key = load_pem_public_key(public_key_pem.encode())
    n = public_key.public_numbers().n
    print(';SIP start')
    print('[Args]')
    print(f'EQUAL,65537,{origin_n}->65537,{n}')
    print(';SIP end')


def url_conf():
    print('[URL]')
    print(';SIP start')
    print('PREFIX,https://xiaolvpuzi.cn')
    print('PREFIX,https://pre2202.xiaolvpuzi.cn')
    print('PREFIX,http://47.102.221.152')
    print('PREFIX,http://139.196.20.59')
    print(';SIP end')


class Keygen:
    def __init__(self, expire_time, username, uuid):
        self.expire_time = expire_time
        self.username = username
        self.uuid = uuid

    def generate_license(self):
        t = time.strptime(self.expire_time, '%Y-%m-%d %H:%M:%S')
        expire_timestamp = int(time.mktime(t))
        pad = self.pad_username(self.username)
        license_str = f'{expire_timestamp}IJ@@@{pad}{self.uuid}'
        aes_key = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))
        aes_iv = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
        license_encrypted = self.encrypt_license(aes_key, aes_iv, license_str)
        print(f'激活码：{license_encrypted}')
        # ooooOOooOo0o = license_encrypted
        # oo0oo0oo = 到期时间戳，毫秒
        license_obj = {
            'ooooOOooOo0o': license_encrypted,
            'oo0oo0oo': expire_timestamp * 1000,
            'o0o0ooo0o': False,
            'oooo0o00o': '0000',
            'oooooOooOooo0oooo': 10086
        }
        self.write_file(self.username, self.uuid, ".d")
        self.write_file(self.username, json.dumps(license_obj), ".l")
        self.write_file(self.username, "OFFLINE", ".lm")
        self.write_file(self.username, str(expire_timestamp * 1000), ".oet")
        self.write_file(self.username, str(round(time.time() * 1000)), ".lst")
        self.write_file(self.username, 'y', ".to")

    @staticmethod
    def write_file(username, plaintext, filename):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(f's_{username}_x'.encode())
        aes_key_bytes = digest.finalize()
        aes_iv_bytes = os.urandom(16)
        encrypted_text_bytes = AesUtil.encrypt(aes_key_bytes, aes_iv_bytes, plaintext)
        encrypt_text_hex = encrypted_text_bytes.hex()
        aes_iv_hex = aes_iv_bytes.hex()
        obj_json = json.dumps({'oooooo': encrypt_text_hex, 'ooo': aes_iv_hex})
        b64_str = base64.b64encode(obj_json.encode()).decode()
        b64_shuffled = Base64ShuffleUtil.encode(b64_str)
        ipi_dir = os.path.join(os.path.expanduser("~"), ".ipi")
        if not os.path.exists(ipi_dir):
            os.makedirs(ipi_dir)
        filepath = os.path.join(ipi_dir, filename)
        with open(filepath, 'w') as f:
            f.write(b64_shuffled)

    @staticmethod
    def pad_username(username):
        username_len = len(username)
        padding_len = 40 - username_len
        if padding_len <= 0:
            return username
        else:
            return username + '@' * padding_len

    @staticmethod
    def encrypt_license(aes_key, aes_iv, plaintext):
        cipher_bytes = AesUtil.encrypt(aes_key.encode(), aes_iv.encode(), plaintext)
        iv_and_cipher = aes_iv.encode() + cipher_bytes
        iv_and_cipher_b64_bytes = base64.b64encode(iv_and_cipher)
        len_str = f'{len(iv_and_cipher_b64_bytes):06X}'
        encrypted_str = aes_key + len_str + iv_and_cipher_b64_bytes.decode()
        # 使用私钥进行签名
        private_key = load_pem_private_key(private_key_pem.encode(), None)
        signature = private_key.sign(
            iv_and_cipher_b64_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        signature_base64 = base64.b64encode(signature).decode()
        s = encrypted_str + signature_base64
        return s


class AesUtil:
    @staticmethod
    def encrypt(aes_key_bytes, aes_iv_bytes, plaintext):
        cipher = AES.new(aes_key_bytes, AES.MODE_CBC, aes_iv_bytes)
        x = 16 - len(plaintext) % 16
        if x > 0:
            # 填充
            plaintext = plaintext + x * chr(x)
        cipher_bytes = cipher.encrypt(plaintext.encode())
        return cipher_bytes


class Base64ShuffleUtil:
    _arr = [6, 2, 7, 1, 4, 0, 8, 3, 5]
    _arr2 = [5, 3, 1, 7, 4, 8, 0, 2, 6]

    @staticmethod
    def _shuffle_string(s, shuffle_map):
        if not s:
            return s
        chunk_size = int(math.ceil(len(s) / 10.0))
        parts = [''] * 10
        for i in range(10):
            start = i * chunk_size
            end = min(start + chunk_size, len(s))
            parts[i] = s[start:end]
        shuffled_parts = [''] * 10
        for i in range(9):
            shuffled_parts[shuffle_map[i]] = parts[i]
        shuffled_parts[9] = parts[9]
        return ''.join(shuffled_parts)

    @staticmethod
    def encode(s):
        return Base64ShuffleUtil._shuffle_string(s, Base64ShuffleUtil._arr)

    @staticmethod
    def decode(s):
        return Base64ShuffleUtil._shuffle_string(s, Base64ShuffleUtil._arr2)


def main():
    # 获取控制台输入
    print('请输入系统信息: ', end='')
    sys_info = input()
    split = sys_info.split(';')
    uuid, username = split[0], split[1]
    print('----------- power.conf 配置 -----------')
    power_conf()
    print('----------- url.conf 配置 -----------')
    url_conf()
    print()
    Keygen('2099-12-31 00:00:00', username, uuid).generate_license()
    print("激活成功，请重启ide")


if __name__ == '__main__':
    main()
