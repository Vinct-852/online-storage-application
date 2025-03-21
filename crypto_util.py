import os
import base64
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import sqlite3

# 生成RSA密钥对
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# 加密文件
def encrypt_file(file_data, public_key_pem):
    # 创建AES密钥
    aes_key = get_random_bytes(16)
    iv = get_random_bytes(12)
    
    print(f"AES key: {base64.b64encode(aes_key).decode()}")
    print(f"IV: {base64.b64encode(iv).decode()}")
    
    # 使用RSA加密AES密钥
    public_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    
    # 使用AES-GCM加密文件
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    encrypted_data, tag = cipher_aes.encrypt_and_digest(file_data)
    
    # 创建加密数据包
    combined_data = {
        'encryptedAesKey': base64.b64encode(encrypted_aes_key).decode(),
        'iv': base64.b64encode(iv).decode(),
        'tag': base64.b64encode(tag).decode() if tag else None
    }
    
    return {
        'encrypted_file': encrypted_data,
        'encrypted_data': base64.b64encode(json.dumps(combined_data).encode()).decode()
    }

# 解密文件
def decrypt_file(encrypted_file, encrypted_data, private_key_pem):
    # 解析加密数据
    combined_data = json.loads(base64.b64decode(encrypted_data).decode())
    encrypted_aes_key = base64.b64decode(combined_data['encryptedAesKey'])
    iv = base64.b64decode(combined_data['iv'])
    tag = base64.b64decode(combined_data['tag']) if combined_data.get('tag') else None
    
    # 使用RSA解密AES密钥
    private_key = RSA.import_key(private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    
    # 使用AES-GCM解密文件
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    try:
        if tag:
            decrypted_data = cipher_aes.decrypt_and_verify(encrypted_file, tag)
        else:
            decrypted_data = cipher_aes.decrypt(encrypted_file)
        return decrypted_data
    except ValueError as e:
        print(f"Decryption failed: {e}")
        return None

def get_private_key_A(user_id):
    """ 從數據庫獲取用戶的 RSA 私鑰 """
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT private_key FROM users WHERE id = ?", (user_id,))
    result = c.fetchone()
    conn.close()
    return result[0] if result else None

def get_public_key_A(user_id):
    """ 從數據庫獲取用戶的 RSA 私鑰 """
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT public_key FROM users WHERE id = ?", (user_id,))
    result = c.fetchone()
    conn.close()
    return result[0] if result else None