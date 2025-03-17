import os
import base64
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

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

# 测试
def test_crypto():
    # 生成测试数据
    test_data = b"This is the content of a test file."
    print(f"Original data: {test_data.decode()}")
    
    # 生成密钥
    private_key, public_key = generate_keys()
    print("RSA key pair generated successfully")
    
    # 加密
    encrypted = encrypt_file(test_data, public_key)
    print(f"Encrypted data size: {len(encrypted['encrypted_file'])} bytes")
    
    # 解密
    decrypted_data = decrypt_file(encrypted['encrypted_file'], encrypted['encrypted_data'], private_key)
    
    # 验证
    if decrypted_data:
        print(f"Decrypted data: {decrypted_data.decode()}")
        print(f"Decryption successful: {test_data == decrypted_data}")
    else:
        print("Decryption failed")

if __name__ == "__main__":
    test_crypto()