import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
from flask import make_response, send_file, jsonify
import base64
import logging
import traceback
import json

# 设置日志记录
logging.basicConfig(filename='app.log', level=logging.DEBUG,
                   format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SECRET_KEY'] = 'supersecretkey'  

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# 創建資料庫表
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            public_key TEXT NOT NULL,
            private_key TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            owner_id INTEGER NOT NULL,
            shared_users TEXT DEFAULT '',
            encryption_key TEXT NOT NULL,
            FOREIGN KEY(owner_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# 📌 生成 RSA 密钥对
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key.decode(), public_key.decode()

# 📌 定義 User 類別
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    conn.close()
    if user:
        return User(user[0], user[1])
    return None

# 📌 首頁
@app.route('/')
@login_required
def index():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # 取得用戶擁有的檔案
    c.execute('SELECT * FROM files WHERE owner_id = ?', (current_user.id,))
    owned_files = c.fetchall()
    
    # 取得共享给当前用户的文件
    c.execute('''
        SELECT f.* 
        FROM files f 
        WHERE f.shared_users LIKE ? OR f.shared_users LIKE ? OR f.shared_users LIKE ?
    ''', (f'%{current_user.id},%', f'%,{current_user.id}', f'{current_user.id}'))
    shared_files = c.fetchall()
    
    # 合并文件列表，确保没有重复
    file_dict = {file[0]: file for file in owned_files}
    for file in shared_files:
        if file[0] not in file_dict:
            file_dict[file[0]] = file
    
    files = list(file_dict.values())
    
    conn.close()
    return render_template('index.html', files=files)

# 📌 註冊（增加密码哈希 & RSA 密钥）
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])  #  存儲哈希密碼
        private_key, public_key = generate_keys()
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username, password, public_key, private_key) VALUES (?, ?, ?, ?)', 
                      (username, password, public_key, private_key))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
        except:
            flash('Username already exists!', 'danger')
        conn.close()
        return redirect(url_for('login'))
    return render_template('register.html')

# 📌 登入（驗證哈希密碼）
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):  #  驗證哈希密碼
            login_user(User(user[0], user[1]))
            return redirect(url_for('index'))
        else:
            flash('Login failed. Please check your username and password!', 'danger')
    return render_template('login.html')

# 📌 登出
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# 📌 上傳檔案（客戶端加密，服务器存储加密的 AES 密钥）
@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    try:
        # 检查请求是否包含文件
        if 'file' not in request.files:
            logging.error("No file detected in the upload request")
            flash('No file detected', 'danger')
            return redirect(url_for('index'))

        file = request.files['file']
        encrypted_data = request.form.get('encrypted_aes_key', None)

        # 检查文件是否为空
        if file.filename == '':
            logging.error("Uploaded file name is empty")
            flash('No file selected', 'danger')
            return redirect(url_for('index'))

        if not encrypted_data:
            logging.error("Missing encrypted data in the upload request")
            flash('Missing encryption key', 'danger')
            return redirect(url_for('index'))

        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # 确保 UPLOAD_FOLDER 目录存在
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])

        logging.debug(f"Uploaded file content size: {len(file.read())} bytes")
        file.seek(0)  # 重置文件指针

        file.save(file_path)  # 存储加密文件
        logging.debug(f"File saved to: {file_path}")

        # 保存加密数据的大小
        try:
            # 尝试解析加密数据
            data_json = json.loads(base64.b64decode(encrypted_data).decode())
            logging.debug(f"Encrypted data contains fields: {', '.join(data_json.keys())}")
        except Exception as e:
            logging.warning(f"Failed to parse encrypted data structure: {str(e)}")

        # 存入数据库
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('INSERT INTO files (filename, owner_id, encryption_key) VALUES (?, ?, ?)', 
                  (filename, current_user.id, encrypted_data))
        conn.commit()
        conn.close()
        logging.debug(f"File information saved to database: {filename}, user_id={current_user.id}")

        flash('File successfully encrypted and uploaded!', 'success')
        return redirect(url_for('index'))
    except Exception as e:
        logging.error(f"Error uploading file: {str(e)}\n{traceback.format_exc()}")
        flash(f'Error uploading file: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.route('/get_public_key')
@login_required
def get_public_key():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT public_key FROM users WHERE id = ?', (current_user.id,))
    user = c.fetchone()
    conn.close()

    if user:
        public_key_pem = user[0]
        try:
            public_key = RSA.import_key(public_key_pem)
            public_key_der = public_key.export_key(format="DER")
            public_key_b64 = base64.b64encode(public_key_der).decode()
            logging.debug(f"Successfully retrieved public key for user {current_user.id}")
            return {"publicKey": public_key_b64}
        except Exception as e:
            logging.error(f"Error exporting public key: {str(e)}")
            return {"error": f"Error processing public key: {str(e)}"}, 500
    else:
        logging.error(f"Public key not found for user {current_user.id}")
        return {"error": "Public key not found"}, 404

# 新增：获取私钥接口
@app.route('/get_private_key')
@login_required
def get_private_key():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT private_key FROM users WHERE id = ?', (current_user.id,))
    user = c.fetchone()
    conn.close()

    if user:
        private_key_pem = user[0]
        try:
            # 获取RSA密钥对象
            private_key = RSA.import_key(private_key_pem)
            # 将私钥转换为PKCS#8 DER格式，这是Web Crypto API支持的格式
            private_key_der = private_key.export_key(format="DER", pkcs=8)
            private_key_b64 = base64.b64encode(private_key_der).decode()
            
            logging.debug(f"Successfully retrieved private key for user {current_user.id}")
            logging.debug(f"Private key format: PKCS#8 DER, encoded length: {len(private_key_b64)}")
            
            return {"privateKey": private_key_b64}
        except Exception as e:
            logging.error(f"Error exporting private key: {str(e)}\n{traceback.format_exc()}")
            return {"error": f"Error processing private key: {str(e)}"}, 500
    else:
        logging.error(f"Private key not found for user {current_user.id}")
        return {"error": "Private key not found"}, 404

# 📌 設定共享權限（用 user_id）
@app.route('/share/<int:file_id>', methods=['POST'])
@login_required
def share_file(file_id):
    shared_username = request.form['shared_user']
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # 取得 shared_user 的 ID 和公钥
    c.execute('SELECT id, public_key FROM users WHERE username = ?', (shared_username,))
    shared_user = c.fetchone()

    if not shared_user:
        flash('User does not exist!', 'danger')
        conn.close()
        return redirect(url_for('index'))

    shared_user_id = shared_user[0]
    shared_user_public_key = shared_user[1]

    # 確保當前用戶擁有這個檔案
    c.execute('SELECT * FROM files WHERE id = ? AND owner_id = ?', (file_id, current_user.id))
    file = c.fetchone()

    if file:
        current_shared_users = file[3] if file[3] else ""
        encryption_key = file[4]
        
        # 檢查是否已經共享過
        if str(shared_user_id) in current_shared_users.split(','):
            flash('File has already been shared with this user!', 'warning')
        else:
            try:
                # 获取当前用户的私钥以解密原始AES密钥
                c.execute('SELECT private_key FROM users WHERE id = ?', (current_user.id,))
                owner_private_key = c.fetchone()[0]
                
                # 解析原始加密数据
                encrypted_data = json.loads(base64.b64decode(encryption_key).decode())
                encrypted_aes_key_base64 = encrypted_data.get('encryptedAesKey')
                iv_base64 = encrypted_data.get('iv')
                
                if not encrypted_aes_key_base64 or not iv_base64:
                    raise ValueError("Invalid encrypted data format")
                
                # 使用所有者的私钥解密AES密钥
                owner_key = RSA.import_key(owner_private_key)
                encrypted_aes_key = base64.b64decode(encrypted_aes_key_base64)
                
                # 修改：使用正确的RSA-OAEP解密方式
                from Crypto.Cipher import PKCS1_OAEP
                from Crypto.Hash import SHA256
                
                # 使用SHA-256哈希算法创建PKCS1_OAEP对象，与前端加密一致
                cipher_rsa = PKCS1_OAEP.new(owner_key, hashAlgo=SHA256)
                
                try:
                    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
                    logging.debug(f"Successfully decrypted AES key, length: {len(aes_key)} bytes")
                except Exception as e:
                    logging.error(f"Failed to decrypt AES key: {str(e)}")
                    raise ValueError(f"Unable to decrypt AES key: {str(e)}")
                
                # 使用接收方的公钥重新加密AES密钥
                recipient_key = RSA.import_key(shared_user_public_key)
                
                # 使用相同的SHA-256哈希算法创建PKCS1_OAEP对象
                cipher_rsa = PKCS1_OAEP.new(recipient_key, hashAlgo=SHA256)
                recipient_encrypted_aes_key = cipher_rsa.encrypt(aes_key)
                
                # 创建接收方的加密数据
                recipient_encrypted_data = {
                    'encryptedAesKey': base64.b64encode(recipient_encrypted_aes_key).decode(),
                    'iv': iv_base64  # IV保持不变
                }
                
                # 将接收方的加密数据存储到共享记录中
                recipient_encryption_key = base64.b64encode(json.dumps(recipient_encrypted_data).encode()).decode()
                
                # 更新共享用户列表
                new_shared_users = current_shared_users + f",{shared_user_id}" if current_shared_users else f"{shared_user_id}"
                
                # 创建共享记录表（如果不存在）
                c.execute('''
                    CREATE TABLE IF NOT EXISTS shared_file_keys (
                        file_id INTEGER,
                        user_id INTEGER,
                        encryption_key TEXT,
                        PRIMARY KEY (file_id, user_id)
                    )
                ''')
                
                # 存储接收方的加密密钥
                c.execute('INSERT OR REPLACE INTO shared_file_keys (file_id, user_id, encryption_key) VALUES (?, ?, ?)',
                         (file_id, shared_user_id, recipient_encryption_key))
                
                c.execute('UPDATE files SET shared_users = ? WHERE id = ?', (new_shared_users, file_id))
                conn.commit()
                flash('File successfully shared!', 'success')
                logging.info(f"File {file_id} successfully shared with user {shared_username}")
                
            except Exception as e:
                logging.error(f"Error sharing file: {str(e)}\n{traceback.format_exc()}")
                flash(f'File sharing failed: {str(e)}', 'danger')
                conn.rollback()
    else:
        flash('Sharing failed, you are not the file owner', 'danger')

    conn.close()
    return redirect(url_for('index'))

#  編輯檔案
@app.route('/edit/<int:file_id>')
@login_required
def edit_file(file_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT * FROM files WHERE id = ? AND owner_id = ?', (file_id, current_user.id))
    file = c.fetchone()
    conn.close()

    if file:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file[1])
        
        # 讀取原始內容並模擬修改
        try:
            with open(file_path, 'a', encoding='utf-8') as f:
                f.write("\n[Edited]")  # 在文件最後加上 "[Edited]"
            
            flash('File successfully modified and saved!', 'success')
        except Exception as e:
            flash(f'File modification failed: {str(e)}', 'danger')
    else:
        flash('You do not have permission to edit this file!', 'danger')

    return redirect(url_for('index'))

#  刪除檔案
@app.route('/delete/<int:file_id>')
@login_required
def delete_file(file_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT * FROM files WHERE id = ? AND owner_id = ?', (file_id, current_user.id))
    file = c.fetchone()

    if file:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file[1])
        if os.path.exists(file_path):
            os.remove(file_path)  # 刪除實體檔案

        c.execute('DELETE FROM files WHERE id = ?', (file_id,))
        conn.commit()
        flash('File successfully deleted!', 'success')
    else:
        flash('You do not have permission to delete this file!', 'danger')

    conn.close()
    return redirect(url_for('index'))

# 修改下载文件功能，支持共享文件的解密
@app.route('/download/<int:file_id>', methods=['GET'])
@login_required
def download_file(file_id):
    try:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        
        # 检查用户是否有权限访问此文件（所有者或共享用户）
        c.execute('SELECT * FROM files WHERE id = ?', (file_id,))
        file = c.fetchone()
        
        if not file:
            return {"error": "File does not exist"}, 404
        
        filename = file[1]
        owner_id = file[2]
        shared_users = file[3].split(',') if file[3] else []
        encryption_key = file[4]
        
        # 检查访问权限
        if current_user.id != owner_id and str(current_user.id) not in shared_users:
            logging.warning(f"User {current_user.username} attempted to access an unauthorized file {file_id}")
            return {"error": "You do not have permission to access this file"}, 403
        
        # 如果是共享用户，获取为该用户特别加密的密钥
        if current_user.id != owner_id and str(current_user.id) in shared_users:
            c.execute('SELECT encryption_key FROM shared_file_keys WHERE file_id = ? AND user_id = ?', 
                     (file_id, current_user.id))
            shared_key = c.fetchone()
            if shared_key:
                encryption_key = shared_key[0]
                logging.debug(f"Using shared user's specific encryption key")
        
        # 读取文件内容
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(file_path, 'rb') as f:
            file_data = base64.b64encode(f.read()).decode('utf-8')
        
        logging.info(f"User {current_user.username} downloaded file {filename}")
        
        # 解析加密数据结构
        try:
            encrypted_data_json = json.loads(base64.b64decode(encryption_key).decode())
            logging.debug(f"Encrypted data contains fields: {', '.join(encrypted_data_json.keys())}")
        except Exception as e:
            logging.warning(f"Failed to parse encrypted data structure: {str(e)}")
        
        return {
            "filename": filename,
            "encrypted_aes_key": encryption_key,
            "file_data": file_data
        }
    except Exception as e:
        logging.error(f"Error downloading file: {str(e)}\n{traceback.format_exc()}")
        return {"error": f"Error downloading file: {str(e)}"}, 500
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)