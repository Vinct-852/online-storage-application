# Secure File Application (SecureFileApp)

SecureFileApp is a Flask-based secure file storage and sharing system designed with a strong emphasis on data privacy and client-side encryption. Files are encrypted before they are uploaded to the server and can only be decrypted by authorized users. Even server administrators cannot access file plaintext.

---

## Features

- **User Account Management:** Registration, login (with MFA/OTP), password reset, and logout.
- **Hybrid Encryption System:** Combines RSA-OAEP (asymmetric) and AES-GCM (symmetric) encryption.
- **Client-Side Encryption:** Files are encrypted in the user's browser before upload.
- **Client-Side Decryption:** Files are decrypted locally after downloading.
- **Secure File Sharing:** Share files securely with designated users using re-encrypted AES keys.
- **Access Control:** Users can only upload, edit, delete, and share their own files. Unauthorized access is prevented.
- **Log Auditing:** Critical operations like login, logout, upload, delete, and share are logged for audit purposes.
- **SQL Injection Protection:** All database interactions use parameterized queries.
- **Filename Validation:** File uploads are secured using `secure_filename` to prevent directory traversal attacks.
- **Modern User Interface:** Responsive design with custom notifications and Font Awesome icons.

---

## Technology Stack

- **Backend:** Flask (Python)
- **Database:** SQLite
- **Encryption:**
  - RSA-OAEP (2048 bits) for encrypting AES keys
  - AES-GCM for encrypting file content
- **Frontend:**
  - Web Crypto API (for encryption and decryption)
  - HTML/CSS (responsive and modern design)
  - JavaScript (client-side encryption, decryption, and secure uploads)

---

## How It Works

### File Upload Workflow
1. The client generates a random AES key and IV.
2. The client fetches the user's RSA public key from the server.
3. The AES key is encrypted using the RSA public key (RSA-OAEP).
4. The file is encrypted locally with AES-GCM.
5. The client uploads the encrypted file and encrypted AES key to the server.
6. The server stores only the encrypted data without decrypting any content.

### File Download Workflow
1. The client requests the encrypted file and AES key.
2. The client fetches their RSA private key.
3. The AES key is decrypted locally using the private key.
4. The file content is decrypted locally using AES-GCM.
5. The user saves the plaintext file.

### File Sharing Workflow
1. The file owner decrypts the original AES key using their private key.
2. The AES key is re-encrypted using the recipient user's RSA public key.
3. The re-encrypted AES key is saved for the specific recipient.
4. The recipient can decrypt the AES key using their private key and access the shared file.

---

## Security Features

- **Password Security:** Passwords are hashed using `generate_password_hash` and verified with `check_password_hash`.
- **End-to-End Encryption:** Files are always encrypted client-side before upload.
- **Integrity and Confidentiality:** AES-GCM ensures both encryption and integrity validation.
- **Strong Key Management:** RSA keys are generated per user and securely handled.
- **Access Control:** Only file owners and explicitly shared users can access specific files.
- **SQL Injection Protection:** All SQL queries are parameterized to prevent injection attacks.
- **Filename Validation:** User-uploaded filenames are sanitized using Flask's `secure_filename`.
- **Multi-Factor Authentication:** OTP verification is implemented during login for enhanced security.
- **Log Auditing:**
  - Login, logout, upload, delete, and share operations are logged.
  - Logs are saved in `app.log`.
  - Users cannot repudiate actions once recorded.

---

## Setup and Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/SecureFileApp.git
   cd SecureFileApp
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set environment variable and run the application:
   ```bash
   export FLASK_APP=app.py
   flask run --port=8001
   ```

4. Access the application at:
   ```
   http://localhost:8001
   ```

---

## Project Requirements Compliance

| Requirement | Status |
|:---|:---|
| User Management (Register/Login/Logout/Reset Password) | ✅ |
| Data Encryption (Client-Side Encrypt/Decrypt, Server cannot read plaintext) | ✅ |
| Access Control (Own files only + Secure sharing) | ✅ |
| Log Auditing (Record critical operations, no repudiation) | ✅ |
| SQL Injection Protection | ✅ |
| Filename Validation (Prevent directory traversal) | ✅ |
| Extended Functionality (MFA/OTP) | ✅ |

---

## License

This project is for educational purposes only.


