# online-storage-application
================

A secure file storage application with user management, client-side encryption, and access control.

Core Features
-------------
1. User Management
   - Registration with unique username and password hashing (PBKDF2/SHA-256)
   - Secure login authentication
   - Password reset functionality

2. Data Encryption
   - Client-side AES-256 encryption before upload
   - Encrypted file storage (server cannot read plaintext)
   - Secure key management using local storage

3. Access Control
   - User-specific file ownership
   - File sharing with designated users
   - Role-based access enforcement

4. Security Measures
   - SQL injection prevention (parameterized queries)
   - Path traversal protection
   - Input validation/sanitization
   - Activity logging and audit trails

5. Log Auditing
   - Records all critical operations (login, file changes, sharing)
   - Non-repudiation through user-specific logs
   - Admin access to audit logs

Technologies Used
-----------------
- Python 3.10+
- Flask (Web Framework)
- SQLAlchemy (ORM)
- PostgreSQL (Database)
- cryptography (AES encryption)
- Werkzeug (Password hashing)
- pytest (Testing)
- Bandit (Security Linter)

Setup Instructions
------------------
1. Install dependencies:
   pip install -r requirements.txt

2. Configure environment variables:
   SECRET_KEY=<your_secret_key>
   DATABASE_URI=postgresql://user:password@localhost/dbname
   ENCRYPTION_KEY_DERIVATION_ITERATIONS=600000

3. Initialize database:
   python -m flask db init
   python -m flask db migrate
   python -m flask db upgrade

4. Run application:
   python -m flask run --host=0.0.0.0 --port=5000

Security Notes
-------------
- Passwords are never stored in plaintext (PBKDF2-HMAC-SHA256)
- Files encrypted client-side before upload
- All database queries use parameterized inputs
- File names sanitized using whitelist (a-zA-Z0-9-_.)
- Session management with secure cookies
- Rate limiting on authentication endpoints

License
-------
Apache License 2.0
