# Security Workflows

This document outlines the end-to-end encryption workflows for file operations.

## File Upload Workflow

1. **Client-Side Key Generation**
   ```javascript
   const aesKey = window.crypto.getRandomValues(new Uint8Array(16));
   const iv = window.crypto.getRandomValues(new Uint8Array(12));
   ```

2. **Public Key Retrieval**
   ```javascript
   const response = await fetch("/get_public_key");
   const { publicKey } = await response.json();
   ```

3. **AES Key Encryption**
   ```javascript
   const encryptedAesKey = await window.crypto.subtle.encrypt(
       { name: "RSA-OAEP" },
       importedPublicKey,
       aesKey
   );
   ```

4. **File Encryption**
   ```javascript
   const encryptedFile = await window.crypto.subtle.encrypt(
       { name: "AES-GCM", iv, tagLength: 128 },
       aesKey,
       fileData
   );
   ```

5. **Upload to Server**
   ```javascript
   const formData = new FormData();
   formData.append("file", encryptedFile);
   formData.append("encrypted_aes_key", JSON.stringify({
       encryptedAesKey: btoa(encryptedAesKey),
       iv: btoa(iv)
   }));
   await fetch("/upload", { method: "POST", body: formData });
   ```

## File Download Workflow

1. **Request Encrypted Data**
   ```javascript
   const response = await fetch(`/download/${fileId}`);
   const { encrypted_aes_key, file_data } = await response.json();
   ```

2. **Private Key Retrieval**
   ```javascript
   const privateKeyResponse = await fetch("/get_private_key");
   const { privateKey } = await privateKeyResponse.json();
   ```

3. **AES Key Decryption**
   ```javascript
   const decryptedAesKey = await window.crypto.subtle.decrypt(
       { name: "RSA-OAEP" },
       importedPrivateKey,
       encryptedAesKey
   );
   ```

4. **File Decryption**
   ```javascript
   const decryptedFile = await window.crypto.subtle.decrypt(
       { name: "AES-GCM", iv, tagLength: 128 },
       decryptedAesKey,
       encryptedFile
   );
   ```

## File Sharing Workflow

1. **Original AES Key Decryption**
   ```javascript
   // File owner decrypts the AES key
   const decryptedAesKey = await window.crypto.subtle.decrypt(
       { name: "RSA-OAEP" },
       ownerPrivateKey,
       encryptedAesKey
   );
   ```

2. **Re-encryption for Recipient**
   ```javascript
   // Encrypt AES key with recipient's public key
   const reEncryptedAesKey = await window.crypto.subtle.encrypt(
       { name: "RSA-OAEP" },
       recipientPublicKey,
       decryptedAesKey
   );
   ```

3. **Server-Side Storage**
   ```python
   # Store recipient-specific encrypted key
   c.execute('''
       INSERT INTO shared_file_keys (file_id, user_id, encryption_key)
       VALUES (?, ?, ?)
   ''', (file_id, recipient_id, encrypted_key))
   ```

## Security Notes

1. All cryptographic operations occur client-side
2. Server never sees plaintext data or decryption keys
3. Each shared user gets their own encrypted AES key
4. Uses standard algorithms:
   - RSA-OAEP for key encryption
   - AES-GCM for file encryption
   - 2048-bit RSA keys
   - 256-bit AES keys
   - 96-bit IVs for GCM

## Error Handling

1. Key retrieval failures abort operations
2. Failed decryption shows user-friendly errors
3. Network errors are caught and logged
4. Invalid file formats are rejected
5. Permission checks on all operations

## Data Flow Security

```plaintext
Client → Server: Only encrypted data
Server → Client: Only encrypted data
Client → Client: Encrypted sharing via server
Server Storage: Only encrypted data
```

All sensitive operations (encryption/decryption) happen in the user's browser using the Web Crypto API.
