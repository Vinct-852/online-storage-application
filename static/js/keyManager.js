class KeyManager {
    static async generateKeyPair() {
        try {
            const keyPair = await window.crypto.subtle.generateKey(
                {
                    name: "RSA-OAEP",
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: "SHA-256",
                },
                true,
                ["encrypt", "decrypt"]
            );

            const publicKey = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
            const privateKey = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
            
            return { publicKey, privateKey, keyPair };
        } catch (error) {
            console.error("Key generation failed:", error);
            throw error;
        }
    }

    static async retrievePrivateKey(username, password) {
        try {
            const storage = await this.getSecureStorage();
            const keys = await storage.getItem(username);
            
            if (!keys || !keys.encryptedPrivateKey) {
                throw new Error("No encrypted private key found for user");
            }

            const { salt, iv, encryptedKey } = keys.encryptedPrivateKey;

            const encoder = new TextEncoder();
            const passwordKey = await window.crypto.subtle.importKey(
                "raw",
                encoder.encode(password),
                { name: "PBKDF2" },
                false,
                ["deriveBits", "deriveKey"]
            );

            const key = await window.crypto.subtle.deriveKey(
                {
                    name: "PBKDF2",
                    salt: new Uint8Array(salt),
                    iterations: 100000,
                    hash: "SHA-256"
                },
                passwordKey,
                { name: "AES-GCM", length: 256 },
                false,
                ["decrypt"]
            );

            const decryptedPrivateKey = await window.crypto.subtle.decrypt(
                { name: "AES-GCM", iv: new Uint8Array(iv) },
                key,
                new Uint8Array(encryptedKey)
            );

            return decryptedPrivateKey;
        } catch (error) {
            console.error("Failed to retrieve private key:", error);
            throw error;
        }
    }

    static async encryptPrivateKey(privateKey, password) {
        const encoder = new TextEncoder();
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const iv = window.crypto.getRandomValues(new Uint8Array(12));

        const passwordKey = await window.crypto.subtle.importKey(
            "raw",
            encoder.encode(password),
            { name: "PBKDF2" },
            false,
            ["deriveBits", "deriveKey"]
        );

        const key = await window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: 100000,
                hash: "SHA-256"
            },
            passwordKey,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt"]
        );

        const encryptedKey = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            key,
            privateKey
        );

        return {
            salt: Array.from(salt),
            iv: Array.from(iv),
            encryptedKey: Array.from(new Uint8Array(encryptedKey))
        };
    }

    static async getSecureStorage() {
        return {
            async setItem(key, value) {
                return new Promise((resolve, reject) => {
                    const request = indexedDB.open("SecureStorage", 1);
                    request.onerror = () => reject(request.error);
                    request.onsuccess = () => {
                        const db = request.result;
                        const tx = db.transaction("keys", "readwrite");
                        const store = tx.objectStore("keys");
                        store.put(value, key);
                        tx.oncomplete = () => resolve();
                    };
                    request.onupgradeneeded = (e) => {
                        const db = e.target.result;
                        db.createObjectStore("keys");
                    };
                });
            },
            async getItem(key) {
                return new Promise((resolve, reject) => {
                    const request = indexedDB.open("SecureStorage", 1);
                    request.onerror = () => reject(request.error);
                    request.onsuccess = () => {
                        const db = request.result;
                        const tx = db.transaction("keys", "readonly");
                        const store = tx.objectStore("keys");
                        const getRequest = store.get(key);
                        getRequest.onsuccess = () => resolve(getRequest.result);
                    };
                });
            }
        };
    }

    static async storeKeys(username, keys) {
        const storage = await this.getSecureStorage();
        await storage.setItem(username, keys);
    }

    static async generateAndStoreKeyPair(username, password) {
        try {
            const { publicKey, privateKey } = await this.generateKeyPair();
            const encryptedPrivateKey = await this.encryptPrivateKey(privateKey, password);
            
            // Store keys with public key in correct format
            await this.storeKeys(username, {
                publicKey: btoa(String.fromCharCode(...new Uint8Array(publicKey))),
                encryptedPrivateKey
            });

            // Return just the base64 public key
            return {
                publicKey: btoa(String.fromCharCode(...new Uint8Array(publicKey)))
            };
        } catch (error) {
            console.error("Failed to generate and store keys:", error);
            throw error;
        }
    }

    static async syncFromServer() {
        throw new Error("Server sync disabled for security");
    }

    static async encryptFile(file, publicKey) {
        try {
            const aesKey = window.crypto.getRandomValues(new Uint8Array(16));
            
            // Convert base64 public key to buffer
            const binaryDer = Uint8Array.from(atob(publicKey), c => c.charCodeAt(0));
            
            // Import the public key
            const importedKey = await window.crypto.subtle.importKey(
                "spki",
                binaryDer,
                {
                    name: "RSA-OAEP",
                    hash: "SHA-256"
                },
                true,
                ["encrypt"]
            );

            // Rest of encryption code...
        } catch (error) {
            console.error("Encryption failed:", error);
            throw error;
        }
    }
}
