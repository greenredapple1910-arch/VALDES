/**
 * Cryptography Wrapper Module
 * Handles End-to-End Encryption (E2EE) logic using native window.crypto.subtle API.
 */

// --- UTILITY FUNCTIONS ---

/**
 * Converts an ArrayBuffer to a Base64 string.
 */
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  let binary = '';
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

/**
 * Converts a Base64 string back to an ArrayBuffer.
 */
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary_string = window.atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
}


// --- CORE CRYPTOGRAPHY FUNCTIONS ---

/**
 * Generates a new ECDH (P-256 curve) key pair.
 * Exports both keys as Base64 encoded strings for easy transport/storage.
 * 
 * @returns An object containing key1 (Private Key) and key2 (Public Key).
 */
export async function generateKeyPair(): Promise<{ key1: string; key2: string }> {
  try {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: "ECDH",
        namedCurve: "P-256",
      },
      true, // extractable
      ["deriveKey", "deriveBits"]
    );

    // Export keys to standard formats
    const privateKeyBuffer = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
    const publicKeyBuffer = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);

    const prvBase64 = arrayBufferToBase64(privateKeyBuffer);
    const pubBase64 = arrayBufferToBase64(publicKeyBuffer);
    const bundleJSON = JSON.stringify({ prv: prvBase64, pub: pubBase64 });
    const bundleBase64 = window.btoa(bundleJSON);

    return {
      key1: bundleBase64, // Private Auth Key
      key2: pubBase64,  // Public Identity Key
    };
  } catch (error) {
    console.error("Error generating key pair:", error);
    throw new Error("Failed to generate key pair.");
  }
}

/**
 * Imports a Base64-encoded string back into a usable CryptoKey object.
 * 
 * @param base64Key The Base64 encoded key string.
 * @param type The type of key: 'private' or 'public'.
 * @returns A Promise resolving to a CryptoKey.
 */
export async function importKey(base64Key: string, type: 'private' | 'public'): Promise<CryptoKey> {
  try {
    const keyBuffer = base64ToArrayBuffer(base64Key);
    const format = type === 'private' ? 'pkcs8' : 'spki';
    // Public keys in ECDH do not have specific usages on their own when passed to deriveKey
    const keyUsages: KeyUsage[] = type === 'private' ? ['deriveKey', 'deriveBits'] : [];
    
    return await window.crypto.subtle.importKey(
      format,
      keyBuffer,
      {
        name: "ECDH",
        namedCurve: "P-256",
      },
      true, // extractable
      keyUsages
    );
  } catch (error) {
    console.error(`Error importing ${type} key:`, error);
    throw new Error(`Invalid ${type} key format or corrupted data.`);
  }
}

/**
 * Derives a shared secret utilizing the local user's Private Key and the peer's Public Key.
 * Exports the shared secret as an AES-GCM (256-bit) CryptoKey.
 * 
 * @param privateKey The local user's Private CryptoKey.
 * @param publicKey The peer's Public CryptoKey.
 * @returns A Promise resolving to the derived AES-GCM CryptoKey.
 */
export async function deriveSharedSecret(privateKey: CryptoKey, publicKey: CryptoKey): Promise<CryptoKey> {
  try {
    return await window.crypto.subtle.deriveKey(
      {
        name: "ECDH",
        public: publicKey,
      },
      privateKey,
      {
        name: "AES-GCM",
        length: 256,
      },
      true, // allow export/extraction if ever needed, though typically not required
      ["encrypt", "decrypt"]
    );
  } catch (error) {
    console.error("Error deriving shared secret:", error);
    throw new Error("Failed to derive shared AES key.");
  }
}

/**
 * Encrypts a plaintext string using AES-GCM with the derived shared key.
 * 
 * @param text The plaintext message to encrypt.
 * @param sharedAesKey The AES-GCM shared CryptoKey.
 * @returns A Base64 string combining the 12-byte IV and the Ciphertext.
 */
export async function encryptMessage(text: string, sharedAesKey: CryptoKey): Promise<string> {
  try {
    const encoder = new TextEncoder();
    const encodedText = encoder.encode(text);
    
    // Generate a secure random 12-byte initialization vector
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    
    // Encrypt the message
    const ciphertextBuffer = await window.crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv,
      },
      sharedAesKey,
      encodedText
    );
    
    // Concatenate the IV and ciphertext into a single byte array
    const ciphertextBytes = new Uint8Array(ciphertextBuffer);
    const combinedBytes = new Uint8Array(iv.length + ciphertextBytes.length);
    combinedBytes.set(iv, 0);
    combinedBytes.set(ciphertextBytes, iv.length);
    
    // Encode the combined payload as Base64 for easy transport
    return arrayBufferToBase64(combinedBytes.buffer);
  } catch (error) {
    console.error("Error encrypting message:", error);
    throw new Error("Encryption failed.");
  }
}

/**
 * Decrypts a Base64-encoded payload (IV + Ciphertext) back into plaintext.
 * 
 * @param encryptedBase64 The Base64 string containing both the IV and the encrypted data.
 * @param sharedAesKey The AES-GCM shared CryptoKey.
 * @returns The decrypted plaintext string.
 */
export async function decryptMessage(encryptedBase64: string, sharedAesKey: CryptoKey): Promise<string> {
  try {
    const combinedBuffer = base64ToArrayBuffer(encryptedBase64);
    const combinedBytes = new Uint8Array(combinedBuffer);
    
    // Extract the 12-byte IV
    const iv = combinedBytes.slice(0, 12);
    
    // Extract the ciphertext
    const ciphertextBytes = combinedBytes.slice(12);
    
    // Decrypt the payload
    const plaintextBuffer = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv,
      },
      sharedAesKey,
      ciphertextBytes
    );
    
    const decoder = new TextDecoder();
    return decoder.decode(plaintextBuffer);
  } catch (error) {
    console.error("Error decrypting message:", error);
    // Be vague on decryption errors to prevent oracle attacks or info leaks
    throw new Error("Decryption failed. Invalid payload or key mismatch.");
  }
}

// --- E2EE INTEGRITY TEST ---
(async function runCryptoAudit() {
  console.log("=== BEGIN CRYPTO AUDIT ===");
  try {
    // 1. Key Generation
    const aliceKeys = await generateKeyPair();
    const bobKeys = await generateKeyPair();
    console.log("Alice Public Key (Base64):", aliceKeys.key2);
    console.log("Bob Public Key (Base64):", bobKeys.key2);

    // 2. Key Derivation
    const aliceBundle = JSON.parse(window.atob(aliceKeys.key1));
    const alicePrivKey = await importKey(aliceBundle.prv, 'private');
    const bobPubKey = await importKey(bobKeys.key2, 'public');
    const sharedSecretA = await deriveSharedSecret(alicePrivKey, bobPubKey);

    const bobBundle = JSON.parse(window.atob(bobKeys.key1));
    const bobPrivKey = await importKey(bobBundle.prv, 'private');
    const alicePubKey = await importKey(aliceKeys.key2, 'public');
    const sharedSecretB = await deriveSharedSecret(bobPrivKey, alicePubKey);

    // 3. Symmetry Check (Export and compare raw key material)
    const rawA = await window.crypto.subtle.exportKey("raw", sharedSecretA);
    const rawB = await window.crypto.subtle.exportKey("raw", sharedSecretB);
    const base64A = arrayBufferToBase64(rawA);
    const base64B = arrayBufferToBase64(rawB);
    
    if (base64A !== base64B) {
      throw new Error("Symmetry Check Failed: Shared secrets do not match!");
    }
    console.log("> Symmetry Check Passed!");

    // 4. Encryption Test
    const plainText = "VALDES_PROTOCOL_TEST: 🕵️‍♂️ [START] // E2EE active. DATA: 0xFA4B";
    console.log("> Original Plaintext:", plainText);
    
    const encryptedPayload = await encryptMessage(plainText, sharedSecretA);
    console.log("> Encrypted Payload (IV + Ciphertext Base64):", encryptedPayload);

    // 5. Decryption Test
    const decryptedText = await decryptMessage(encryptedPayload, sharedSecretB);
    console.log("> Decrypted Text:", decryptedText);

    // 6. Integrity Check
    if (decryptedText !== plainText) {
      throw new Error("Integrity Check Failed: Decrypted text does not match original!");
    }
    console.log("> Integrity Check Passed: E2EE Lifecycle Verified!");

  } catch (err) {
    console.error("Crypto Audit Failed:", err);
  }
  console.log("=== END CRYPTO AUDIT ===");
})();
