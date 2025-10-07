const crypto = require('crypto');
const NodeRSA = require('node-rsa');

// Load keys from environment variables. The Base64 encoding is crucial.
const privateKeyB64 = process.env.SERVER_PRIVATE_KEY;
const publicKeyB64 = process.env.SERVER_PUBLIC_KEY;

if (!privateKeyB64 || !publicKeyB64) {
  throw new Error("FATAL: Server RSA key pair is not configured in environment variables.");
}

// Create a persistent key instance from the Base64 encoded private key.
const key = new NodeRSA();
key.importKey(Buffer.from(privateKeyB64, 'base64'), 'pkcs1-private-pem');

/**
 * Generates a SHA-256 fingerprint of the public key.
 * This is used by the client to verify the key's authenticity and prevent MITM attacks.
 * @returns {string} The SHA-256 hash of the public key.
 */
function getPublicKeyFingerprint() {
  const publicKey = Buffer.from(publicKeyB64, 'base64');
  return crypto.createHash('sha256').update(publicKey).digest('hex');
}

/**
 * Returns the public key in Base64 format.
 * @returns {string} The Base64 encoded public key.
 */
function getPublicKey() {
  return publicKeyB64;
}

/**
 * Decrypts a Base64 encoded string using the server's private key.
 * @param {string} encryptedDataB64 The Base64 encoded data from the client.
 * @returns {string} The decrypted data (UTF-8 string).
 */
function decryptWithPrivateKey(encryptedDataB64) {
  try {
    const encryptedBuffer = Buffer.from(encryptedDataB64, 'base64');
    const decryptedBuffer = key.decrypt(encryptedBuffer);
    return decryptedBuffer.toString('utf8');
  } catch (error) {
    // This will catch padding errors or malformed data, indicating a potential tampering attempt.
    console.error("Decryption failed:", error);
    return null;
  }
}

module.exports = {
  getPublicKey,
  getPublicKeyFingerprint,
  decryptWithPrivateKey,
};