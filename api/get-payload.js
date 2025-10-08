import { getPayload } from './_lib/payloads.js';
import redis from './_lib/upstash.js';
import crypto from 'crypto';

const ALGORITHM = 'aes-256-cbc';
const IV_LENGTH = 16; // For AES, this is always 16

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  try {
    const { sessionToken, scriptId } = req.body;
    
    if (!sessionToken || !scriptId) {
      return res.status(400).json({ error: 'Bad Request: Missing sessionToken or scriptId.' });
    }

    const symmetricKey = await redis.get(`session:${sessionToken}`);

    if (!symmetricKey) {
      return res.status(401).json({ error: "Unauthorized: Invalid or expired session token." });
    }

    // TODO: Add authorization logic here.

    const payload = getPayload(scriptId) || getPayload('default_placeholder');

    if (!payload) {
         return res.status(404).json({ error: "Payload not found." });
    }
    
    // Perform AES-256-CBC Encryption
    const iv = crypto.randomBytes(IV_LENGTH);
    // The key from the client is a string of bytes; we need it as a buffer.
    const keyBuffer = Buffer.from(symmetricKey, 'binary'); 
    const cipher = crypto.createCipheriv(ALGORITHM, keyBuffer, iv);
    let encrypted = cipher.update(payload, 'utf8', 'binary');
    encrypted += cipher.final('binary');

    // Prepend the IV to the ciphertext and encode the whole thing in Base64.
    const combined = Buffer.concat([iv, Buffer.from(encrypted, 'binary')]);
    const encryptedPayloadB64 = combined.toString('base64');

    res.status(200).json({ encryptedPayload: encryptedPayloadB64 });

  } catch (error) {
    console.error("Get Payload Error:", error);
    res.status(500).json({ error: "Internal Server Error: Could not retrieve payload." });
  }
}