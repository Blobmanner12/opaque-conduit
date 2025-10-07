import { decryptWithPrivateKey } from './_lib/crypto.js';
import redis from './_lib/upstash.js';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  try {
    const { encryptedKey } = req.body;

    if (!encryptedKey) {
      return res.status(400).json({ error: 'Bad Request: Missing encryptedKey.' });
    }

    const symmetricKey = decryptWithPrivateKey(encryptedKey);

    if (!symmetricKey) {
      return res.status(400).json({ error: 'Bad Request: Invalid encrypted payload.' });
    }
    
    // Generate a secure, short-lived session token
    const sessionToken = crypto.randomBytes(32).toString('hex');
    
    // Store the mapping in Redis: `session:<token>` -> symmetricKey, with a 5-minute (300 sec) expiry.
    await redis.set(`session:${sessionToken}`, symmetricKey, { ex: 300 });
    
    console.log(`Successfully decrypted symmetric key and stored session for token: ...${sessionToken.slice(-6)}`);

    res.status(200).json({ sessionToken: sessionToken });

  } catch (error) {
    console.error("Exchange Error:", error);
    res.status(500).json({ error: "Internal Server Error: Could not process key exchange." });
  }
}