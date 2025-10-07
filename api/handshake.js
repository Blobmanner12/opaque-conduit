import { getPublicKey, getPublicKeyFingerprint } from './_lib/crypto.js';

export default function handler(req, res) {
  try {
    const publicKey = getPublicKey();
    const fingerprint = getPublicKeyFingerprint();

    res.status(200).json({
      publicKey: publicKey,
      fingerprint: fingerprint,
    });
  } catch (error) {
    console.error("Handshake Error:", error);
    res.status(500).json({ error: "Internal Server Error: Could not process handshake." });
  }
}