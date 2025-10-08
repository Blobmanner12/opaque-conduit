import { sendError } from '../../_core/util/api-helpers.js';
// Placeholder for the crypto service, internal or external
import CryptoService from '../../_core/security/crypto.js';

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method Not Allowed' });
    }

    try {
        const { plaintext } = req.body;
        if (!plaintext) {
            return sendError(res, 400, 'Missing required field: plaintext');
        }

        const ciphertext = await CryptoService.encryptWithPublicKey(plaintext);
        res.status(200).json({ ciphertext });

    } catch (error) {
        return sendError(res, 500, 'RSA encryption failed', error);
    }
}