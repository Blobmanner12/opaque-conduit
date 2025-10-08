import { sendError } from '../../_core/util/api-helpers.js';
import CryptoService from '../../_core/security/crypto.js';

export default async function handler(req, res) {
    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method Not Allowed' });
    }
    
    try {
        const { publicKey, fingerprint } = CryptoService.getPublicKeyInfo();
        res.status(200).json({ publicKey, fingerprint });
    } catch (error) {
        return sendError(res, 500, 'Could not retrieve public key', error);
    }
}