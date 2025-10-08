import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = '1h';

if (!JWT_SECRET) {
    throw new Error('FATAL: JWT_SECRET environment variable is not set.');
}

export function createSessionToken(payload) {
    // TODO: Implement token creation logic
    // return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    console.log('createSessionToken called with:', payload);
    return 'dummy-jwt-token';
}

export function verifySessionToken(token) {
    // TODO: Implement token verification logic
    // return jwt.verify(token, JWT_SECRET);
    console.log('verifySessionToken called with:', token);
    return { userId: 1, entitlements: ['game123'] }; // Dummy decoded payload
}