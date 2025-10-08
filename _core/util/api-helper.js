// A centralized helper for consistent error responses.
export function sendError(res, statusCode, message, details = null) {
    console.error(`API Error: ${message}`, details || '');
    return res.status(statusCode).json({
        error: {
            message: message,
            // Only include details in non-production environments for security
            details: process.env.NODE_ENV !== 'production' && details ? details.message : undefined
        }
    });
}