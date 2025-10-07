// The target Vercel deployment URL.
// All requests to this worker will be proxied to this backend.
const VERCEL_BACKEND_URL = "https://opaque-conduit.vercel.app";

// Define the CORS headers. These tell the client's browser that it is safe
// to make requests to this API from a different origin (i.e., from Roblox).
const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*", // Allows any origin
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS", // Specifies allowed methods
  "Access-Control-Allow-Headers": "Content-Type", // Specifies allowed headers
};

export default {
  async fetch(request, env, ctx) {
    // The browser/client will send an OPTIONS request first to check CORS policy.
    // This is called a "preflight" request. We must handle it correctly.
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204, // No Content
        headers: CORS_HEADERS,
      });
    }

    // For all other requests (GET, POST), we act as a proxy.
    const url = new URL(request.url);
    const proxyUrl = VERCEL_BACKEND_URL + url.pathname + url.search;

    // Create a new request to forward to the Vercel backend.
    // We must pass along the method, headers, and body from the original request.
    const proxyRequest = new Request(proxyUrl, {
      method: request.method,
      headers: request.headers,
      body: request.body,
    });

    // Make the actual request to the Vercel backend.
    const backendResponse = await fetch(proxyRequest);

    // Create a new, mutable response based on the backend's response.
    const response = new Response(backendResponse.body, backendResponse);

    // Inject our CORS headers into the final response that goes back to the client.
    Object.entries(CORS_HEADERS).forEach(([key, value]) => {
      response.headers.set(key, value);
    });

    return response;
  },
};