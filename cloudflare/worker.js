// The target Vercel deployment URL.
// This is the stable production alias that always points to the latest live deployment.
const VERCEL_BACKEND_URL = "https://opaque-conduit.vercel.app";

// Define the CORS headers.
const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: CORS_HEADERS,
      });
    }

    const url = new URL(request.url);
    const proxyUrl = VERCEL_BACKEND_URL + url.pathname + url.search;

    const proxyRequest = new Request(proxyUrl, {
      method: request.method,
      headers: request.headers,
      body: request.body,
    });

    const backendResponse = await fetch(proxyRequest);
    const response = new Response(backendResponse.body, backendResponse);

    // --- CACHE CONTROL LOGIC ---
    // The following headers are now added to every response to ensure that
    // neither Cloudflare nor the client will ever cache the response.
    // This is critical for ensuring we always serve the latest client script.
    response.headers.set("Cache-Control", "no-cache, no-store, must-revalidate");
    response.headers.set("Pragma", "no-cache");
    response.headers.set("Expires", "0");
    // --- END CACHE CONTROL ---

    // Inject our CORS headers into the final response.
    Object.entries(CORS_HEADERS).forEach(([key, value]) => {
      response.headers.set(key, value);
    });

    return response;
  },
};