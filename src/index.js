// -------------------------------------------------------------------------
// CLOUDFLARE WORKER ROUTER & PROXY ENGINE
// -------------------------------------------------------------------------

addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event));
});

async function handleRequest(event) {
  const request = event.request;
  const url = new URL(request.url);
  
  // 1. CORS Preflight & Handshake
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Accept, User-Agent",
        "Access-Control-Max-Age": "86400",
      },
    });
  }

  // 2. Extract upstream destination target
  const srcUrl = url.searchParams.get("src");
  if (!srcUrl) {
    return new Response(JSON.stringify({ error: "Missing 'src' target URL" }), {
      status: 400,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
      },
    });
  }

  // 3. Cache read initialization (caches.default is Cloudflare-specific)
  const cache = typeof caches !== 'undefined' ? caches.default : null;
  const cacheKey = request.clone();
  let cachedResponse = null;
  
  if (cache) {
    try {
      cachedResponse = await cache.match(cacheKey);
    } catch (e) {
      console.warn("[Worker Cache] Match error:", e);
    }
  }

  if (cachedResponse) {
    const headers = new Headers(cachedResponse.headers);
    headers.set("Access-Control-Allow-Origin", "*");
    return new Response(cachedResponse.body, {
      status: cachedResponse.status,
      statusText: cachedResponse.statusText,
      headers,
    });
  }

  // 4. Construct Upstream request headers
  const headers = new Headers();
  
  // Forward real User-Agent from client or simulate a modern Chrome client
  let userAgent = request.headers.get("User-Agent");
  if (!userAgent) {
    userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";
  }
  headers.set("User-Agent", userAgent);

  // Forward Content-Type & Accept headers if specified
  const contentType = request.headers.get("Content-Type");
  if (contentType) {
    headers.set("Content-Type", contentType);
  }
  
  const accept = request.headers.get("Accept");
  if (accept) {
    headers.set("Accept", accept);
  }

  const fetchOptions = {
    method: request.method,
    headers: headers,
  };

  // 5. Read and forward body payload for POST requests (e.g. GraphQL calls)
  if (request.method === "POST" || request.method === "PUT") {
    fetchOptions.body = await request.text();
  }

  try {
    const upstreamResponse = await fetch(srcUrl, fetchOptions);
    
    // Build new response appending CORS headers
    const responseHeaders = new Headers(upstreamResponse.headers);
    responseHeaders.set("Access-Control-Allow-Origin", "*");
    
    const modifiedResponse = new Response(upstreamResponse.body, {
      status: upstreamResponse.status,
      statusText: upstreamResponse.statusText,
      headers: responseHeaders,
    });

    // 6. Selective Caching: ONLY cache successful HTTP 200 GET requests
    // Exclude 403 (Forbidden), 404, or any other client/server error codes
    if (cache && upstreamResponse.status === 200 && request.method === "GET") {
      try {
        event.waitUntil(cache.put(cacheKey, modifiedResponse.clone()));
      } catch (e) {
        console.warn("[Worker Cache] Put error:", e);
      }
    }

    return modifiedResponse;
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 502,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
      },
    });
  }
}
