export default {
    async fetch(request, env, ctx) {
        // 1. Handle CORS Preflight (OPTIONS)
        if (request.method === "OPTIONS") {
            return new Response(null, {
                status: 204,
                headers: {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                    "Access-Control-Max-Age": "86400",
                },
            });
        }

        const url = new URL(request.url);

        // 2. Extract target destination from target parameter (e.g., ?src=https://...)
        const targetUrlStr = url.searchParams.get("src") || url.searchParams.get("url");

        if (!targetUrlStr) {
            return new Response("Invalid request context", { status: 400 });
        }

        let targetUrl;
        try {
            targetUrl = new URL(targetUrlStr);
        } catch (e) {
            return new Response("Invalid target URL", { status: 400 });
        }

        // 3. Setup Cache Engine Key
        const cacheKey = new Request(url.toString(), request);
        const cache = caches.default;

        // Check if item exists in 30-day edge cache
        let response = await cache.match(cacheKey);

        if (response) {
            // CACHE HIT: Re-save asynchronously to RESET the 30-day (2,592,000s) TTL timer
            const clonedResponse = response.clone();
            ctx.waitUntil(
                (async () => {
                    const newHeaders = new Headers(clonedResponse.headers);
                    newHeaders.set("Cache-Control", "public, max-age=2592000");
                    const refreshedResponse = new Response(clonedResponse.body, {
                        status: clonedResponse.status,
                        statusText: clonedResponse.statusText,
                        headers: newHeaders,
                    });
                    await cache.put(cacheKey, refreshedResponse);
                })()
            );

            // Return response with CORS headers injected
            return addCorsHeaders(response);
        }

        // 4. CACHE MISS: Prepare upstream request
        const clientUserAgent = request.headers.get("User-Agent") || "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
        
        const upstreamHeaders = new Headers();
        upstreamHeaders.set("User-Agent", clientUserAgent);
        upstreamHeaders.set("Accept", "application/json, text/html, */*");
        if (request.headers.get("Accept-Language")) {
            upstreamHeaders.set("Accept-Language", request.headers.get("Accept-Language"));
        }

        try {
            const upstreamResponse = await fetch(targetUrl.toString(), {
                method: request.method,
                headers: upstreamHeaders,
            });

            // Re-build response with 30-day Cache-Control header
            const responseHeaders = new Headers(upstreamResponse.headers);
            responseHeaders.set("Cache-Control", "public, max-age=2592000");
            responseHeaders.set("Access-Control-Allow-Origin", "*");

            const newResponse = new Response(upstreamResponse.body, {
                status: upstreamResponse.status,
                statusText: upstreamResponse.statusText,
                headers: responseHeaders,
            });

            // Store in Cache Engine asynchronously
            ctx.waitUntil(cache.put(cacheKey, newResponse.clone()));

            return newResponse;
        } catch (err) {
            return new Response("Gateway response error", { status: 502 });
        }
    }
};

// Helper function to attach open CORS headers
function addCorsHeaders(response) {
    const newHeaders = new Headers(response.headers);
    newHeaders.set("Access-Control-Allow-Origin", "*");
    return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: newHeaders,
    });
}
