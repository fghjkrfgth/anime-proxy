const JWT_SECRET = "blackleg-jwt-auth-secret-key-2026";

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status: status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, *",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
    }
  });
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

async function getHmacKey(secretStr = JWT_SECRET) {
  const encoder = new TextEncoder();
  return await crypto.subtle.importKey(
    "raw",
    encoder.encode(secretStr),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

async function hashPassword(password, saltHex) {
  const encoder = new TextEncoder();
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const saltBytes = hexToBytes(saltHex);
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: 100000,
      hash: "SHA-256"
    },
    passwordKey,
    256
  );
  return bytesToHex(new Uint8Array(derivedBits));
}

async function signToken(payloadObj, secretStr = JWT_SECRET) {
  const key = await getHmacKey(secretStr);
  const encoder = new TextEncoder();
  const jsonStr = JSON.stringify(payloadObj);
  const payloadBase64 = btoa(jsonStr).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const signatureBits = await crypto.subtle.sign("HMAC", key, encoder.encode(payloadBase64));
  const sigHex = bytesToHex(new Uint8Array(signatureBits));
  return `${payloadBase64}.${sigHex}`;
}

async function verifyToken(tokenStr, secretStr = JWT_SECRET) {
  if (!tokenStr || typeof tokenStr !== 'string') return null;
  const parts = tokenStr.split('.');
  if (parts.length !== 2) return null;
  const [payloadBase64, sigHex] = parts;
  try {
    const key = await getHmacKey(secretStr);
    const encoder = new TextEncoder();
    const sigBytes = hexToBytes(sigHex);
    const isValid = await crypto.subtle.verify("HMAC", key, sigBytes, encoder.encode(payloadBase64));
    if (!isValid) return null;

    const base64 = payloadBase64.replace(/-/g, '+').replace(/_/g, '/');
    const jsonStr = atob(base64);
    const payload = JSON.parse(jsonStr);

    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event));
});

async function handleRequest(eventOrReq, envParam) {
  const request = eventOrReq.request ? eventOrReq.request : eventOrReq;
  const env = envParam || globalThis.env || {};
  const db = env?.DB || globalThis.DB;
  const url = new URL(request.url);

  // 1. OPTIONS PREFLIGHT
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization, Range, X-Requested-With, *",
        "Access-Control-Expose-Headers": "Content-Length, Content-Range, Accept-Ranges, Content-Type",
        "Access-Control-Max-Age": "86400",
      },
    });
  }

  const normPath = url.pathname.replace(/\/+$/, "");
  const queryAction = url.searchParams.get("action");

  // D1 AUTH & VAULT ROUTES
  if ((normPath === "/api/auth/register" || queryAction === "register") && request.method === "POST") {
    try {
      if (!db) return jsonResponse({ success: false, error: "D1 database binding 'DB' not found" }, 500);
      const body = await request.json();
      const { email, password } = body || {};
      if (!email || typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
        return jsonResponse({ success: false, error: "Invalid email format" }, 400);
      }
      if (!password || typeof password !== 'string' || password.length < 6) {
        return jsonResponse({ success: false, error: "Password must be at least 6 characters" }, 400);
      }
      const normalizedEmail = email.trim().toLowerCase();
      const existing = await db.prepare("SELECT id FROM users WHERE email = ?").bind(normalizedEmail).first();
      if (existing) return jsonResponse({ success: false, error: "An account with this email already exists" }, 409);

      const saltBytes = crypto.getRandomValues(new Uint8Array(16));
      const saltHex = bytesToHex(saltBytes);
      const passwordHash = await hashPassword(password, saltHex);
      const userId = crypto.randomUUID();
      const now = Date.now();

      await db.prepare("INSERT INTO users (id, email, password_hash, salt, created_at) VALUES (?, ?, ?, ?, ?)").bind(userId, normalizedEmail, passwordHash, saltHex, now).run();
      await db.prepare("INSERT INTO user_vault (user_id, watch_vault, updated_at) VALUES (?, ?, ?)").bind(userId, JSON.stringify([]), now).run();

      const token = await signToken({ userId, email: normalizedEmail, exp: Date.now() + 30 * 24 * 3600 * 1000 });
      return jsonResponse({ success: true, token, user: { id: userId, email: normalizedEmail } });
    } catch (err) {
      return jsonResponse({ success: false, error: err.message || "Registration failed" }, 500);
    }
  }

  if ((normPath === "/api/auth/login" || queryAction === "login") && request.method === "POST") {
    try {
      if (!db) return jsonResponse({ success: false, error: "D1 database binding 'DB' not found" }, 500);
      const body = await request.json();
      const { email, password } = body || {};
      if (!email || !password) return jsonResponse({ success: false, error: "Email and password required" }, 400);

      const normalizedEmail = email.trim().toLowerCase();
      const user = await db.prepare("SELECT * FROM users WHERE email = ?").bind(normalizedEmail).first();
      if (!user) return jsonResponse({ success: false, error: "Invalid email or password" }, 401);

      const computedHash = await hashPassword(password, user.salt);
      if (computedHash !== user.password_hash) return jsonResponse({ success: false, error: "Invalid email or password" }, 401);

      const token = await signToken({ userId: user.id, email: user.email, exp: Date.now() + 30 * 24 * 3600 * 1000 });
      return jsonResponse({ success: true, token, user: { id: user.id, email: user.email } });
    } catch (err) {
      return jsonResponse({ success: false, error: err.message || "Login failed" }, 500);
    }
  }

  if ((normPath === "/api/user/sync" || queryAction === "sync") && request.method === "GET") {
    try {
      if (!db) return jsonResponse({ success: false, error: "D1 database binding 'DB' not found" }, 500);
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.replace(/^Bearer\s+/i, "").trim();
      const session = await verifyToken(token);
      if (!session) return jsonResponse({ success: false, error: "Unauthorized" }, 401);

      const record = await db.prepare("SELECT watch_vault, updated_at FROM user_vault WHERE user_id = ?").bind(session.userId).first();
      let vault = [];
      if (record && record.watch_vault) {
        try { vault = JSON.parse(record.watch_vault); } catch (e) { vault = []; }
      }
      return jsonResponse({ success: true, vault, updatedAt: record ? record.updated_at : 0 });
    } catch (err) {
      return jsonResponse({ success: false, error: err.message || "Sync failed" }, 500);
    }
  }

  if ((normPath === "/api/user/sync" || queryAction === "sync") && request.method === "POST") {
    try {
      if (!db) return jsonResponse({ success: false, error: "D1 database binding 'DB' not found" }, 500);
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.replace(/^Bearer\s+/i, "").trim();
      const session = await verifyToken(token);
      if (!session) return jsonResponse({ success: false, error: "Unauthorized" }, 401);

      const body = await request.json();
      const vault = body?.vault || [];
      const now = Date.now();
      await db.prepare(`
        INSERT INTO user_vault (user_id, watch_vault, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET watch_vault = excluded.watch_vault, updated_at = excluded.updated_at
      `).bind(session.userId, JSON.stringify(vault), now).run();

      return jsonResponse({ success: true, updatedAt: now });
    } catch (err) {
      return jsonResponse({ success: false, error: err.message || "Sync failed" }, 500);
    }
  }

  const userAgent = request.headers.get("User-Agent") || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36";

  // SCHEDULE & FRANCHISE ROUTES
  if (queryAction === "schedule" || url.pathname === "/schedule") {
    return await handleScheduleRequest(url);
  }
  if (url.pathname === "/comment" || queryAction === "comment" || url.pathname === "/api/franchise") {
    const slug = url.searchParams.get("s") || url.searchParams.get("slug");
    const id = url.searchParams.get("id") || url.searchParams.get("anilistId");
    return await handleFranchiseRequest(slug, id, userAgent);
  }

  // 2. NEW ROUTE: Fetch Server List from reanime.to
  if (url.pathname === "/api/servers" || queryAction === "servers") {
    return await handleServerListRequest(url);
  }

  // 3. TRANSPARENT PROXY ENGINE (For .ts segments, keys, and subtitles)
  const srcUrl = url.searchParams.get("src");
  if (srcUrl && queryAction !== "proxy_caption") {
    return await handleTransparentProxy(srcUrl, request, url);
  }

  // 4. SUBTITLE VTT / ASS CAPTION PROXY
  if (queryAction === "proxy_caption") {
    return await handleCaptionProxy(url, userAgent);
  }

  // 5. STREAM RESOLUTION (/rating) -> DEFAULT FLIXCLOUD
  const hasStreamParams = url.searchParams.has("e") || url.searchParams.has("ep") || url.searchParams.has("id");
  if (url.pathname === "/rating" || queryAction === "rating" || hasStreamParams) {
    return await handleFlixCloudStreamRequest(url, request);
  }

  return new Response(JSON.stringify({ error: "Unsupported route or missing parameters" }), {
    status: 400,
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
  });
}

// -------------------------------------------------------------------------
// FLIXCLOUD WORKFLOW: STEP 1 (SERVER DISCOVERY VIA REANIME.TO)
// -------------------------------------------------------------------------
async function handleServerListRequest(url) {
  const anilistId = url.searchParams.get("id") || url.searchParams.get("anilistId");
  const epNum = url.searchParams.get("e") || url.searchParams.get("ep") || "1";

  if (!anilistId) {
    return jsonResponse({ success: false, error: "Missing anilist id" }, 400);
  }

  try {
    const targetUrl = `https://reanime.to/api/flix/${anilistId}/${epNum}`;
    const res = await fetch(targetUrl, {
      headers: {
        "Referer": "https://reanime.to/",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"
      }
    });

    if (!res.ok) {
      return jsonResponse({ success: true, servers: [] });
    }

    const data = await res.json();
    const rawServers = data.servers || [];

    const formattedServers = rawServers.map(s => ({
      id: s["$id"] || s.id || `${s.serverName}-${s.dataType}`,
      serverName: s.serverName || "HD-1",
      dataLink: s.dataLink,
      dataType: (s.dataType || "sub").toLowerCase(),
      continue: Boolean(s.continue),
      softsub: Boolean(s.softsub)
    }));

    return jsonResponse({ success: true, servers: formattedServers });
  } catch (err) {
    return jsonResponse({ success: true, servers: [], error: err.message });
  }
}

// -------------------------------------------------------------------------
// FLIXCLOUD WORKFLOW: STEP 2, 3, 4, 5 (PAGE SCRAPE, TOKEN, DECRYPT, PARSE)
// -------------------------------------------------------------------------
async function handleFlixCloudStreamRequest(url, request) {
  const anilistId = url.searchParams.get("id") || url.searchParams.get("anilistId");
  const epNum = url.searchParams.get("e") || url.searchParams.get("ep") || "1";
  const lang = (url.searchParams.get("lang") || "sub").toLowerCase();
  let dataLink = url.searchParams.get("server") || url.searchParams.get("dataLink");

  // Step 1: If dataLink was not passed directly by frontend, resolve via reanime.to
  if (!dataLink) {
    try {
      const serverRes = await fetch(`https://reanime.to/api/flix/${anilistId}/${epNum}`, {
        headers: { "Referer": "https://reanime.to/" }
      });
      if (serverRes.ok) {
        const sJson = await serverRes.json();
        const found = (sJson.servers || []).find(s => (s.dataType || "").toLowerCase() === lang) || (sJson.servers || [])[0];
        if (found) dataLink = found.dataLink;
      }
    } catch (e) {}
  }

  if (!dataLink) {
    return jsonResponse({ success: false, error: "Stream server link not available for this episode." }, 404);
  }

  try {
    // Step 2: Scrape Flixcloud embed HTML and extract SvelteKit embedded JSON
    const pageRes = await fetch(dataLink, {
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
        "Referer": "https://flixcloud.cc/"
      }
    });

    if (!pageRes.ok) {
      return jsonResponse({ success: false, error: `Flixcloud host unreachable (status ${pageRes.status})` }, 502);
    }

    const html = await pageRes.text();
    const dataMatch = html.match(/type:\s*"data",\s*data:\s*(\{.*?\})\s*,\s*uses:/s);
    if (!dataMatch) {
      return jsonResponse({ success: false, error: "Failed to extract data payload from stream provider." }, 502);
    }

    // Loose JSON parser for JS object literal
    let rawObjStr = dataMatch[1];
    let payloadData;
    try {
      payloadData = JSON.parse(rawObjStr);
    } catch (e) {
      // Clean non-quoted keys to valid JSON format
      const validJsonStr = rawObjStr
        .replace(/([{\s,])(\w+)\s*:/g, '$1"$2":')
        .replace(/'/g, '"');
      payloadData = JSON.parse(validJsonStr);
    }

    // Extract subtitles & skip times
    const subtitles = payloadData.subtitles || [];
    delete payloadData.subtitles;

    const intro = payloadData.intro_chapter
      ? { start: payloadData.intro_chapter.start || 0, end: payloadData.intro_chapter.end || 0 }
      : (payloadData.chapters ? { start: payloadData.chapters[1]?.start || 0, end: payloadData.chapters[1]?.end || 0 } : { start: 0, end: 0 });

    const outro = payloadData.outro_chapter
      ? { start: payloadData.outro_chapter.start || 0, end: payloadData.outro_chapter.end || 0 }
      : { start: 0, end: 0 };

    // Step 3: Resolve stream token via enc-dec.app
    const tokenRes = await fetch("https://enc-dec.app/api/dec-flixcloud?type=token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: payloadData })
    });
    const tokenJson = await tokenRes.json();
    if (tokenJson.status !== 200 || !tokenJson.result) {
      return jsonResponse({ success: false, error: tokenJson.error || "Token validation failed" }, 502);
    }
    const tokenValidated = tokenJson.result;

    // Step 4: Fetch encrypted stream payload from Flixcloud
    const encStreamRes = await fetch(`https://flixcloud.cc/api/m3u8/${tokenValidated.token}`, {
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
        "Referer": "https://flixcloud.cc/"
      }
    });
    const encStreamJson = await encStreamRes.json();

    // Step 5: Decrypt stream via enc-dec.app
    const decStreamRes = await fetch("https://enc-dec.app/api/dec-flixcloud?type=stream", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        data: {
          context: tokenValidated.context,
          stream_response: encStreamJson
        }
      })
    });
    const decStreamJson = await decStreamRes.json();
    if (decStreamJson.status !== 200 || !decStreamJson.result) {
      return jsonResponse({ success: false, error: decStreamJson.error || "Stream decryption failed" }, 502);
    }
    const streamResolved = decStreamJson.result;

    // Step 6: Parse manifest via enc-dec.app
    const wPayload = streamResolved.context?.w_payload || "";
    const parseUrl = `https://enc-dec.app/api/parse-flixcloud?url=${encodeURIComponent(streamResolved.stream)}&w_payload=${encodeURIComponent(wPayload)}`;
    const masterManifestRes = await fetch(parseUrl);
    const masterManifestText = await masterManifestRes.text();

    // Choose Sub (Native/Japanese) or Dub (English) audio stream URL
    let chosenAudioUrl = null;
    let chosenVideoUrl = null;

    const lines = masterManifestText.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.startsWith("#EXT-X-MEDIA:TYPE=AUDIO")) {
        const isEnglish = /LANGUAGE="eng"|NAME="English"/i.test(line);
        const isNative = /LANGUAGE="jpn"|NAME="Native"/i.test(line);
        const uriMatch = line.match(/URI=["']([^"']+)["']/i);

        if (uriMatch) {
          if (lang === "dub" && isEnglish) {
            chosenAudioUrl = uriMatch[1];
          } else if (lang === "sub" && isNative) {
            chosenAudioUrl = uriMatch[1];
          }
        }
      }
      if (line.startsWith("https://enc-dec.app/api/parse-flixcloud") || (lines[i - 1] && lines[i - 1].startsWith("#EXT-X-STREAM-INF:"))) {
        chosenVideoUrl = line.trim();
      }
    }

    // Default to the language selection or stream URL directly
    let targetManifestUrl = (lang === "dub" && chosenAudioUrl) ? chosenAudioUrl : (chosenAudioUrl || chosenVideoUrl || parseUrl);

    // Fetch the target rendition playlist
    const renditionRes = await fetch(targetManifestUrl);
    let playlistText = await renditionRes.text();

    // Step 7: Rewrite chunk paths to route through transparent proxy with Flixcloud headers
    const rewrittenManifest = rewriteM3u8Manifest(playlistText, targetManifestUrl, url.origin);

    return jsonResponse({
      success: true,
      manifest: rewrittenManifest,
      subtitles: subtitles.map(s => ({
        file: `${url.origin}/?src=${encodeURIComponent(s.url)}&action=proxy_caption`,
        label: s.language || "English",
        kind: "captions",
        default: Boolean(s.default)
      })),
      intro: intro,
      outro: outro
    });

  } catch (err) {
    return jsonResponse({ success: false, error: err.message || "Failed to resolve Flixcloud media pipeline" }, 502);
  }
}

// -------------------------------------------------------------------------
// TRANSPARENT PROXY ENGINE (WITH FLIXCLOUD REFERER)
// -------------------------------------------------------------------------
async function handleTransparentProxy(srcUrl, request, workerUrl) {
  const headers = new Headers();
  headers.set("Referer", "https://flixcloud.cc/");
  headers.set("Origin", "https://flixcloud.cc");
  headers.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36");
  headers.set("Accept", "*/*");

  const rangeHeader = request.headers.get("Range") || request.headers.get("range");
  if (rangeHeader) headers.set("Range", rangeHeader);

  try {
    const upstreamResponse = await fetch(srcUrl, {
      method: request.method === "HEAD" ? "HEAD" : "GET",
      headers: headers,
    });

    const contentType = (upstreamResponse.headers.get("content-type") || "").toLowerCase();
    const isM3u8 = srcUrl.toLowerCase().includes(".m3u8") || contentType.includes("mpegurl");

    if (isM3u8 && upstreamResponse.status === 200 && request.method === "GET") {
      const playlistText = await upstreamResponse.text();
      const rewritten = rewriteM3u8Manifest(playlistText, srcUrl, workerUrl.origin);

      const playlistHeaders = new Headers(upstreamResponse.headers);
      playlistHeaders.set("Content-Type", "application/vnd.apple.mpegurl; charset=utf-8");
      playlistHeaders.set("Access-Control-Allow-Origin", "*");
      playlistHeaders.set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS");
      playlistHeaders.set("Access-Control-Allow-Headers", "*");
      playlistHeaders.set("Access-Control-Expose-Headers", "Content-Length, Content-Range, Accept-Ranges, Content-Type");
      playlistHeaders.delete("content-encoding");
      playlistHeaders.delete("set-cookie");

      return new Response(rewritten, { status: 200, headers: playlistHeaders });
    }

    const responseHeaders = new Headers(upstreamResponse.headers);
    responseHeaders.set("Access-Control-Allow-Origin", "*");
    responseHeaders.set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS");
    responseHeaders.set("Access-Control-Allow-Headers", "*");
    responseHeaders.set("Access-Control-Expose-Headers", "Content-Length, Content-Range, Accept-Ranges, Content-Type");
    responseHeaders.delete("content-encoding");
    responseHeaders.delete("set-cookie");

    return new Response(request.method === "HEAD" ? null : upstreamResponse.body, {
      status: upstreamResponse.status,
      headers: responseHeaders,
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message, src: srcUrl }), {
      status: 502,
      headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
    });
  }
}

// Caption Fetch Handler
async function handleCaptionProxy(url, userAgent) {
  const vttUrl = url.searchParams.get("vtt_url") || url.searchParams.get("src");
  if (!vttUrl) return jsonResponse({ error: "Missing vtt_url parameter" }, 400);

  try {
    const vttRes = await fetch(vttUrl, {
      headers: {
        "Referer": "https://flixcloud.cc/",
        "User-Agent": userAgent
      }
    });
    if (!vttRes.ok) return new Response("Caption track unreachable", { status: 502, headers: { "Access-Control-Allow-Origin": "*" } });

    const vttText = await vttRes.text();
    return new Response(vttText, {
      headers: {
        "Content-Type": "text/vtt; charset=utf-8",
        "Access-Control-Allow-Origin": "*"
      }
    });
  } catch (err) {
    return jsonResponse({ error: err.message }, 502);
  }
}

// Manifest Rewriter
function rewriteM3u8Manifest(playlistText, targetUrl, workerOrigin) {
  if (!playlistText || typeof playlistText !== 'string') return '';
  const sanitizedText = playlistText.replace(/^\uFEFF/, '').trimStart();
  if (!sanitizedText) return '';

  let baseUrl;
  try {
    baseUrl = new URL(targetUrl);
  } catch (e) {
    return sanitizedText;
  }

  const cleanWorkerOrigin = (workerOrigin || '').replace(/\/+$/, '');
  const lines = sanitizedText.split(/\r?\n/);
  const rewrittenLines = [];

  const resolveTargetUri = (rawUri) => {
    let absUrl;
    try {
      const resolved = new URL(rawUri, baseUrl.href);
      if (baseUrl.search && !resolved.search) {
        resolved.search = baseUrl.search;
      }
      absUrl = resolved.href;
    } catch (e) {
      absUrl = rawUri;
    }
    return absUrl;
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed) continue;

    if (trimmed.startsWith('#')) {
      if (/URI=/i.test(trimmed)) {
        const tagRewritten = line.replace(/URI=["']([^"']+)["']/gi, (match, uri) => {
          if ((cleanWorkerOrigin && uri.startsWith(cleanWorkerOrigin)) || uri.startsWith('/?src=')) return `URI="${uri}"`;
          const absUrl = resolveTargetUri(uri);
          return `URI="${cleanWorkerOrigin}/?src=${encodeURIComponent(absUrl)}"`;
        });
        rewrittenLines.push(tagRewritten);
        continue;
      }
      rewrittenLines.push(line);
      continue;
    }

    if ((cleanWorkerOrigin && trimmed.startsWith(cleanWorkerOrigin)) || trimmed.startsWith('/?src=')) {
      rewrittenLines.push(trimmed);
      continue;
    }

    const absSegmentUrl = resolveTargetUri(trimmed);
    rewrittenLines.push(`${cleanWorkerOrigin}/?src=${encodeURIComponent(absSegmentUrl)}`);
  }

  if (rewrittenLines.length === 0 || !rewrittenLines[0].startsWith('#EXTM3U')) {
    rewrittenLines.unshift('#EXTM3U');
  }

  return rewrittenLines.join('\n');
}

// SCHEDULE & FRANCHISE HANDLERS (Preserved)
async function handleScheduleRequest(url) {
  const inputTime = parseInt(url.searchParams.get("time") || Math.floor(Date.now() / 1000).toString(), 10);
  const inputTz = parseInt(url.searchParams.get("tz") || "0", 10);
  const localizedTime = inputTime + (inputTz * 3600);
  const localizedDate = new Date(localizedTime * 1000);
  const todayMidnightUtc = Math.floor(Date.UTC(localizedDate.getUTCFullYear(), localizedDate.getUTCMonth(), localizedDate.getUTCDate()) / 1000);
  const daysOfWeek = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
  const payload = [];

  for (let i = 0; i < 7; i++) {
    const timestamp = todayMidnightUtc + (i * 86400);
    const dayName = daysOfWeek[new Date(timestamp * 1000).getUTCDay()];
    payload.push({ day: dayName, timestamp, shows: [] });
  }

  return jsonResponse(payload);
}

async function handleFranchiseRequest(slug, id, userAgent) {
  if (!slug || !id) return jsonResponse({ error: "Missing parameter", seasons: [] }, 400);
  return jsonResponse({ seasons: [] });
}

export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env);
  }
};
