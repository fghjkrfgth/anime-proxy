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

  // 1. UNIVERSAL OPTIONS PREFLIGHT HANDLER
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization, *",
        "Access-Control-Expose-Headers": "Content-Length, Content-Range, Accept-Ranges, Content-Type",
        "Access-Control-Max-Age": "86400",
      },
    });
  }

  const normPath = url.pathname.replace(/\/+$/, "");
  const queryAction = url.searchParams.get("action");

  // 1.5 D1 AUTH & CLOUD WATCH VAULT SYNC ENDPOINTS
  if ((normPath === "/api/auth/register" || queryAction === "register") && request.method === "POST") {
    try {
      if (!db) {
        return jsonResponse({ success: false, error: "D1 database binding 'DB' not found" }, 500);
      }
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
      if (existing) {
        return jsonResponse({ success: false, error: "An account with this email already exists" }, 409);
      }

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
      if (!db) {
        return jsonResponse({ success: false, error: "D1 database binding 'DB' not found" }, 500);
      }
      const body = await request.json();
      const { email, password } = body || {};

      if (!email || !password) {
        return jsonResponse({ success: false, error: "Email and password required" }, 400);
      }

      const normalizedEmail = email.trim().toLowerCase();
      const user = await db.prepare("SELECT * FROM users WHERE email = ?").bind(normalizedEmail).first();
      if (!user) {
        return jsonResponse({ success: false, error: "Invalid email or password" }, 401);
      }

      const computedHash = await hashPassword(password, user.salt);
      if (computedHash !== user.password_hash) {
        return jsonResponse({ success: false, error: "Invalid email or password" }, 401);
      }

      const token = await signToken({ userId: user.id, email: user.email, exp: Date.now() + 30 * 24 * 3600 * 1000 });
      return jsonResponse({ success: true, token, user: { id: user.id, email: user.email } });
    } catch (err) {
      return jsonResponse({ success: false, error: err.message || "Login failed" }, 500);
    }
  }

  if ((normPath === "/api/user/sync" || queryAction === "sync") && request.method === "GET") {
    try {
      if (!db) {
        return jsonResponse({ success: false, error: "D1 database binding 'DB' not found" }, 500);
      }
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.replace(/^Bearer\s+/i, "").trim();
      const session = await verifyToken(token);
      if (!session) {
        return jsonResponse({ success: false, error: "Unauthorized or expired session token" }, 401);
      }

      const record = await db.prepare("SELECT watch_vault, updated_at FROM user_vault WHERE user_id = ?").bind(session.userId).first();
      let vault = [];
      if (record && record.watch_vault) {
        try {
          vault = JSON.parse(record.watch_vault);
        } catch (e) {
          vault = [];
        }
      }
      return jsonResponse({ success: true, vault, updatedAt: record ? record.updated_at : 0 });
    } catch (err) {
      return jsonResponse({ success: false, error: err.message || "Sync failed" }, 500);
    }
  }

  if ((normPath === "/api/user/sync" || queryAction === "sync") && request.method === "POST") {
    try {
      if (!db) {
        return jsonResponse({ success: false, error: "D1 database binding 'DB' not found" }, 500);
      }
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.replace(/^Bearer\s+/i, "").trim();
      const session = await verifyToken(token);
      if (!session) {
        return jsonResponse({ success: false, error: "Unauthorized or expired session token" }, 401);
      }

      const body = await request.json();
      const vault = body?.vault || [];
      const vaultStr = JSON.stringify(vault);
      const now = Date.now();

      await db.prepare(`
        INSERT INTO user_vault (user_id, watch_vault, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
          watch_vault = excluded.watch_vault,
          updated_at = excluded.updated_at
      `).bind(session.userId, vaultStr, now).run();

      return jsonResponse({ success: true, updatedAt: now });
    } catch (err) {
      return jsonResponse({ success: false, error: err.message || "Sync failed" }, 500);
    }
  }

  // Define client User-Agent
  let userAgent = request.headers.get("User-Agent") || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";

  // 2. ROUTING PIPELINE: Weekly Broadcast Schedule (/schedule)
  const action = url.searchParams.get("action");
  if (action === "schedule" || url.pathname === "/schedule") {
    return await handleScheduleRequest(url);
  }

  // 3. OBFUSCATED ROUTE: Franchise Tree (/comment?s={slug}&id={anilistId})
  if (url.pathname === "/comment" || action === "comment" || url.pathname === "/api/franchise" || action === "franchise") {
    const slug = url.searchParams.get("s") || url.searchParams.get("slug");
    const id = url.searchParams.get("id") || url.searchParams.get("anilistId") || url.searchParams.get("anilist_id");
    return await handleFranchiseRequest(slug, id, userAgent);
  }

  // 4. OBFUSCATED ROUTE: Media & Stream Resolution (/rating?e={episodeId}&id={anilistId}&lang={lang})
  const hasStreamParams = url.searchParams.has("e") || url.searchParams.has("ep_num") || url.searchParams.has("ep") || url.searchParams.has("episodeId");
  if (url.pathname === "/rating" || action === "rating" || url.pathname === "/api/stream" || url.pathname === "/api/media" || (hasStreamParams && action !== "proxy_caption" && action !== "schedule")) {
    return await handleStreamRequest(url, request);
  }

  // 4. ROUTING PIPELINE: Subtitle VTT Caption Proxy
  if (action === "proxy_caption") {
    const vttUrl = url.searchParams.get("vtt_url") || url.searchParams.get("src");
    if (!vttUrl) {
      return new Response(JSON.stringify({ error: "Missing vtt_url parameter" }), {
        status: 400,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*"
        }
      });
    }

    try {
      const vttRes = await fetch(vttUrl, {
        headers: {
          'Referer': 'https://megaplay.buzz/',
          'User-Agent': userAgent
        }
      });

      if (!vttRes.ok) {
        return new Response("Failed to fetch caption tracks from upstream source.", {
          status: 502,
          headers: { "Access-Control-Allow-Origin": "*" }
        });
      }

      const vttText = await vttRes.text();
      return new Response(vttText, {
        headers: {
          "Content-Type": "text/vtt; charset=utf-8",
          "Access-Control-Allow-Origin": "*"
        }
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), {
        status: 502,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }
  }

  // 5. TRANSPARENT PROXY ENGINE (For general assets, TS segments, sub-playlists, keys)
  const srcUrl = url.searchParams.get("src");
  if (srcUrl) {
    return await handleTransparentProxy(srcUrl, request, url);
  }

  return new Response(JSON.stringify({ error: "Unsupported route or missing parameters" }), {
    status: 400,
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
  });
}

// Universal Transparent Proxy Handler for all ?src= media segments and keys
async function handleTransparentProxy(srcUrl, request, workerUrl) {
  const headers = new Headers();

  // 1. Normalize and attach required anti-leech headers for all third-party media CDNs
  headers.set("Referer", "https://megaplay.buzz/");
  headers.set("Origin", "https://megaplay.buzz");
  headers.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36");
  headers.set("Accept", "*/*");
  headers.set("Accept-Language", "en-US,en;q=0.9");
  headers.set("Sec-Fetch-Dest", "empty");
  headers.set("Sec-Fetch-Mode", "cors");
  headers.set("Sec-Fetch-Site", "cross-site");

  // 2. Forward Range header if requested by HLS player
  const rangeHeader = request.headers.get("Range");
  if (rangeHeader) {
    headers.set("Range", rangeHeader);
  }

  try {
    const upstreamResponse = await fetch(srcUrl, {
      method: request.method,
      headers: headers,
    });

    // Handle M3U8 Sub-Playlist Rewriting on-the-fly
    if (srcUrl.toLowerCase().includes(".m3u8") && upstreamResponse.status === 200 && request.method === "GET") {
      const playlistText = await upstreamResponse.text();
      const rewritten = rewriteM3u8Manifest(playlistText, srcUrl, workerUrl.origin);

      return new Response(rewritten, {
        status: 200,
        headers: {
          "Content-Type": "application/x-mpegURL",
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
          "Access-Control-Allow-Headers": "*",
          "Access-Control-Expose-Headers": "Content-Length, Content-Range, Accept-Ranges",
        },
      });
    }

    // 3. Forward stream response with full CORS and byte-range preservation
    const responseHeaders = new Headers(upstreamResponse.headers);
    responseHeaders.set("Access-Control-Allow-Origin", "*");
    responseHeaders.set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS");
    responseHeaders.set("Access-Control-Allow-Headers", "*");
    responseHeaders.set("Access-Control-Expose-Headers", "Content-Length, Content-Range, Accept-Ranges, Content-Type");

    return new Response(upstreamResponse.body, {
      status: upstreamResponse.status,
      statusText: upstreamResponse.statusText,
      headers: responseHeaders,
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message, src: srcUrl }), {
      status: 502,
      headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
    });
  }
}

// Helper: Rewrite M3U8 manifest segments and URI attributes to proxy URLs
function rewriteM3u8Manifest(playlistText, targetUrl, workerOrigin) {
  if (!playlistText) return '';
  let baseUrl;
  try {
    baseUrl = new URL(targetUrl);
  } catch (e) {
    return playlistText;
  }

  const lines = playlistText.split(/\r?\n/);
  const rewrittenLines = lines.map(line => {
    let trimmed = line.trim();
    if (!trimmed) return line;

    if (trimmed.startsWith('#')) {
      return line.replace(/URI=["']([^"']+)["']/gi, (match, uri) => {
        let absUrl;
        try {
          absUrl = new URL(uri, baseUrl.href).href;
        } catch (e) {
          absUrl = uri;
        }
        const proxiedUrl = `${workerOrigin}/?src=${encodeURIComponent(absUrl)}`;
        return `URI="${proxiedUrl}"`;
      });
    }

    let absSegmentUrl;
    try {
      absSegmentUrl = new URL(trimmed, baseUrl.href).href;
    } catch (e) {
      absSegmentUrl = trimmed;
    }
    return `${workerOrigin}/?src=${encodeURIComponent(absSegmentUrl)}`;
  });

  return rewrittenLines.join('\n');
}

// Helper: HTML entity decoder
function htmlEntityDecode(str) {
  if (!str) return '';
  return str
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/&#39;/g, "'")
    .replace(/&#039;/g, "'")
    .replace(/&#x27;/g, "'")
    .replace(/&#x2F;/g, '/')
    .replace(/&nbsp;/g, ' ');
}

// Helper: Discover master manifest path (.m3u8)
function findM3u8Url(arr) {
  if (!arr || typeof arr !== 'object') return null;
  if (typeof arr.video === 'string') return arr.video;
  if (typeof arr.file === 'string') return arr.file;
  if (Array.isArray(arr.sources)) {
    for (let src of arr.sources) {
      if (typeof src.file === 'string') return src.file;
    }
  }
  for (let k in arr) {
    let v = arr[k];
    if (typeof v === 'string' && /\.m3u8(\?|$)/i.test(v)) {
      return v;
    } else if (typeof v === 'object' && v !== null) {
      let res = findM3u8Url(v);
      if (res) return res;
    }
  }
  return null;
}

// Helper: Locate subtitle tracks
function findSubtitlesRecursive(arr) {
  if (!arr || typeof arr !== 'object') return [];
  if (Array.isArray(arr)) {
    let subs = [];
    for (let item of arr) {
      if (item && typeof item === 'object' && typeof item.file === 'string' && (item.label || item.kind)) {
        subs.push({
          file: item.file,
          label: item.label || item.kind || 'Unknown Language',
          kind: item.kind || 'captions'
        });
      }
    }
    if (subs.length > 0) return subs;
  }
  for (let k in arr) {
    let v = arr[k];
    if (typeof v === 'object' && v !== null) {
      let res = findSubtitlesRecursive(v);
      if (res && res.length > 0) return res;
    }
  }
  return [];
}

// Helper: Locate skip point timestamp configs
function findSkipTimesRecursive(arr, key) {
  if (!arr || typeof arr !== 'object') return null;
  for (let k in arr) {
    let v = arr[k];
    if (k.toLowerCase() === key.toLowerCase()) {
      if (v && typeof v === 'object') {
        return {
          start: parseFloat(v.start || 0),
          end: parseFloat(v.end || 0)
        };
      } else if (typeof v === 'number' || !isNaN(v)) {
        return {
          start: parseFloat(v),
          end: 0.0
        };
      }
    }
    if (typeof v === 'object' && v !== null) {
      let res = findSkipTimesRecursive(v, key);
      if (res) return res;
    }
  }
  return null;
}

// -------------------------------------------------------------------------
// RESOLVER 1: WEEKLY BROADCAST SCHEDULE ROUTER
// -------------------------------------------------------------------------
async function handleScheduleRequest(url) {
  const inputTime = parseInt(url.searchParams.get("time") || Math.floor(Date.now() / 1000).toString(), 10);
  const inputTz = parseInt(url.searchParams.get("tz") || "0", 10);

  const localizedTime = inputTime + (inputTz * 3600);
  const localizedDate = new Date(localizedTime * 1000);
  const year = localizedDate.getUTCFullYear();
  const month = localizedDate.getUTCMonth();
  const date = localizedDate.getUTCDate();
  const todayMidnightUtc = Math.floor(Date.UTC(year, month, date) / 1000);

  const daysOfWeek = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
  const payload = [];

  for (let i = 0; i < 7; i++) {
    const timestamp = todayMidnightUtc + (i * 86400);
    const dayIndex = new Date(timestamp * 1000).getUTCDay();
    const dayName = daysOfWeek[dayIndex];

    const ajaxUrl = `https://anikototv.to/ajax/schedule/date?tz=0&time=${timestamp}`;
    const headers = new Headers({
      'X-Requested-With': 'XMLHttpRequest',
      'Referer': 'https://anikototv.to/home',
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
    });

    const shows = [];

    try {
      const res = await fetch(ajaxUrl, { headers });
      if (res.ok) {
        const data = await res.json();
        const html = data.result || '';

        const itemRegex = /<a\s+([^>]*class=["'][^"']*item[^"']*["'][^>]*)>([\s\S]*?)<\/a>/gi;
        let match;
        while ((match = itemRegex.exec(html)) !== null) {
          const attrs = match[1];
          const inner = match[2];

          const hrefMatch = attrs.match(/href=["']([^"']*)["']/i);
          const href = hrefMatch ? hrefMatch[1] : '';

          let slug = '';
          const slugMatch = href.match(/\/watch\/([^\/]+)/i);
          if (slugMatch) {
            slug = slugMatch[1];
          } else {
            slug = href.substring(href.lastIndexOf('/') + 1);
          }

          const timeMatch = inner.match(/<div[^>]+class=["']time["'][^>]*>([\s\S]*?)<\/div>/i);
          const timeStr = timeMatch ? timeMatch[1].replace(/<[^>]*>/g, '').trim() : '';

          let showTimeUnix = timestamp;
          if (timeStr) {
            const ampmMatch = timeStr.match(/^(\d{1,2}):(\d{2})\s*(AM|PM)$/i);
            const militaryMatch = timeStr.match(/^(\d{1,2}):(\d{2})$/);
            if (ampmMatch) {
              let hours = parseInt(ampmMatch[1], 10);
              const mins = parseInt(ampmMatch[2], 10);
              const ampm = ampmMatch[3].toUpperCase();
              if (ampm === 'PM' && hours < 12) {
                hours += 12;
              } else if (ampm === 'AM' && hours === 12) {
                hours = 0;
              }
              showTimeUnix = timestamp + (hours * 3600) + (mins * 60);
            } else if (militaryMatch) {
              const hours = parseInt(militaryMatch[1], 10);
              const mins = parseInt(militaryMatch[2], 10);
              showTimeUnix = timestamp + (hours * 3600) + (mins * 60);
            }
          }

          const epMatch = inner.match(/<div[^>]+class=["']ep["'][^>]*>[\s\S]*?<span>([\s\S]*?)<\/span>/i);
          const epStr = epMatch ? epMatch[1].replace(/<[^>]*>/g, '').trim() : '';
          const epNumClean = epStr.replace(/^Episode\s+/i, '');

          let titleEn = '';
          let titleJp = '';
          const titleMatch = inner.match(/<div[^>]+class=["'][^"']*(title\s+d-title|d-title\s+title)[^"']*["'][^>]*>([\s\S]*?)<\/div>/i);
          if (titleMatch) {
            const titleDivTag = titleMatch[0];
            titleEn = htmlEntityDecode(titleMatch[2].replace(/<[^>]*>/g, '').trim());

            const jpMatch = titleDivTag.match(/data-jp=["']([^"']*)["']/i);
            if (jpMatch) {
              titleJp = htmlEntityDecode(jpMatch[1].trim());
            }
          }

          let image = '';
          const imgMatch = inner.match(/<img[^>]+(?:src|data-src|data-original)=["']([^"']*)["']/i);
          if (imgMatch) {
            image = imgMatch[1].trim();
          }

          const formatTime = (unixSecs) => {
            const date = new Date(unixSecs * 1000);
            let hours = date.getUTCHours();
            const minutes = date.getUTCMinutes();
            const ampm = hours >= 12 ? 'PM' : 'AM';
            hours = hours % 12;
            hours = hours ? hours : 12;
            const minutesStr = minutes < 10 ? '0' + minutes : minutes;
            const hoursStr = hours < 10 ? '0' + hours : hours;
            return `${hoursStr}:${minutesStr} ${ampm}`;
          };

          shows.push({
            time: formatTime(showTimeUnix),
            timestamp: showTimeUnix,
            episode: epNumClean,
            title: titleEn,
            title_jp: titleJp,
            slug: slug,
            href: href,
            image: image
          });
        }
      }
    } catch (e) {
      console.error(`[Worker Schedule] Failed parsing date ${dayName}:`, e);
    }

    payload.push({
      day: dayName,
      timestamp: timestamp,
      shows: shows
    });
  }

  const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
  const currentDayName = days[new Date(localizedTime * 1000).getUTCDay()];
  let foundIdx = -1;
  for (let k = 0; k < payload.length; k++) {
    if (payload[k].day.toLowerCase() === currentDayName.toLowerCase()) {
      foundIdx = k;
      break;
    }
  }

  let reorderedPayload = payload;
  if (foundIdx !== -1) {
    reorderedPayload = [
      ...payload.slice(foundIdx),
      ...payload.slice(0, foundIdx)
    ];
  }

  return new Response(JSON.stringify(reorderedPayload), {
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*"
    }
  });
}

// -------------------------------------------------------------------------
// RESOLVER 2: VIDEO STREAM & MANIFEST ROUTER
// -------------------------------------------------------------------------
// Helper: Parse master manifest to find the highest quality stream
function parseMasterM3u8(masterText, masterUrl) {
  const lines = masterText.split('\n');
  let bestBandwidth = -1;
  let bestUrl = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line.startsWith('#EXT-X-STREAM-INF:')) {
      const bwMatch = line.match(/BANDWIDTH=(\d+)/i);
      const bandwidth = bwMatch ? parseInt(bwMatch[1], 10) : 0;

      let nextUrl = null;
      for (let j = i + 1; j < lines.length; j++) {
        const subLine = lines[j].trim();
        if (subLine && !subLine.startsWith('#')) {
          nextUrl = subLine;
          break;
        }
      }
      if (nextUrl) {
        if (bandwidth > bestBandwidth || bestUrl === null) {
          bestBandwidth = bandwidth;
          bestUrl = nextUrl;
        }
      }
    }
  }

  if (!bestUrl) {
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith('#')) {
        bestUrl = trimmed;
        break;
      }
    }
  }

  if (!bestUrl) return null;

  const parsedUrl = new URL(masterUrl);
  const scheme = parsedUrl.protocol;
  const host = parsedUrl.host;
  let path = parsedUrl.pathname;
  let baseDir = path.substring(0, path.lastIndexOf('/'));
  if (baseDir === '' || baseDir === '/') {
    baseDir = '';
  }
  const baseUrl = `${scheme}//${host}${baseDir}/`;
  const originUrl = `${scheme}//${host}`;

  if (!bestUrl.startsWith('http://') && !bestUrl.startsWith('https://')) {
    if (bestUrl.startsWith('/')) {
      return originUrl + bestUrl;
    } else {
      return baseUrl + bestUrl;
    }
  }
  return bestUrl;
}

// -------------------------------------------------------------------------
// RESOLVER 2: VIDEO STREAM & MANIFEST ROUTER (/rating)
// -------------------------------------------------------------------------
async function handleStreamRequest(url, request) {
  const anilistId = url.searchParams.get("id") || url.searchParams.get("anilist_id") || url.searchParams.get("anilistId");
  const epNum = url.searchParams.get("e") || url.searchParams.get("ep_num") || url.searchParams.get("ep") || url.searchParams.get("episodeId") || "1";
  const language = url.searchParams.get("lang") || url.searchParams.get("language") || url.searchParams.get("provider") || "sub";

  const megaplayUrl = `https://megaplay.buzz/stream/ani/${anilistId}/${epNum}/${language}`;
  const userAgent = request.headers.get("User-Agent") || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";

  // Step 1: Fetch target HTML page
  const step1Res = await fetch(megaplayUrl, {
    headers: {
      'Referer': 'https://megaplay.buzz/',
      'User-Agent': userAgent,
      'Origin': 'https://megaplay.buzz'
    }
  });

  if (!step1Res.ok) {
    return new Response(JSON.stringify({
      error: 'Failed to connect to streaming gateway page',
      debug: { target_url: megaplayUrl, http_code: step1Res.status }
    }), {
      status: 502,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*"
      }
    });
  }

  const html = await step1Res.text();
  let fileId = null;

  const titleMatch = html.match(/<title>[^<]*?File\s+(\d+)\s*-[^<]*?<\/title>/i);
  const megaMatch = html.match(/File\s+(\d+)\s*-\s*MegaPlay/i);
  const fileMatch = html.match(/File\s+(\d+)/i);

  if (titleMatch) {
    fileId = titleMatch[1];
  } else if (megaMatch) {
    fileId = megaMatch[1];
  } else if (fileMatch) {
    fileId = fileMatch[1];
  }

  if (!fileId) {
    return new Response(JSON.stringify({
      error: 'Streaming source token could not be resolved from gateway HTML',
      debug: { url: megaplayUrl }
    }), {
      status: 404,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*"
      }
    });
  }

  // Step 2: Fetch sources from internal API
  const apiUrl = `https://megaplay.buzz/stream/getSources?id=${fileId}`;
  const step2Res = await fetch(apiUrl, {
    headers: {
      'X-Requested-With': 'XMLHttpRequest',
      'Accept': 'application/json, text/javascript, */*; q=0.01',
      'Referer': 'https://megaplay.buzz/',
      'User-Agent': userAgent,
      'Origin': 'https://megaplay.buzz'
    }
  });

  if (!step2Res.ok) {
    return new Response(JSON.stringify({
      error: 'Failed to resolve streaming paths from internal API gateway',
      debug: { target_url: apiUrl, http_code: step2Res.status }
    }), {
      status: 502,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*"
      }
    });
  }

  let sources;
  try {
    sources = await step2Res.json();
  } catch (e) {
    return new Response(JSON.stringify({
      error: 'Aggregator received corrupted JSON from streaming router API'
    }), {
      status: 502,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*"
      }
    });
  }

  const m3u8Url = findM3u8Url(sources);
  if (!m3u8Url) {
    return new Response(JSON.stringify({
      error: 'Master stream coordinate playlist (.m3u8) path not found in sources mapping',
      debug: sources
    }), {
      status: 404,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*"
      }
    });
  }

  const subtitles = findSubtitlesRecursive(sources);
  const intro = findSkipTimesRecursive(sources, 'intro') || { start: 0.0, end: 0.0 };
  const outro = findSkipTimesRecursive(sources, 'outro') || { start: 0.0, end: 0.0 };

  // Step 3: Fetch master playlist text from CDN
  const masterRes = await fetch(m3u8Url, {
    headers: {
      'Referer': 'https://megaplay.buzz/',
      'Origin': 'https://megaplay.buzz',
      'User-Agent': userAgent
    }
  });

  if (!masterRes.ok) {
    return new Response(JSON.stringify({
      error: 'Failed to download master stream configuration playlist from CDN',
      debug: { m3u8_url: m3u8Url, http_code: masterRes.status }
    }), {
      status: 502,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*"
      }
    });
  }

  const masterText = await masterRes.text();

  // Step 4: Parse master playlist and find highest quality variant URL
  const variantUrl = parseMasterM3u8(masterText, m3u8Url);
  if (!variantUrl) {
    return new Response(JSON.stringify({
      error: 'Failed to extract quality variant from master playlist',
      debug: { masterText }
    }), {
      status: 502,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*"
      }
    });
  }

  // Step 5: Fetch highest quality variant playlist text directly
  const variantRes = await fetch(variantUrl, {
    headers: {
      'Referer': 'https://megaplay.buzz/',
      'Origin': 'https://megaplay.buzz',
      'User-Agent': userAgent
    }
  });

  if (!variantRes.ok) {
    return new Response(JSON.stringify({
      error: 'Failed to download variant playlist from CDN',
      debug: { variantUrl, http_code: variantRes.status }
    }), {
      status: 502,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*"
      }
    });
  }

  const variantText = await variantRes.text();

  // Step 6: Rewrite the variant playlist relative/absolute URLs to use our proxy
  const rewrittenManifest = rewriteM3u8Manifest(variantText, variantUrl, url.origin);

  // Step 7: Server-side fetch and resolve all subtitle caption file contents
  const subtitleTracks = [];
  for (const track of subtitles) {
    if (track.file) {
      try {
        const vttRes = await fetch(track.file, {
          headers: {
            'Referer': 'https://megaplay.buzz/',
            'Origin': 'https://megaplay.buzz',
            'User-Agent': userAgent
          }
        });
        if (vttRes.ok) {
          const vttText = await vttRes.text();
          subtitleTracks.push({
            file: track.file,
            label: track.label,
            kind: track.kind,
            content: vttText
          });
        } else {
          subtitleTracks.push(track);
        }
      } catch (err) {
        console.error(`Failed to download subtitle content for ${track.label}:`, err);
        subtitleTracks.push(track);
      }
    } else {
      subtitleTracks.push(track);
    }
  }

  // Step 8: Return a single fully self-contained response
  return new Response(JSON.stringify({
    success: true,
    manifest: rewrittenManifest,
    subtitles: subtitleTracks,
    intro: intro,
    outro: outro
  }), {
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*"
    }
  });
}

// -------------------------------------------------------------------------
// FRANCHISE TREE FETCH & SVELTEKIT JSON DE-SERIALIZATION ENGINE (/comment)
// -------------------------------------------------------------------------
async function handleFranchiseRequest(slug, id, userAgent) {
  if (!slug || !id) {
    return new Response(JSON.stringify({ error: "Missing parameter", seasons: [] }), {
      status: 400,
      headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
    });
  }

  const targetUrl = `https://animex.one/anime/${encodeURIComponent(slug)}-${id}/__data.json?x-sveltekit-invalidated=01`;
  try {
    const upstreamRes = await fetch(targetUrl, {
      headers: {
        'Referer': 'https://animex.one/',
        'User-Agent': userAgent,
        'Accept': 'application/json'
      }
    });

    if (!upstreamRes.ok) {
      return new Response(JSON.stringify({ seasons: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }

    const json = await upstreamRes.json();
    const seasons = parseAnimexDataPayload(json);

    return new Response(JSON.stringify({ seasons }), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Cache-Control": "public, max-age=3600"
      }
    });
  } catch (err) {
    return new Response(JSON.stringify({ seasons: [], error: err.message }), {
      status: 200,
      headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
    });
  }
}

function parseAnimexDataPayload(json) {
  if (!json) return [];
  if (Array.isArray(json.seasons)) return formatSeasonsArray(json.seasons);

  let rawSeasons = null;

  if (json.nodes && Array.isArray(json.nodes)) {
    for (const node of json.nodes) {
      if (!node) continue;
      if (Array.isArray(node.data)) {
        const flatData = node.data;
        for (let i = 0; i < flatData.length; i++) {
          const item = flatData[i];
          if (item && typeof item === 'object' && !Array.isArray(item)) {
            if (item.seasons !== undefined) {
              const deserialized = deserializeSvelteKit(flatData, i);
              if (deserialized && Array.isArray(deserialized.seasons)) {
                rawSeasons = deserialized.seasons;
                break;
              }
            }
          }
        }
      } else if (node.data && Array.isArray(node.data.seasons)) {
        rawSeasons = node.data.seasons;
      }
      if (rawSeasons) break;
    }
  }

  if (!rawSeasons && json.data && Array.isArray(json.data.seasons)) {
    rawSeasons = json.data.seasons;
  }

  if (Array.isArray(rawSeasons)) {
    return formatSeasonsArray(rawSeasons);
  }

  return [];
}

function deserializeSvelteKit(flatData, idx) {
  if (idx === null || idx === undefined) return null;
  if (typeof idx !== 'number') return idx;
  if (idx < 0 || idx >= flatData.length) return idx;

  const val = flatData[idx];
  if (val === null || val === undefined) return null;
  if (typeof val !== 'object') return val;

  if (Array.isArray(val)) {
    return val.map(item => deserializeSvelteKit(flatData, item));
  }

  const res = {};
  for (const [k, v] of Object.entries(val)) {
    res[k] = deserializeSvelteKit(flatData, v);
  }
  return res;
}

function formatSeasonsArray(arr) {
  if (!Array.isArray(arr)) return [];
  return arr.map(item => {
    if (!item) return null;
    let anilistId = item.anilistId || item.id || item.anilist_id || item.mediaId || '';
    if (typeof anilistId !== 'string') anilistId = String(anilistId);

    let title = '';
    if (typeof item.title === 'string') {
      title = item.title;
    } else if (item.title && typeof item.title === 'object') {
      title = item.title.english || item.title.romaji || item.title.userPreferred || '';
    } else if (item.name) {
      title = String(item.name);
    }

    let image = item.image || item.poster || item.coverImage || item.banner || item.cover || '';
    if (typeof image === 'object' && image !== null) {
      image = image.large || image.extraLarge || image.medium || '';
    }

    let type = item.type || item.format || item.mediaType || 'TV';
    if (typeof type !== 'string') type = 'TV';

    return {
      anilistId: anilistId,
      title: title || 'Anime',
      image: image || '',
      type: type || 'TV'
    };
  }).filter(Boolean);
}

// -------------------------------------------------------------------------
// ES MODULE WORKER EXPORT
// -------------------------------------------------------------------------
export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env);
  }
};

