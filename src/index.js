const JWT_SECRET = "blackleg-jwt-auth-secret-key-2026";

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status: status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, Range, X-Requested-With, *",
      "Access-Control-Expose-Headers": "Content-Length, Content-Range, Accept-Ranges, Content-Type",
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

// -------------------------------------------------------------------------
// IN-MEMORY ASS/SSA TO WEBVTT CONVERTER
// -------------------------------------------------------------------------
function assTimestampToVtt(ts) {
  const parts = ts.trim().split(':');
  if (parts.length === 3) {
    let hours = parts[0].padStart(2, '0');
    let minutes = parts[1].padStart(2, '0');
    let [seconds, centis] = parts[2].split('.');
    seconds = (seconds || '00').padStart(2, '0');
    centis = (centis || '00').padEnd(3, '0').slice(0, 3);
    return `${hours}:${minutes}:${seconds}.${centis}`;
  }
  return ts;
}

function convertAssToVtt(assText) {
  if (!assText || typeof assText !== 'string') return 'WEBVTT\n\n';
  const lines = assText.split(/\r?\n/);
  const vttLines = ['WEBVTT\n'];
  let formatFields = [];

  for (let line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('Format:')) {
      formatFields = trimmed.substring(7).split(',').map(f => f.trim().toLowerCase());
      continue;
    }

    if (trimmed.startsWith('Dialogue:')) {
      const content = trimmed.substring(9).trim();
      const numFields = formatFields.length || 10;

      let tokens = [];
      let currentToken = '';
      let commaCount = 0;

      for (let i = 0; i < content.length; i++) {
        const char = content[i];
        if (char === ',' && commaCount < numFields - 1) {
          tokens.push(currentToken.trim());
          currentToken = '';
          commaCount++;
        } else {
          currentToken += char;
        }
      }
      tokens.push(currentToken.trim());

      let start = '';
      let end = '';
      let text = '';

      if (formatFields.length > 0) {
        const startIdx = formatFields.indexOf('start');
        const endIdx = formatFields.indexOf('end');
        const textIdx = formatFields.indexOf('text');

        start = startIdx !== -1 ? tokens[startIdx] : tokens[1];
        end = endIdx !== -1 ? tokens[endIdx] : tokens[2];
        text = textIdx !== -1 ? tokens[textIdx] : tokens[tokens.length - 1];
      } else {
        start = tokens[1] || '00:00:00.00';
        end = tokens[2] || '00:00:05.00';
        text = tokens.slice(9).join(',');
      }

      if (start && end && text) {
        const vttStart = assTimestampToVtt(start);
        const vttEnd = assTimestampToVtt(end);

        // Strip out ASS styling: {\...}, \N (newline), \n, \h
        let cleanText = text
          .replace(/\{[^}]+\}/g, '')
          .replace(/\\[Nn]/g, '\n')
          .replace(/\\h/g, ' ')
          .trim();

        if (cleanText) {
          vttLines.push(`${vttStart} --> ${vttEnd}`);
          vttLines.push(cleanText);
          vttLines.push('');
        }
      }
    }
  }

  return vttLines.join('\n');
}

// -------------------------------------------------------------------------
// RESILIENT LOOSE JSON PARSER (FOR SVELTEKIT / EMBEDDED OBJECT LITERALS)
// -------------------------------------------------------------------------
function parseLooseJson(str) {
  if (!str || typeof str !== 'string') return null;
  const trimmed = str.trim();
  try {
    return JSON.parse(trimmed);
  } catch (e) {
    try {
      let fixed = trimmed
        .replace(/([{,]\s*)([a-zA-Z0-9_$]+)\s*:/g, '$1"$2":')
        .replace(/:\s*'([^'\\]*(?:\\.[^'\\]*)*)'/g, ':"$1"')
        .replace(/,\s*([}\]])/g, '$1');
      return JSON.parse(fixed);
    } catch (e1) {
      try {
        const fn = new Function(`"use strict"; return (${trimmed});`);
        return fn();
      } catch (e2) {
        try {
          let fixed2 = trimmed
            .replace(/([{\s,])([a-zA-Z0-9_$-]+)\s*:/g, '$1"$2":')
            .replace(/'([^'\\]*(?:\\.[^'\\]*)*)'/g, '"$1"')
            .replace(/,\s*([}\]])/g, '$1');
          return JSON.parse(fixed2);
        } catch (e3) {
          return null;
        }
      }
    }
  }
}

if (typeof addEventListener === "function") {
  addEventListener("fetch", (event) => {
    event.respondWith(handleRequest(event));
  });
}

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
        "Access-Control-Allow-Methods": "GET, HEAD, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization, Range, X-Requested-With, *",
        "Access-Control-Expose-Headers": "Content-Length, Content-Range, Accept-Ranges, Content-Type",
        "Access-Control-Max-Age": "86400",
      },
    });
  }

  const normPath = url.pathname.replace(/\/+$/, "");
  const queryAction = url.searchParams.get("action");
  const action = queryAction;

  // Client User-Agent
  let userAgent = request.headers.get("User-Agent") || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36";

  // ROUTE: Direct Embed Subtitle Scraper (/api/embed-subtitles or ?action=embed_subtitles)
  if (normPath === "/api/embed-subtitles" || queryAction === "embed_subtitles") {
    const embedTarget = url.searchParams.get("url") || url.searchParams.get("id");
    return await handleEmbedSubtitlesExtraction(embedTarget, url.origin, userAgent);
  }

async function ensureDbSchema(db) {
  if (!db) return;
  try { await db.prepare("ALTER TABLE users ADD COLUMN username TEXT").run(); } catch (e) {}
  try { await db.prepare("ALTER TABLE users ADD COLUMN avatar_url TEXT").run(); } catch (e) {}
  try { await db.prepare("ALTER TABLE users ADD COLUMN bio TEXT").run(); } catch (e) {}
}

  // 1.5 D1 AUTH, PROFILE & CLOUD WATCH VAULT SYNC ENDPOINTS
  if ((normPath === "/api/auth/register" || queryAction === "register") && request.method === "POST") {
    try {
      if (!db) return jsonResponse({ success: false, error: "D1 database binding 'DB' not found" }, 500);
      await ensureDbSchema(db);
      const body = await request.json();
      const { email, password } = body || {};

      if (!email || typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
        return jsonResponse({ success: false, error: "Invalid email format" }, 400);
      }
      if (!password || typeof password !== 'string' || password.length < 6) {
        return jsonResponse({ success: false, error: "Password must be at least 6 characters" }, 400);
      }

      const normalizedEmail = email.trim().toLowerCase();
      const existing = await db.prepare("SELECT id FROM users WHERE LOWER(email) = LOWER(?)").bind(normalizedEmail).first();
      if (existing) {
        return jsonResponse({
          success: false,
          error: "An account with this email address already exists. Please sign in instead."
        }, 409);
      }

      const saltBytes = crypto.getRandomValues(new Uint8Array(16));
      const saltHex = bytesToHex(saltBytes);
      const passwordHash = await hashPassword(password, saltHex);
      const userId = crypto.randomUUID();
      const now = Date.now();
      const defaultUsername = (body.username && typeof body.username === 'string' && body.username.trim())
        ? body.username.trim()
        : normalizedEmail.split('@')[0];
      const avatarUrl = (body.avatar_url && typeof body.avatar_url === 'string') ? body.avatar_url.trim() : '';
      const bio = (body.bio && typeof body.bio === 'string') ? body.bio.trim() : '';

      await db.prepare(
        "INSERT INTO users (id, email, password_hash, salt, username, avatar_url, bio, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
      ).bind(userId, normalizedEmail, passwordHash, saltHex, defaultUsername, avatarUrl, bio, now).run();

      const initialVault = JSON.stringify({ watched: {}, liked: {}, watchLater: {} });
      await db.prepare("INSERT INTO user_vault (user_id, watch_vault, updated_at) VALUES (?, ?, ?)").bind(userId, initialVault, now).run();

      const token = await signToken({ userId, email: normalizedEmail, exp: Date.now() + 30 * 24 * 3600 * 1000 });
      return jsonResponse({
        success: true,
        token,
        user: { id: userId, email: normalizedEmail, username: defaultUsername, avatar_url: avatarUrl, bio, created_at: now }
      });
    } catch (err) {
      return jsonResponse({ success: false, error: err.message || "Registration failed" }, 500);
    }
  }

  if ((normPath === "/api/auth/login" || queryAction === "login") && request.method === "POST") {
    try {
      if (!db) return jsonResponse({ success: false, error: "D1 database binding 'DB' not found" }, 500);
      await ensureDbSchema(db);
      const body = await request.json();
      const { email, password } = body || {};

      if (!email || !password) return jsonResponse({ success: false, error: "Email and password required" }, 400);

      const normalizedEmail = email.trim().toLowerCase();
      const user = await db.prepare("SELECT * FROM users WHERE LOWER(email) = LOWER(?)").bind(normalizedEmail).first();
      if (!user) return jsonResponse({ success: false, error: "Invalid email or password" }, 401);

      const computedHash = await hashPassword(password, user.salt);
      if (computedHash !== user.password_hash) return jsonResponse({ success: false, error: "Invalid email or password" }, 401);

      const token = await signToken({ userId: user.id, email: user.email, exp: Date.now() + 30 * 24 * 3600 * 1000 });
      return jsonResponse({
        success: true,
        token,
        user: {
          id: user.id,
          email: user.email,
          username: user.username || user.email.split('@')[0],
          avatar_url: user.avatar_url || '',
          bio: user.bio || '',
          created_at: user.created_at
        }
      });
    } catch (err) {
      return jsonResponse({ success: false, error: err.message || "Login failed" }, 500);
    }
  }

  if (normPath === "/api/user/profile" || queryAction === "profile") {
    try {
      if (!db) return jsonResponse({ success: false, error: "D1 database binding 'DB' not found" }, 500);
      await ensureDbSchema(db);
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.replace(/^Bearer\s+/i, "").trim();
      const session = await verifyToken(token);
      if (!session) return jsonResponse({ success: false, error: "Unauthorized or expired session token" }, 401);

      if (request.method === "GET") {
        const user = await db.prepare("SELECT id, email, username, avatar_url, bio, created_at FROM users WHERE id = ?").bind(session.userId).first();
        if (!user) return jsonResponse({ success: false, error: "User not found" }, 404);
        return jsonResponse({
          success: true,
          profile: {
            id: user.id,
            email: user.email,
            username: user.username || user.email.split('@')[0],
            avatar_url: user.avatar_url || '',
            bio: user.bio || '',
            created_at: user.created_at
          }
        });
      }

      if (request.method === "POST" || request.method === "PUT") {
        const user = await db.prepare("SELECT * FROM users WHERE id = ?").bind(session.userId).first();
        if (!user) return jsonResponse({ success: false, error: "User not found" }, 404);

        const body = await request.json();
        const newUsername = (body.username !== undefined && typeof body.username === 'string') ? body.username.trim() : user.username;
        const newAvatar = (body.avatar_url !== undefined && typeof body.avatar_url === 'string') ? body.avatar_url.trim() : user.avatar_url;
        const newBio = (body.bio !== undefined && typeof body.bio === 'string') ? body.bio.trim() : user.bio;

        await db.prepare("UPDATE users SET username = ?, avatar_url = ?, bio = ? WHERE id = ?")
          .bind(newUsername, newAvatar, newBio, session.userId).run();

        return jsonResponse({
          success: true,
          profile: {
            id: user.id,
            email: user.email,
            username: newUsername || user.email.split('@')[0],
            avatar_url: newAvatar || '',
            bio: newBio || '',
            created_at: user.created_at
          }
        });
      }

      return jsonResponse({ success: false, error: "Method not allowed" }, 405);
    } catch (err) {
      return jsonResponse({ success: false, error: err.message || "Profile operation failed" }, 500);
    }
  }

  if ((normPath === "/api/user/sync" || queryAction === "sync") && request.method === "GET") {
    try {
      if (!db) return jsonResponse({ success: false, error: "D1 database binding 'DB' not found" }, 500);
      await ensureDbSchema(db);
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.replace(/^Bearer\s+/i, "").trim();
      const session = await verifyToken(token);
      if (!session) return jsonResponse({ success: false, error: "Unauthorized or expired session token" }, 401);

      const record = await db.prepare("SELECT watch_vault, updated_at FROM user_vault WHERE user_id = ?").bind(session.userId).first();
      const user = await db.prepare("SELECT id, email, username, avatar_url, bio, created_at FROM users WHERE id = ?").bind(session.userId).first();

      let vault = { watched: {}, liked: {}, watchLater: {} };
      if (record && record.watch_vault) {
        try {
          const parsed = JSON.parse(record.watch_vault);
          if (parsed && (parsed.watched || parsed.liked || parsed.watchLater)) {
            vault.watched = parsed.watched || {};
            vault.liked = parsed.liked || {};
            vault.watchLater = parsed.watchLater || {};
          } else if (parsed && typeof parsed === 'object') {
            vault.watched = Array.isArray(parsed)
              ? parsed.reduce((acc, it) => { if (it && it.id) acc[String(it.id)] = it; return acc; }, {})
              : parsed;
          }
        } catch (e) {
          vault = { watched: {}, liked: {}, watchLater: {} };
        }
      }

      const profile = user ? {
        id: user.id,
        email: user.email,
        username: user.username || user.email.split('@')[0],
        avatar_url: user.avatar_url || '',
        bio: user.bio || '',
        created_at: user.created_at
      } : null;

      return jsonResponse({
        success: true,
        vault,
        profile,
        updatedAt: record ? record.updated_at : 0
      });
    } catch (err) {
      return jsonResponse({ success: false, error: err.message || "Sync failed" }, 500);
    }
  }

  if ((normPath === "/api/user/sync" || queryAction === "sync") && request.method === "POST") {
    try {
      if (!db) return jsonResponse({ success: false, error: "D1 database binding 'DB' not found" }, 500);
      await ensureDbSchema(db);
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.replace(/^Bearer\s+/i, "").trim();
      const session = await verifyToken(token);
      if (!session) return jsonResponse({ success: false, error: "Unauthorized or expired session token" }, 401);

      const body = await request.json();
      const incomingVault = body?.vault || {};

      // Load existing vault for non-destructive merge
      const record = await db.prepare("SELECT watch_vault FROM user_vault WHERE user_id = ?").bind(session.userId).first();
      let existingVault = { watched: {}, liked: {}, watchLater: {} };
      if (record && record.watch_vault) {
        try {
          const parsed = JSON.parse(record.watch_vault);
          if (parsed && (parsed.watched || parsed.liked || parsed.watchLater)) {
            existingVault.watched = parsed.watched || {};
            existingVault.liked = parsed.liked || {};
            existingVault.watchLater = parsed.watchLater || {};
          } else if (parsed && typeof parsed === 'object') {
            existingVault.watched = Array.isArray(parsed)
              ? parsed.reduce((acc, it) => { if (it && it.id) acc[String(it.id)] = it; return acc; }, {})
              : parsed;
          }
        } catch (e) {}
      }

      function mergeCollection(target, source) {
        const out = { ...target };
        if (!source) return out;
        const entries = Array.isArray(source)
          ? source.map(item => [String(item?.id || item?.show?.id || ''), item])
          : Object.entries(source);

        for (const [key, item] of entries) {
          if (!key || !item) continue;
          const current = out[key];
          if (!current) {
            out[key] = item;
          } else {
            const inTime = item.updatedAt || item.addedAt || 0;
            const curTime = current.updatedAt || current.addedAt || 0;
            if (inTime >= curTime) {
              out[key] = { ...current, ...item };
            }
          }
        }
        return out;
      }

      // Check if incoming is legacy array or unified map
      let incomingWatched = incomingVault.watched;
      if (!incomingWatched && (Array.isArray(incomingVault) || (typeof incomingVault === 'object' && !incomingVault.liked && !incomingVault.watchLater))) {
        incomingWatched = incomingVault;
      }

      // Direct replacement for liked & watchLater snapshots so deletions persist in D1
      let newLiked = existingVault.liked || {};
      if (incomingVault.liked !== undefined) {
        newLiked = {};
        const likedEntries = Array.isArray(incomingVault.liked)
          ? incomingVault.liked.map(it => [String(it?.id || '').trim(), it])
          : Object.entries(incomingVault.liked);
        for (const [k, it] of likedEntries) {
          const cleanKey = String(k || it?.id || '').trim();
          if (cleanKey && it) {
            newLiked[cleanKey] = {
              id: cleanKey,
              title: it.title,
              coverImage: it.coverImage,
              bannerImage: it.bannerImage || it.banner || '',
              meanScore: it.meanScore || it.averageScore || it.rating || 0,
              format: it.format || 'TV',
              addedAt: it.addedAt || Date.now()
            };
          }
        }
      }

      let newWatchLater = existingVault.watchLater || {};
      if (incomingVault.watchLater !== undefined) {
        newWatchLater = {};
        const wlEntries = Array.isArray(incomingVault.watchLater)
          ? incomingVault.watchLater.map(it => [String(it?.id || '').trim(), it])
          : Object.entries(incomingVault.watchLater);
        for (const [k, it] of wlEntries) {
          const cleanKey = String(k || it?.id || '').trim();
          if (cleanKey && it) {
            newWatchLater[cleanKey] = {
              id: cleanKey,
              title: it.title,
              coverImage: it.coverImage,
              bannerImage: it.bannerImage || it.banner || '',
              meanScore: it.meanScore || it.averageScore || it.rating || 0,
              format: it.format || 'TV',
              addedAt: it.addedAt || Date.now()
            };
          }
        }
      }

      const mergedVault = {
        watched: mergeCollection(existingVault.watched, incomingWatched),
        liked: newLiked,
        watchLater: newWatchLater
      };

      const now = Date.now();
      await db.prepare(`
        INSERT INTO user_vault (user_id, watch_vault, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
          watch_vault = excluded.watch_vault,
          updated_at = excluded.updated_at
      `).bind(session.userId, JSON.stringify(mergedVault), now).run();

      return jsonResponse({ success: true, vault: mergedVault, updatedAt: now });
    } catch (err) {
      return jsonResponse({ success: false, error: err.message || "Sync failed" }, 500);
    }
  }

  // 2. ROUTING PIPELINE: Weekly Broadcast Schedule (/schedule)
  if (action === "schedule" || url.pathname === "/schedule") {
    return await handleScheduleRequest(url);
  }

  // 3. OBFUSCATED ROUTE: Franchise Tree (/comment?s={slug}&id={anilistId})
  if (url.pathname === "/comment" || action === "comment" || url.pathname === "/api/franchise" || action === "franchise") {
    const slug = url.searchParams.get("s") || url.searchParams.get("slug");
    const id = url.searchParams.get("id") || url.searchParams.get("anilistId") || url.searchParams.get("anilist_id");
    return await handleFranchiseRequest(slug, id, userAgent);
  }

  // 4. NEW ROUTE: Fetch Server List from reanime.to (/api/servers or ?action=servers)
  if (normPath === "/api/servers" || queryAction === "servers" || action === "servers") {
    return await handleServerListRequest(url);
  }

  // 5. TRANSPARENT PROXY ENGINE (For .ts segments, sub-playlists, keys, fonts, subtitles)
  const srcUrl = url.searchParams.get("src");
  if (srcUrl && action !== "proxy_caption") {
    return await handleTransparentProxy(srcUrl, request, url);
  }

  // 6. ROUTING PIPELINE: Subtitle Caption Proxy (Automatic ASS/SSA to VTT conversion)
  if (action === "proxy_caption") {
    return await handleCaptionProxy(url, userAgent);
  }

  // 7. STREAM RESOLUTION ROUTE: Media & Stream Resolution (/rating?e={episodeId}&id={anilistId}&lang={lang})
  const hasStreamParams = url.searchParams.has("e") || url.searchParams.has("ep_num") || url.searchParams.has("ep") || url.searchParams.has("episodeId") || url.searchParams.has("id");
  if (url.pathname === "/rating" || action === "rating" || url.pathname === "/api/stream" || url.pathname === "/api/media" || (hasStreamParams && action !== "proxy_caption" && action !== "schedule")) {
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
  const anilistId = url.searchParams.get("id") || url.searchParams.get("anilistId") || url.searchParams.get("anilist_id");
  const epNum = url.searchParams.get("e") || url.searchParams.get("ep") || url.searchParams.get("ep_num") || "1";

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
// MASTER MANIFEST AUDIO ADJUSTER (FOR DEMUXED STREAMS)
// -------------------------------------------------------------------------
function adjustMasterManifestAudio(masterText, preferredLang) {
  if (!masterText || typeof masterText !== 'string') return '';
  const lines = masterText.split(/\r?\n/);
  const adjusted = [];

  for (let line of lines) {
    let trimmed = line.trim();
    if (trimmed.startsWith("#EXT-X-MEDIA:TYPE=AUDIO")) {
      const isEnglish = /LANGUAGE=["']eng["']|NAME=["']English["']/i.test(trimmed);
      const isNative = /LANGUAGE=["']jpn["']|NAME=["']Native["']|NAME=["']Japanese["']/i.test(trimmed);

      if (preferredLang === "dub") {
        if (isEnglish) {
          trimmed = trimmed
            .replace(/DEFAULT=(YES|NO)/gi, "DEFAULT=YES")
            .replace(/AUTOSELECT=(YES|NO)/gi, "AUTOSELECT=YES");
          if (!/DEFAULT=/i.test(trimmed)) trimmed += ',DEFAULT=YES';
          if (!/AUTOSELECT=/i.test(trimmed)) trimmed += ',AUTOSELECT=YES';
        } else if (isNative) {
          trimmed = trimmed.replace(/DEFAULT=(YES|NO)/gi, "DEFAULT=NO");
        }
      } else {
        // sub / native
        if (isNative) {
          trimmed = trimmed
            .replace(/DEFAULT=(YES|NO)/gi, "DEFAULT=YES")
            .replace(/AUTOSELECT=(YES|NO)/gi, "AUTOSELECT=YES");
          if (!/DEFAULT=/i.test(trimmed)) trimmed += ',DEFAULT=YES';
          if (!/AUTOSELECT=/i.test(trimmed)) trimmed += ',AUTOSELECT=YES';
        } else if (isEnglish) {
          trimmed = trimmed.replace(/DEFAULT=(YES|NO)/gi, "DEFAULT=NO");
        }
      }
    }
    adjusted.push(trimmed);
  }

  return adjusted.join('\n');
}

// -------------------------------------------------------------------------
// FLIXCLOUD WORKFLOW: STEP 2, 3, 4, 5 (PAGE SCRAPE, TOKEN, DECRYPT, PARSE)
// -------------------------------------------------------------------------
async function handleFlixCloudStreamRequest(url, request) {
  const anilistId = url.searchParams.get("id") || url.searchParams.get("anilistId") || url.searchParams.get("anilist_id");
  const epNum = url.searchParams.get("e") || url.searchParams.get("ep") || url.searchParams.get("ep_num") || url.searchParams.get("episodeId") || "1";
  const lang = (url.searchParams.get("lang") || url.searchParams.get("language") || "sub").toLowerCase();
  let dataLink = url.searchParams.get("server") || url.searchParams.get("dataLink");

  // Normalize server dataLink: Flixcloud v=2 uses proprietary non-HLS WASM obfuscation with dummy image headers (WebP/PNG without AES-128 key)
  // that breaks standard Hls.js in browser. Normalizing v=2 to v=1 guarantees delivery of the standard AES-128 HLS stream.
  if (dataLink) {
    dataLink = dataLink.replace(/([?&])v=2\b/, '$1v=1');
  }

  // Step 1: If dataLink was not provided directly by client, resolve via reanime.to
  if (!dataLink && anilistId) {
    try {
      const serverRes = await fetch(`https://reanime.to/api/flix/${anilistId}/${epNum}`, {
        headers: {
          "Referer": "https://reanime.to/",
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"
        }
      });
      if (serverRes.ok) {
        const sJson = await serverRes.json();
        const found = (sJson.servers || []).find(s => (s.dataType || "").toLowerCase() === lang) || (sJson.servers || [])[0];
        if (found) dataLink = found.dataLink;
      }
    } catch (e) { }
  }

  if (dataLink) {
    dataLink = dataLink.replace(/([?&])v=2\b/, '$1v=1');
  }

  if (!dataLink) {
    return jsonResponse({ success: false, error: "Stream server link not available for this episode." }, 404);
  }

  try {
    // 1. EXTRACT SUBTITLES AND FONTS PRECISELY FROM VIEW-SOURCE
    // Fetch FlixCloud embed page HTML
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

    // Match subtitles:\s*(\[\s*\{.*?\}\s*\]) to parse all subtitle tracks (url, language, format, default)
    let rawSubtitles = [];
    const subMatch = html.match(/subtitles:\s*(\[\s*\{.*?\}\s*\])/s);
    if (subMatch) {
      try {
        rawSubtitles = parseLooseJson(subMatch[1]) || [];
      } catch (e) { }
    }

    // Match available_fonts:\s*(\{.*?\}) to extract the font map so complex styles (.ass) can render properly
    let rawFonts = {};
    const fontMatch = html.match(/available_fonts:\s*(\{.*?\})/s);
    if (fontMatch) {
      try {
        rawFonts = parseLooseJson(fontMatch[1]) || {};
      } catch (e) { }
    }

    // Extract intro_chapter and outro_chapter for timestamp skip markers
    let introChapter = null;
    const introMatch = html.match(/intro_chapter:\s*(\{.*?\})/s);
    if (introMatch) {
      try { introChapter = parseLooseJson(introMatch[1]); } catch (e) { }
    }

    let outroChapter = null;
    const outroMatch = html.match(/outro_chapter:\s*(\{.*?\})/s);
    if (outroMatch) {
      try { outroChapter = parseLooseJson(outroMatch[1]); } catch (e) { }
    }

    // 2. ACCURATELY MIRROR THE FLIX_3.PY WORKFLOW:
    // Extract full data object from type:\s*"data",\s*data:\s*(\{.*?\})\s*,\s*uses:
    const dataMatch = html.match(/type:\s*"data",\s*data:\s*(\{.*?\})\s*,\s*uses:/s);
    if (!dataMatch) {
      return jsonResponse({ success: false, error: "Failed to extract data payload from stream provider." }, 502);
    }

    let dataObj = parseLooseJson(dataMatch[1]);
    if (!dataObj || typeof dataObj !== 'object') {
      return jsonResponse({ success: false, error: "Failed to parse data payload from stream provider." }, 502);
    }

    // Fallback extraction from dataObj if html regex didn't catch them
    if ((!rawSubtitles || rawSubtitles.length === 0) && Array.isArray(dataObj.subtitles)) {
      rawSubtitles = dataObj.subtitles;
    }
    if ((!rawFonts || Object.keys(rawFonts).length === 0) && dataObj.available_fonts) {
      rawFonts = dataObj.available_fonts;
    }
    if (!introChapter && dataObj.intro_chapter) {
      introChapter = dataObj.intro_chapter;
    }
    if (!outroChapter && dataObj.outro_chapter) {
      outroChapter = dataObj.outro_chapter;
    }
    if (!introChapter && dataObj.chapters && dataObj.chapters[1]) {
      introChapter = dataObj.chapters[1];
    }

    // Remove the subtitles key from the object, exactly as done in Python script (data.pop("subtitles"))
    delete dataObj.subtitles;

    const intro = introChapter
      ? { start: parseFloat(introChapter.start || 0), end: parseFloat(introChapter.end || 0) }
      : { start: 0, end: 0 };
    const outro = outroChapter
      ? { start: parseFloat(outroChapter.start || 0), end: parseFloat(outroChapter.end || 0) }
      : { start: 0, end: 0 };

    // POST to https://enc-dec.app/api/dec-flixcloud?type=token with { data: dataWithoutSubtitles } and validate status === 200
    const tokenRes = await fetch("https://enc-dec.app/api/dec-flixcloud?type=token", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"
      },
      body: JSON.stringify({ data: dataObj })
    });
    const tokenJson = await tokenRes.json().catch(() => null);
    if (!tokenRes.ok || !tokenJson || tokenJson.status !== 200 || !tokenJson.result) {
      return jsonResponse({
        success: false,
        error: (tokenJson && (tokenJson.error || tokenJson.message)) || "Token validation failed",
        step: "token_validation"
      }, 502);
    }
    const tokenValidated = tokenJson.result;

    // GET https://flixcloud.cc/api/m3u8/${token_validated.token} with Referer: https://flixcloud.cc/
    const encStreamRes = await fetch(`https://flixcloud.cc/api/m3u8/${tokenValidated.token}`, {
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
        "Referer": "https://flixcloud.cc/"
      }
    });
    if (!encStreamRes.ok) {
      return jsonResponse({
        success: false,
        error: `Encrypted stream request failed (status ${encStreamRes.status})`,
        step: "fetch_encrypted_stream"
      }, 502);
    }
    const encStreamJson = await encStreamRes.json().catch(() => null);
    if (!encStreamJson) {
      return jsonResponse({
        success: false,
        error: "Invalid encrypted stream response",
        step: "parse_encrypted_stream"
      }, 502);
    }

    // POST to https://enc-dec.app/api/dec-flixcloud?type=stream with { data: { context: token_validated.context, stream_response: stream_response } } and validate status === 200
    const decStreamRes = await fetch("https://enc-dec.app/api/dec-flixcloud?type=stream", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"
      },
      body: JSON.stringify({
        data: {
          context: tokenValidated.context,
          stream_response: encStreamJson
        }
      })
    });
    const decStreamJson = await decStreamRes.json().catch(() => null);
    if (!decStreamRes.ok || !decStreamJson || decStreamJson.status !== 200 || !decStreamJson.result) {
      return jsonResponse({
        success: false,
        error: (decStreamJson && (decStreamJson.error || decStreamJson.message)) || "Stream decryption failed",
        step: "stream_decryption"
      }, 502);
    }
    const streamResolved = decStreamJson.result;

    // Construct manifest URL: https://enc-dec.app/api/parse-flixcloud?url=${encodeURIComponent(stream_resolved.stream)}&w_payload=${encodeURIComponent(stream_resolved.context.w_payload)}
    const wPayload = (streamResolved.context && streamResolved.context.w_payload) || "";
    const parseUrl = `https://enc-dec.app/api/parse-flixcloud?url=${encodeURIComponent(streamResolved.stream)}&w_payload=${encodeURIComponent(wPayload)}`;

    // 3. MASTER MANIFEST RENDITIONS (TREAT TRACKS AS FULL PLAYLISTS)
    const masterManifestRes = await fetch(parseUrl, {
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"
      }
    });
    if (!masterManifestRes.ok) {
      return jsonResponse({
        success: false,
        error: `Failed to fetch master manifest (status ${masterManifestRes.status})`,
        step: "fetch_master_manifest"
      }, 502);
    }

    const masterManifestText = await masterManifestRes.text();

    // 3. MASTER MANIFEST RENDITIONS (DEMUXED AUDIO & VIDEO HANDLING)
    let finalManifestText = masterManifestText;
    const finalManifestUrl = parseUrl;

    if (masterManifestText.includes("#EXT-X-STREAM-INF")) {
      // Demuxed HLS master playlist: adjust default audio track to requested lang (sub vs dub)
      // while keeping all audio renditions available for dynamic in-player track switching
      finalManifestText = adjustMasterManifestAudio(masterManifestText, lang);
    } else {
      finalManifestText = masterManifestText;
    }

    // 4. REWRITE MANIFEST & PROXY SEGMENTS
    const rewrittenManifest = rewriteM3u8Manifest(finalManifestText, finalManifestUrl, url.origin);

    // 5. API RESPONSE STRUCTURE
    const extractedSubtitles = (rawSubtitles || []).map(s => {
      const proxiedUrl = `${url.origin}/?src=${encodeURIComponent(s.url)}`;
      const vttProxyUrl = `${url.origin}/?src=${encodeURIComponent(s.url)}&action=proxy_caption`;
      return {
        url: proxiedUrl,
        file: proxiedUrl,
        rawUrl: s.url,
        vttUrl: vttProxyUrl,
        language: s.language || s.label || "English",
        label: s.language || s.label || "English",
        format: s.format || (s.url && s.url.endsWith(".ass") ? "ass" : "vtt"),
        default: Boolean(s.default),
        kind: "captions"
      };
    });

    let extractedFonts = {};
    if (rawFonts && typeof rawFonts === 'object' && !Array.isArray(rawFonts)) {
      for (const [fontName, fontUrl] of Object.entries(rawFonts)) {
        if (typeof fontUrl === 'string') {
          extractedFonts[fontName] = `${url.origin}/?src=${encodeURIComponent(fontUrl)}`;
        } else {
          extractedFonts[fontName] = fontUrl;
        }
      }
    } else if (Array.isArray(rawFonts)) {
      extractedFonts = rawFonts.map(f => (typeof f === 'string' ? `${url.origin}/?src=${encodeURIComponent(f)}` : f));
    }

    return jsonResponse({
      success: true,
      manifest: rewrittenManifest,
      subtitles: extractedSubtitles,
      fonts: extractedFonts,
      intro: intro,
      outro: outro
    });

  } catch (err) {
    console.error("[Flixcloud Stream Pipeline] Error:", err);
    return jsonResponse({
      success: false,
      error: err.message || "Failed to resolve Flixcloud media pipeline"
    }, 502);
  }
}

// -------------------------------------------------------------------------
// TRANSPARENT PROXY ENGINE (WITH FLIXCLOUD REFERER & RANGE FORWARDING)
// -------------------------------------------------------------------------
async function handleTransparentProxy(srcUrl, request, workerUrl) {
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Expose-Headers": "Content-Length, Content-Range, Accept-Ranges, Content-Type",
        "Access-Control-Max-Age": "86400",
      },
    });
  }

  let cleanSrcUrl = srcUrl;
  if (cleanSrcUrl && cleanSrcUrl.includes("src=")) {
    try {
      const parsed = new URL(cleanSrcUrl);
      if (parsed.searchParams.has("src")) {
        cleanSrcUrl = parsed.searchParams.get("src");
      }
    } catch (e) { }
  }

  const headers = new Headers();
  headers.set("Referer", "https://flixcloud.cc/");
  headers.set("Origin", "https://flixcloud.cc");
  headers.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36");
  headers.set("Accept", "*/*");
  headers.set("Sec-Fetch-Dest", "empty");
  headers.set("Sec-Fetch-Mode", "cors");
  headers.set("Sec-Fetch-Site", "cross-site");

  const rangeHeader = request.headers.get("Range") || request.headers.get("range");
  if (rangeHeader) {
    headers.set("Range", rangeHeader);
  }

  try {
    const upstreamResponse = await fetch(cleanSrcUrl, {
      method: request.method === "HEAD" ? "HEAD" : "GET",
      headers: headers,
    });

    const contentType = (upstreamResponse.headers.get("content-type") || "").toLowerCase();
    const isM3u8 = cleanSrcUrl.toLowerCase().includes(".m3u8") || contentType.includes("mpegurl");

    if (isM3u8 && upstreamResponse.status === 200 && request.method === "GET") {
      const playlistText = await upstreamResponse.text();
      const rewritten = rewriteM3u8Manifest(playlistText, cleanSrcUrl, workerUrl.origin);

      const playlistHeaders = new Headers(upstreamResponse.headers);
      playlistHeaders.set("Content-Type", "application/vnd.apple.mpegurl; charset=utf-8");
      playlistHeaders.set("Access-Control-Allow-Origin", "*");
      playlistHeaders.set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS");
      playlistHeaders.set("Access-Control-Allow-Headers", "*");
      playlistHeaders.set("Access-Control-Expose-Headers", "Content-Length, Content-Range, Accept-Ranges, Content-Type");
      playlistHeaders.set("Cache-Control", "no-cache, no-store, must-revalidate");
      playlistHeaders.delete("content-length");
      playlistHeaders.delete("content-encoding");
      playlistHeaders.delete("set-cookie");

      return new Response(rewritten, {
        status: 200,
        headers: playlistHeaders,
      });
    }

    const responseHeaders = new Headers(upstreamResponse.headers);
    responseHeaders.set("Access-Control-Allow-Origin", "*");
    responseHeaders.set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS");
    responseHeaders.set("Access-Control-Allow-Headers", "*");
    responseHeaders.set("Access-Control-Expose-Headers", "Content-Length, Content-Range, Accept-Ranges, Content-Type");
    responseHeaders.delete("content-encoding");
    responseHeaders.delete("set-cookie");

    const responseBody = request.method === "HEAD" ? null : upstreamResponse.body;

    return new Response(responseBody, {
      status: upstreamResponse.status,
      headers: responseHeaders,
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message, src: srcUrl }), {
      status: 502,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Expose-Headers": "Content-Length, Content-Range, Accept-Ranges, Content-Type"
      },
    });
  }
}

// -------------------------------------------------------------------------
// CAPTION VTT / ASS PROXY HANDLER (WITH IN-MEMORY CONVERSION)
// -------------------------------------------------------------------------
async function handleCaptionProxy(url, userAgent) {
  let targetSubUrl = url.searchParams.get("vtt_url") || url.searchParams.get("src") || url.searchParams.get("url");
  if (targetSubUrl && targetSubUrl.includes("src=")) {
    try {
      const parsedSub = new URL(targetSubUrl);
      if (parsedSub.searchParams.has("src")) {
        targetSubUrl = parsedSub.searchParams.get("src");
      }
    } catch (e) { }
  }
  if (!targetSubUrl) {
    return new Response(JSON.stringify({ error: "Missing subtitle url parameter" }), {
      status: 400,
      headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
    });
  }

  try {
    const subRes = await fetch(targetSubUrl, {
      headers: {
        'Referer': 'https://flixcloud.cc/',
        'Origin': 'https://flixcloud.cc',
        'User-Agent': userAgent || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"
      }
    });

    if (!subRes.ok) {
      return new Response("Failed to fetch subtitle track from upstream source.", {
        status: 502,
        headers: { "Access-Control-Allow-Origin": "*" }
      });
    }

    let subText = await subRes.text();
    const isAss = targetSubUrl.toLowerCase().endsWith('.ass') || targetSubUrl.toLowerCase().endsWith('.ssa') || subText.includes('[Script Info]');

    if (isAss) {
      subText = convertAssToVtt(subText);
    } else if (!subText.startsWith('WEBVTT')) {
      subText = `WEBVTT\n\n${subText.replace(/(\d{2}:\d{2}:\d{2}),(\d{3})/g, '$1.$2')}`;
    }

    return new Response(subText, {
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

// -------------------------------------------------------------------------
// RESOLVER: EMBED SCRAPER (EXTRACT SUBTITLES & FONTS DIRECTLY FROM FLIXCLOUD)
// -------------------------------------------------------------------------
async function handleEmbedSubtitlesExtraction(embedTarget, workerOrigin, userAgent) {
  if (!embedTarget) {
    return jsonResponse({ success: false, error: "Missing embed target or URL" }, 400);
  }

  let targetUrl = embedTarget;
  if (!targetUrl.startsWith('http')) {
    targetUrl = `https://flixcloud.cc/e/${embedTarget}?v=1`;
  }

  try {
    const res = await fetch(targetUrl, {
      headers: {
        'User-Agent': userAgent,
        'Referer': 'https://flixcloud.cc/'
      }
    });

    if (!res.ok) {
      return jsonResponse({ success: false, error: `Upstream returned status ${res.status}` }, 502);
    }

    const html = await res.text();

    // 1. Extract subtitles block
    let subtitles = [];
    const subMatch = html.match(/subtitles:\s*(\[\s*\{[\s\S]*?\}\s*\])/);
    if (subMatch) {
      try {
        subtitles = parseLooseJson(subMatch[1]) || [];
      } catch (e) { }
    }

    // 2. Extract fonts block for libass rendering
    let fonts = {};
    const fontMatch = html.match(/available_fonts:\s*(\{[\s\S]*?\})/);
    if (fontMatch) {
      try {
        fonts = parseLooseJson(fontMatch[1]) || {};
      } catch (e) { }
    }

    // 3. Format output with proxied VTT URLs for standard HTML5 players
    const formattedSubtitles = (subtitles || []).map(sub => ({
      label: sub.language,
      format: sub.format,
      default: Boolean(sub.default),
      rawUrl: sub.url,
      vttProxyUrl: `${workerOrigin}/?action=proxy_caption&src=${encodeURIComponent(sub.url)}`
    }));

    return jsonResponse({
      success: true,
      subtitles: formattedSubtitles,
      fonts: fonts
    });
  } catch (err) {
    return jsonResponse({ success: false, error: err.message }, 500);
  }
}

// -------------------------------------------------------------------------
// MANIFEST REWRITER (REWRITING SEGMENTS & TAG URIS TO PROXY)
// -------------------------------------------------------------------------
function rewriteM3u8Manifest(playlistText, targetUrl, workerOrigin) {
  if (!playlistText || typeof playlistText !== 'string') return '';
  const sanitizedText = playlistText.replace(/^\uFEFF/, '').trimStart();
  if (!sanitizedText) return '';

  let baseUrl = null;
  try {
    const parsedTarget = new URL(targetUrl);
    if (parsedTarget.searchParams.has("url")) {
      baseUrl = new URL(parsedTarget.searchParams.get("url"));
    } else {
      baseUrl = parsedTarget;
    }
  } catch (e) {
    return sanitizedText.startsWith('#EXTM3U') ? sanitizedText : `#EXTM3U\n${sanitizedText}`;
  }

  const cleanWorkerOrigin = (workerOrigin || '').replace(/\/+$/, '');

  const resolveTargetUri = (rawUri) => {
    if (!rawUri || typeof rawUri !== 'string') return '';
    const cleanUri = rawUri.trim();
    if (/^https?:\/\//i.test(cleanUri)) {
      return cleanUri;
    }
    try {
      return new URL(cleanUri, baseUrl).toString();
    } catch (e) {
      return cleanUri;
    }
  };

  const lines = sanitizedText.split(/\r?\n/);
  const rewrittenLines = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed) {
      if (rewrittenLines.length > 0) rewrittenLines.push('');
      continue;
    }

    if (trimmed.startsWith('#')) {
      if (/URI=/i.test(trimmed)) {
        const tagRewritten = trimmed.replace(/URI=["']([^"']+)["']/gi, (match, uri) => {
          if ((cleanWorkerOrigin && uri.startsWith(cleanWorkerOrigin)) || uri.startsWith('/?src=')) {
            return `URI="${uri}"`;
          }
          const absUrl = resolveTargetUri(uri);
          const proxiedUrl = `${cleanWorkerOrigin}/?src=${encodeURIComponent(absUrl)}`;
          return `URI="${proxiedUrl}"`;
        });
        rewrittenLines.push(tagRewritten);
        continue;
      }
      rewrittenLines.push(trimmed);
      continue;
    }

    // Segment URL line
    if ((cleanWorkerOrigin && trimmed.startsWith(cleanWorkerOrigin)) || trimmed.startsWith('/?src=')) {
      rewrittenLines.push(trimmed);
      continue;
    }

    const absSegmentUrl = resolveTargetUri(trimmed);
    rewrittenLines.push(`${cleanWorkerOrigin}/?src=${encodeURIComponent(absSegmentUrl)}`);
  }

  while (rewrittenLines.length > 0 && !rewrittenLines[0].trim()) {
    rewrittenLines.shift();
  }
  if (rewrittenLines.length === 0 || !rewrittenLines[0].startsWith('#EXTM3U')) {
    rewrittenLines.unshift('#EXTM3U');
  }

  return rewrittenLines.join('\n').replace(/^\uFEFF/, '').trimStart();
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
              if (ampm === 'PM' && hours < 12) hours += 12;
              else if (ampm === 'AM' && hours === 12) hours = 0;
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
            titleEn = titleMatch[2].replace(/<[^>]*>/g, '').trim();

            const jpMatch = titleDivTag.match(/data-jp=["']([^"']*)["']/i);
            if (jpMatch) titleJp = jpMatch[1].trim();
          }

          let image = '';
          const imgMatch = inner.match(/<img[^>]+(?:src|data-src|data-original)=["']([^"']*)["']/i);
          if (imgMatch) image = imgMatch[1].trim();

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

    payload.push({ day: dayName, timestamp: timestamp, shows: shows });
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
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
  });
}

// -------------------------------------------------------------------------
// FRANCHISE TREE FETCH (/comment)
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

  if (Array.isArray(rawSeasons)) return formatSeasonsArray(rawSeasons);
  return [];
}

function deserializeSvelteKit(flatData, idx) {
  if (idx === null || idx === undefined) return null;
  if (typeof idx !== 'number') return idx;
  if (idx < 0 || idx >= flatData.length) return idx;

  const val = flatData[idx];
  if (val === null || val === undefined) return null;
  if (typeof val !== 'object') return val;

  if (Array.isArray(val)) return val.map(item => deserializeSvelteKit(flatData, item));

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

export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env);
  }
};
