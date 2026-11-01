const COOKIE = "sc_session";
const SESSION_DAYS = 7;
const ITERATIONS = 310000;

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...headers
    }
  });

const fail = (message, status = 400) =>
  json({ ok: false, error: message }, status);

const id = () => crypto.randomUUID();

function cookie(token, maxAge = SESSION_DAYS * 86400) {
  return `${COOKIE}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

async function hash(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function passwordHash(password, salt) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    salt: new TextEncoder().encode(salt),
    iterations: ITERATIONS,
    hash: "SHA-256"
  }, key, 256);

  return [...new Uint8Array(bits)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function body(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function validUsername(name) {
  return typeof name === "string" &&
    /^[a-zA-Z0-9 _-]{3,24}$/.test(name);
}

function validPassword(password) {
  return typeof password === "string" &&
    password.length >= 10 &&
    password.length <= 128;
}

async function currentUser(request, env) {
  const raw = request.headers.get("Cookie") || "";
  const match = raw.match(/(?:^|;\s*)sc_session=([a-f0-9]{64})/);

  if (!match) return null;

  const tokenHash = await hash(match[1]);
  const now = Math.floor(Date.now() / 1000);

  const result = await env.DB.prepare(`
    SELECT users.id, users.username, users.role,
           users.bio, users.avatar, users.level, users.xp
    FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ?
      AND sessions.expires_at > ?
  `).bind(tokenHash, now).first();

  return result || null;
}

async function requireUser(request, env) {
  const user = await currentUser(request, env);
  return user || false;
}

async function requireOwner(request, env) {
  const user = await requireUser(request, env);
  return user && user.role === "owner" ? user : false;
}

async function log(env, actor, action, details = "") {
  await env.DB.prepare(`
    INSERT INTO admin_logs (id, actor_id, action, details)
    VALUES (?, ?, ?, ?)
  `).bind(id(), actor?.id || null, action, details.slice(0, 500)).run();
}

async function activity(env, user, action, details = "") {
  await env.DB.prepare(`
    INSERT INTO activity (id, user_id, action, details)
    VALUES (?, ?, ?, ?)
  `).bind(id(), user.id, action, details.slice(0, 500)).run();
}

async function createSession(user, env) {
  const token = [...crypto.getRandomValues(new Uint8Array(32))]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  const tokenHash = await hash(token);
  const expires = Math.floor(Date.now() / 1000) +
    SESSION_DAYS * 86400;

  await env.DB.prepare(`
    INSERT INTO sessions (token_hash, user_id, expires_at)
    VALUES (?, ?, ?)
  `).bind(tokenHash, user.id, expires).run();

  return cookie(token);
}

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api\/?/, "");
  const method = request.method;

  if (!env.DB) return fail("La base de datos DB no está conectada.", 500);

  // Evita peticiones de escritura desde otros sitios.
  if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
    const origin = request.headers.get("Origin");
    if (origin && origin !== url.origin) {
      return fail("Origen no permitido.", 403);
    }
  }

  try {
    if (method === "GET" && path === "me") {
      const user = await currentUser(request, env);
      return json({ ok: true, user });
    }

    if (method === "POST" && path === "register") {
      const data = await body(request);
      if (!data) return fail("Datos inválidos.");

      const username = String(data.username || "").trim();
      const password = data.password;

      if (!validUsername(username)) {
        return fail("El usuario debe tener entre 3 y 24 caracteres.");
      }

      if (!validPassword(password)) {
        return fail("La contraseña debe tener al menos 10 caracteres.");
      }

      const existing = await env.DB.prepare(
        "SELECT id FROM users WHERE username = ? COLLATE NOCASE"
      ).bind(username).first();

      if (existing) return fail("Ese nombre de usuario ya existe.", 409);

      const salt = [...crypto.getRandomValues(new Uint8Array(16))]
        .map(b => b.toString(16).padStart(2, "0")).join("");

      const derived = await passwordHash(password, salt);
      const userId = id();

      await env.DB.prepare(`
        INSERT INTO users (id, username, password_hash, password_salt)
        VALUES (?, ?, ?, ?)
      `).bind(userId, username, derived, salt).run();

      const user = await env.DB.prepare(
        "SELECT id, username, role FROM users WHERE id = ?"
      ).bind(userId).first();

      await activity(env, user, "Registro", "Cuenta creada");
      await log(env, user, "user.register", "Nueva cuenta registrada");

      const sessionCookie = await createSession(user, env);

      return json({ ok: true, user }, 201, {
        "Set-Cookie": sessionCookie
      });
    }

    if (method === "POST" && path === "login") {
      const data = await body(request);
      if (!data) return fail("Datos inválidos.");

      const username = String(data.username || "").trim();
      const password = data.password;

      if (!username || typeof password !== "string") {
        return fail("Completá todos los campos.");
      }

      const user = await env.DB.prepare(`
        SELECT id, username, role, password_hash, password_salt
        FROM users
        WHERE username = ? COLLATE NOCASE
      `).bind(username).first();

      if (!user) return fail("Usuario o contraseña incorrectos.", 401);

      const derived = await passwordHash(password, user.password_salt);

      if (derived !== user.password_hash) {
        return fail("Usuario o contraseña incorrectos.", 401);
      }

      const sessionCookie = await createSession(user, env);
      await activity(env, user, "Inicio de sesión");

      return json({
        ok: true,
        user: {
          id: user.id,
          username: user.username,
          role: user.role
        }
      }, 200, { "Set-Cookie": sessionCookie });
    }

    if (method === "POST" && path === "logout") {
      const raw = request.headers.get("Cookie") || "";
      const match = raw.match(/(?:^|;\s*)sc_session=([a-f0-9]{64})/);

      if (match) {
        await env.DB.prepare(
          "DELETE FROM sessions WHERE token_hash = ?"
        ).bind(await hash(match[1])).run();
      }

      return json({ ok: true }, 200, {
        "Set-Cookie": cookie("", 0)
      });
    }

    const user = await requireUser(request, env);
    if (!user) return fail("Iniciá sesión para continuar.", 401);

    if (method === "GET" && path === "servers") {
      const rows = await env.DB.prepare(`
        SELECT s.*,
          (SELECT COUNT(*) FROM favorites f WHERE f.server_id = s.id) AS favorites_count,
          (SELECT ROUND(AVG(r.rating), 1) FROM reviews r WHERE r.server_id = s.id) AS rating,
          (SELECT COUNT(*) FROM reviews r WHERE r.server_id = s.id) AS reviews_count
        FROM servers s
        WHERE s.disabled = 0
        ORDER BY s.verified DESC, s.created_at DESC
      `).all();

      return json({ ok: true, servers: rows.results });
    }

    if (method === "POST" && path === "servers") {
      const data = await body(request);
      if (!data) return fail("Datos inválidos.");

      const name = String(data.name || "").trim();
      const ip = String(data.ip || "").trim().toLowerCase();
      const edition = data.edition;
      const mode = String(data.mode || "Survival");
      const description = String(data.description || "").trim();

      if (name.length < 2 || name.length > 50) return fail("Nombre inválido.");
      if (!/^[a-z0-9.-]{3,253}$/i.test(ip)) return fail("IP inválida.");
      if (!["Java", "Bedrock", "Crossplay"].includes(edition)) {
        return fail("Edición inválida.");
      }
      if (description.length > 500) return fail("Descripción demasiado larga.");

      const port = Number(data.port || (edition === "Java" ? 25565 : 19132));
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        return fail("Puerto inválido.");
      }

      const serverId = id();

      await env.DB.prepare(`
        INSERT INTO servers
          (id, owner_id, name, ip, port, edition, mode, description, banner)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        serverId, user.id, name, ip, port, edition,
        mode.slice(0, 30), description, String(data.banner || "").slice(0, 500)
      ).run();

      await activity(env, user, "Publicó servidor", name);
      await log(env, user, "server.create", name);

      return json({ ok: true, id: serverId }, 201);
    }

    if (method === "POST" && path === "favorite") {
      const data = await body(request);
      if (!data?.serverId) return fail("Servidor inválido.");

      const exists = await env.DB.prepare(
        "SELECT id FROM servers WHERE id = ? AND disabled = 0"
      ).bind(data.serverId).first();

      if (!exists) return fail("Servidor no encontrado.", 404);

      const favorite = await env.DB.prepare(`
        SELECT 1 FROM favorites WHERE user_id = ? AND server_id = ?
      `).bind(user.id, data.serverId).first();

      if (favorite) {
        await env.DB.prepare(
          "DELETE FROM favorites WHERE user_id = ? AND server_id = ?"
        ).bind(user.id, data.serverId).run();
      } else {
        await env.DB.prepare(
          "INSERT INTO favorites (user_id, server_id) VALUES (?, ?)"
        ).bind(user.id, data.serverId).run();
      }

      return json({ ok: true, favorite: !favorite });
    }

    if (method === "GET" && path === "favorites") {
      const rows = await env.DB.prepare(`
        SELECT s.* FROM favorites f
        JOIN servers s ON s.id = f.server_id
        WHERE f.user_id = ? AND s.disabled = 0
        ORDER BY f.created_at DESC
      `).bind(user.id).all();

      return json({ ok: true, servers: rows.results });
    }

    if (method === "POST" && path === "report") {
      const data = await body(request);
      if (!data?.serverId) return fail("Servidor inválido.");

      const reason = String(data.reason || "").trim();
      if (reason.length < 5 || reason.length > 500) {
        return fail("Explicá el motivo del reporte.");
      }

      const exists = await env.DB.prepare(
        "SELECT id FROM servers WHERE id = ?"
      ).bind(data.serverId).first();

      if (!exists) return fail("Servidor no encontrado.", 404);

      await env.DB.prepare(`
        INSERT INTO reports (id, user_id, server_id, reason)
        VALUES (?, ?, ?, ?)
      `).bind(id(), user.id, data.serverId, reason).run();

      await activity(env, user, "Reportó servidor", data.serverId);

      return json({ ok: true });
    }

    if (method === "POST" && path === "review") {
      const data = await body(request);
      const rating = Number(data?.rating);

      if (!data?.serverId || !Number.isInteger(rating) ||
          rating < 1 || rating > 5) {
        return fail("Valoración inválida.");
      }

      const comment = String(data.comment || "").trim();
      if (comment.length > 500) return fail("Comentario demasiado largo.");

      await env.DB.prepare(`
        INSERT INTO reviews (id, user_id, server_id, rating, comment)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(user_id, server_id)
        DO UPDATE SET rating = excluded.rating, comment = excluded.comment
      `).bind(id(), user.id, data.serverId, rating, comment).run();

      await activity(env, user, "Valoró servidor", data.serverId);
      return json({ ok: true });
    }

    if (method === "GET" && path === "profile") {
      const rows = await env.DB.prepare(`
        SELECT id, action, details, created_at
        FROM activity WHERE user_id = ?
        ORDER BY created_at DESC LIMIT 50
      `).bind(user.id).all();

      return json({ ok: true, user, activity: rows.results });
    }

    if (method === "GET" && path === "notifications") {
      const rows = await env.DB.prepare(`
        SELECT * FROM notifications
        WHERE user_id = ? ORDER BY created_at DESC LIMIT 50
      `).bind(user.id).all();

      return json({ ok: true, notifications: rows.results });
    }

    if (method === "POST" && path === "comment") {
      const data = await body(request);
      const content = String(data?.content || "").trim();

      if (!data?.serverId || content.length < 2 || content.length > 500) {
        return fail("Comentario inválido.");
      }

      await env.DB.prepare(`
        INSERT INTO comments (id, user_id, server_id, content)
        VALUES (?, ?, ?, ?)
      `).bind(id(), user.id, data.serverId, content).run();

      return json({ ok: true });
    }

    if (method === "GET" && path === "comments") {
      const serverId = url.searchParams.get("serverId");
      if (!serverId) return fail("Falta el servidor.");

      const rows = await env.DB.prepare(`
        SELECT c.id, c.content, c.created_at, u.username
        FROM comments c JOIN users u ON u.id = c.user_id
        WHERE c.server_id = ?
        ORDER BY c.created_at DESC LIMIT 50
      `).bind(serverId).all();

      return json({ ok: true, comments: rows.results });
    }

    // Administración: todas las rutas siguientes requieren owner.
    if (path.startsWith("admin/")) {
      const owner = await requireOwner(request, env);
      if (!owner) return fail("No tenés permisos de administrador.", 403);

      if (method === "GET" && path === "admin/stats") {
        const queries = await Promise.all([
          env.DB.prepare("SELECT COUNT(*) AS n FROM users").first(),
          env.DB.prepare("SELECT COUNT(*) AS n FROM servers").first(),
          env.DB.prepare("SELECT COUNT(*) AS n FROM reports WHERE status='pending'").first(),
          env.DB.prepare("SELECT COUNT(*) AS n FROM reviews").first()
        ]);

        return json({
          ok: true,
          users: queries[0].n,
          servers: queries[1].n,
          pendingReports: queries[2].n,
          reviews: queries[3].n
        });
      }

      if (method === "GET" && path === "admin/users") {
        const rows = await env.DB.prepare(`
          SELECT id, username, role, level, xp, created_at
          FROM users ORDER BY created_at DESC LIMIT 200
        `).all();
        return json({ ok: true, users: rows.results });
      }

      if (method === "GET" && path === "admin/reports") {
        const rows = await env.DB.prepare(`
          SELECT r.*, u.username, s.name AS server_name
          FROM reports r
          JOIN users u ON u.id = r.user_id
          JOIN servers s ON s.id = r.server_id
          ORDER BY r.created_at DESC LIMIT 200
        `).all();
        return json({ ok: true, reports: rows.results });
      }

      if (method === "GET" && path === "admin/logs") {
        const rows = await env.DB.prepare(`
          SELECT l.*, u.username
          FROM admin_logs l
          LEFT JOIN users u ON u.id = l.actor_id
          ORDER BY l.created_at DESC LIMIT 200
        `).all();
        return json({ ok: true, logs: rows.results });
      }

      if (method === "POST" && path === "admin/server-status") {
        const data = await body(request);
        if (!data?.serverId) return fail("Servidor inválido.");

        await env.DB.prepare(
          "UPDATE servers SET disabled = ? WHERE id = ?"
        ).bind(data.disabled ? 1 : 0, data.serverId).run();

        await log(env, owner, "server.status", data.serverId);
        return json({ ok: true });
      }

      if (method === "POST" && path === "admin/report-status") {
        const data = await body(request);
        if (!data?.reportId || !["pending", "reviewed", "rejected"].includes(data.status)) {
          return fail("Estado inválido.");
        }

        await env.DB.prepare(
          "UPDATE reports SET status = ? WHERE id = ?"
        ).bind(data.status, data.reportId).run();

        await log(env, owner, "report.status", data.reportId);
        return json({ ok: true });
      }

      if (method === "GET" && path === "admin/servers") {
        const rows = await env.DB.prepare(
          "SELECT * FROM servers ORDER BY created_at DESC LIMIT 300"
        ).all();
        return json({ ok: true, servers: rows.results });
      }

      return fail("Ruta administrativa no encontrada.", 404);
    }

    return fail("Ruta no encontrada.", 404);

  } catch (error) {
    console.error("ServerCraft API error:", error);
    return fail("Error interno. Intentá nuevamente.", 500);
  }
}
