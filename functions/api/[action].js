const OWNER = "nolc74";
const REPO = "moonlightlibrary.github.io";
const BRANCH = "main";
const COOKIE = "moon_admin";

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers }
  });
}
function b64url(bytes) {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
async function sign(value, secret) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64url(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value)));
}
async function validSession(request, env) {
  const raw = request.headers.get("Cookie") || "";
  const token = raw.split(";").map(x => x.trim()).find(x => x.startsWith(COOKIE + "="))?.slice(COOKIE.length + 1);
  if (!token || !env.SESSION_SECRET) return false;
  const [payload, sig] = token.split(".");
  if (!payload || !sig || await sign(payload, env.SESSION_SECRET) !== sig) return false;
  try { return JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/"))).exp > Date.now(); } catch { return false; }
}
function sameOrigin(request) {
  const origin = request.headers.get("Origin");
  return !origin || origin === new URL(request.url).origin;
}
async function github(path, env, options = {}) {
  return fetch("https://api.github.com" + path, {
    ...options,
    headers: {
      "Accept": "application/vnd.github+json",
      "Authorization": "Bearer " + env.GITHUB_TOKEN,
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "MoonlightLibrary",
      ...(options.headers || {})
    }
  });
}
export async function onRequest({ request, env }) {
  if (!sameOrigin(request)) return json({ error: "요청 출처가 올바르지 않습니다." }, 403);
  const url = new URL(request.url);
  if (request.method === "POST" && url.pathname.endsWith("/login")) {
    if (!env.ADMIN_PASSWORD || !env.SESSION_SECRET) return json({ error: "관리자 비밀번호 설정이 필요합니다." }, 503);
    const body = await request.json().catch(() => ({}));
    if (typeof body.password !== "string" || body.password.length > 200 || body.password !== env.ADMIN_PASSWORD) {
      return json({ error: "비밀번호가 올바르지 않습니다." }, 401);
    }
    const payload = b64url(new TextEncoder().encode(JSON.stringify({ exp: Date.now() + 8 * 60 * 60 * 1000 })));
    const token = payload + "." + await sign(payload, env.SESSION_SECRET);
    return json({ ok: true }, 200, { "Set-Cookie": COOKIE + "=" + token + "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800" });
  }
  if (request.method === "POST" && url.pathname.endsWith("/logout")) {
    return json({ ok: true }, 200, { "Set-Cookie": COOKIE + "=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0" });
  }
  if (request.method === "GET" && url.pathname.endsWith("/novels")) {
    const r = await github("/repos/" + OWNER + "/" + REPO + "/contents/novels.json?ref=" + BRANCH, env);
    if (r.status === 404) return json({ novels: null });
    if (!r.ok) return json({ error: "작품 데이터를 불러오지 못했습니다." }, 502);
    const file = await r.json();
    if (!file.content) return json({ error: "작품 데이터가 비어 있습니다." }, 502);
    const binary = atob(file.content.replace(/\\s/g, ""));
    const bytes = Uint8Array.from(binary, ch => ch.charCodeAt(0));
    const content = new TextDecoder().decode(bytes);
    return new Response(content, { headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
  }
  if (request.method === "PUT" && url.pathname.endsWith("/novels")) {
    if (!await validSession(request, env)) return json({ error: "관리자 로그인이 필요합니다." }, 401);
    if (!env.GITHUB_TOKEN) return json({ error: "Cloudflare에 GitHub 토큰 설정이 필요합니다." }, 503);
    const body = await request.json().catch(() => null);
    if (!body || !Array.isArray(body.novels)) return json({ error: "저장할 작품 데이터가 올바르지 않습니다." }, 400);
    const content = JSON.stringify({ novels: body.novels }, null, 2);
    const existing = await github("/repos/" + OWNER + "/" + REPO + "/contents/novels.json?ref=" + BRANCH, env);
    let sha;
    if (existing.ok) sha = (await existing.json()).sha;
    else if (existing.status !== 404) return json({ error: "GitHub 저장소를 확인할 수 없습니다." }, 502);
    const bytes = new TextEncoder().encode(content);
    let binary = "";
    for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    const payload = { message: "달무리책방 작품 및 회차 업데이트", content: btoa(binary), branch: BRANCH, ...(sha ? { sha } : {}) };
    const saved = await github("/repos/" + OWNER + "/" + REPO + "/contents/novels.json", env, {
      method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(payload)
    });
    if (!saved.ok) return json({ error: "GitHub 저장에 실패했습니다. 토큰의 Contents 쓰기 권한을 확인해 주세요." }, 502);
    return json({ ok: true });
  }
  return json({ error: "Not found" }, 404);
}
