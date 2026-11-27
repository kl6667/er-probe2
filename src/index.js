// ticket 06 探測用 Worker(一次性,用完整個刪掉)。
// 需要的設定:Secret TURNSTILE_SECRET(在 Cloudflare 儀表板設定)、Rate Limiting 綁定 RL(wrangler.jsonc 已宣告)。

const json = (b, status = 200) =>
  new Response(JSON.stringify(b, null, 2), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname === "/") return new Response(PAGE, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
    if (url.pathname === "/verify" && req.method === "POST") return verify(req, env, url);
    if (url.pathname === "/rl") return rl(req, env, url);
    if (url.pathname === "/rlburst") return burst(req, env, url);
    if (url.pathname === "/envcheck") return json({ bindings: Object.keys(env), hasSecret: !!env.TURNSTILE_SECRET, secretLength: (env.TURNSTILE_SECRET || "").length, colo: req.cf?.colo });
    return new Response("not found", { status: 404 });
  },
};

async function verify(req, env, url) {
  if (!env.TURNSTILE_SECRET) return json({ error: "尚未設定 Secret TURNSTILE_SECRET", 這個Worker看得到的綁定名稱: Object.keys(env), 提示: "名稱必須完全是 TURNSTILE_SECRET,且要加在這個 Worker(er-probe)上;加完後要等新版本部署完成" }, 500);
  const { token } = await req.json().catch(() => ({ token: "" }));
  const form = new URLSearchParams({ secret: env.TURNSTILE_SECRET, response: token ?? "" });
  const ip = req.headers.get("cf-connecting-ip");
  if (ip) form.set("remoteip", ip);
  const t0 = Date.now();
  let status = 0, body = null, failure = null;
  try {
    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: form, signal: AbortSignal.timeout(5000) });
    status = res.status;
    body = await res.json();
  } catch (e) {
    failure = String(e);
  }
  const out = { pageHost: url.hostname, colo: req.cf?.colo, tokenLength: (token ?? "").length, siteverifyElapsedMs: Date.now() - t0, httpStatus: status, body, failure };
  console.log(JSON.stringify({ probe: "siteverify", ...out, body: body && { success: body.success, errors: body["error-codes"], hostname: body.hostname } }));
  return json(out);
}

async function rl(req, env, url) {
  if (!env.RL) return json({ error: "沒有 RL 綁定" }, 500);
  const key = url.searchParams.get("key") || "probe";
  const r = await env.RL.limit({ key });
  return json({ success: r.success, at: Date.now(), colo: req.cf?.colo });
}

async function burst(req, env, url) {
  if (!env.RL) return json({ error: "沒有 RL 綁定" }, 500);
  const key = url.searchParams.get("key") || "probe";
  const n = Math.min(50, Math.max(1, Number(url.searchParams.get("n")) || 20));
  const t0 = Date.now();
  const seq = [];
  for (let i = 0; i < n; i++) seq.push((await env.RL.limit({ key })).success ? "o" : "x");
  return json({ n, key, colo: req.cf?.colo, allowed: seq.filter((c) => c === "o").length, denied: seq.filter((c) => c === "x").length, sequence: seq.join(""), elapsedMs: Date.now() - t0 });
}

const PAGE = `<!doctype html><html lang="zh-Hant"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ticket 06 探測</title>
<style>body{font:14px system-ui;margin:16px;max-width:760px}button{margin:3px;padding:6px 10px}input{width:100%;padding:6px;box-sizing:border-box}pre{background:#111;color:#0f0;padding:10px;white-space:pre-wrap;min-height:200px}h3{margin:14px 0 4px}</style>
<h2>ticket 06 探測頁</h2>
<p>主機名稱:<b id="host"></b></p>
<label>Turnstile 網站金鑰(sitekey)<input id="sitekey" placeholder="0x4AAAA..."></label>

<h3>A. Turnstile</h3>
<button onclick="getToken()">1 取得新 token</button>
<button onclick="verifyStored()">2 驗證暫存的 token</button>
<button onclick="verifyRaw('')">3 驗證空 token</button>
<button onclick="verifyRaw('garbage-token')">4 驗證亂碼 token</button>

<h3>B. Rate Limiting(限額 5 次 / 10 秒)</h3>
<label>key<input id="key" value="probe"></label>
<button onclick="serverBurst()">5 Worker 內循序連打 20 次</button>
<button onclick="browserSeq()">6 瀏覽器循序連打 20 次</button>
<button onclick="browserPar()">7 瀏覽器平行連打 20 次</button>
<button onclick="single()">8 單次</button>

<h3>C. 第 21 張用的補充量測</h3>
<button onclick="timeline()">9 時間軸:每秒 1 次、共 25 秒(看視窗怎麼重置)</button>
<button onclick="twoKeys()">10 兩個不同 key 是否各自計數</button>
<button onclick="envcheck()">11 檢查 Worker 設定(不會顯示 secret 內容)</button>

<p><button onclick="navigator.clipboard.writeText(out.textContent)">複製全部結果</button> <button onclick="out.textContent=''">清除</button></p>
<pre id="out"></pre>
<script>
var out = document.getElementById("out"), stored = null, widgetId = null, pending = null;
document.getElementById("host").textContent = location.hostname;
document.getElementById("sitekey").value = localStorage.getItem("sk") || "";
function log(x) { out.textContent += "[" + new Date().toLocaleTimeString() + "] " + (typeof x === "string" ? x : JSON.stringify(x)) + "\\n"; }
function loadScript() {
  if (window.turnstile) return Promise.resolve();
  return new Promise(function (ok, bad) {
    var s = document.createElement("script");
    s.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    s.onload = ok; s.onerror = function () { bad(new Error("script blocked")); };
    document.head.appendChild(s);
  });
}
async function getToken() {
  var sk = document.getElementById("sitekey").value.trim();
  localStorage.setItem("sk", sk);
  if (!sk) return log("請先填 sitekey");
  var t0 = performance.now();
  try { await loadScript(); } catch (e) { return log("腳本載入失敗:" + e.message); }
  var token = await new Promise(function (resolve) {
    var timer = setTimeout(function () { resolve("(逾時 30 秒)"); }, 30000);
    var done = function (t) { clearTimeout(timer); resolve(t); };
    pending = done;
    if (widgetId === null) {
      var box = document.createElement("div"); document.body.appendChild(box);
      widgetId = turnstile.render(box, {
        sitekey: sk, execution: "execute", appearance: "interaction-only",
        callback: function (t) { pending(t); },
        "error-callback": function (c) { pending("(error-callback " + c + ")"); },
        "expired-callback": function () { pending("(expired-callback)"); }
      });
    } else { turnstile.reset(widgetId); }
    turnstile.execute(widgetId);
  });
  var ok = token.charAt(0) !== "(";
  stored = ok ? token : null;
  log({ step: "取得 token", ok: ok, acquireMs: Math.round(performance.now() - t0), tokenLength: token.length, note: ok ? "已暫存 " + new Date().toISOString() : token });
}
async function post(token, label) {
  var r = await fetch("/verify", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token: token }) });
  var j = await r.json();
  j.step = label; log(j);
}
function verifyStored() { if (!stored) return log("沒有暫存 token,先按 1"); return post(stored, "驗證暫存 token(重複按=重複使用;隔 5 分鐘以上再按=過期)"); }
function verifyRaw(t) { return post(t, t ? "驗證亂碼 token" : "驗證空 token"); }
function keyv() { return encodeURIComponent(document.getElementById("key").value || "probe"); }
async function serverBurst() { var r = await fetch("/rlburst?n=20&key=" + keyv()); var j = await r.json(); j.step = "Worker 內循序連打"; log(j); }
async function browserSeq() {
  var seq = "", colos = {}, t0 = performance.now();
  for (var i = 0; i < 20; i++) { var j = await (await fetch("/rl?key=" + keyv())).json(); seq += j.success ? "o" : "x"; colos[j.colo] = 1; }
  log({ step: "瀏覽器循序連打", sequence: seq, allowed: seq.split("o").length - 1, colos: Object.keys(colos), elapsedMs: Math.round(performance.now() - t0) });
}
async function browserPar() {
  var t0 = performance.now(), colos = {};
  var rs = await Promise.all(Array.from({ length: 20 }, function () { return fetch("/rl?key=" + keyv()).then(function (r) { return r.json(); }); }));
  var seq = rs.map(function (j) { colos[j.colo] = 1; return j.success ? "o" : "x"; }).join("");
  log({ step: "瀏覽器平行連打", sequence: seq, allowed: seq.split("o").length - 1, colos: Object.keys(colos), elapsedMs: Math.round(performance.now() - t0) });
}
async function timeline() {
  log("時間軸開始(25 秒,請不要切換分頁)。o=放行 x=拒絕");
  var line = "", t0 = Date.now();
  for (var i = 0; i < 25; i++) { var j = await (await fetch("/rl?key=timeline-" + t0)).json(); line += j.success ? "o" : "x"; if (i % 5 === 4) line += " "; await new Promise(function (r) { setTimeout(r, 1000); }); }
  log({ step: "時間軸(每秒 1 次,限額 5 次/10 秒)", sequence: line, allowed: line.split("o").length - 1 });
}
async function twoKeys() {
  var a = await (await fetch("/rlburst?n=10&key=A-" + Date.now())).json();
  var b = await (await fetch("/rlburst?n=10&key=B-" + Date.now())).json();
  log({ step: "兩個不同 key 各連打 10 次", A: a.sequence, B: b.sequence, 結論: a.allowed === b.allowed ? "各自獨立計數" : "不一致,請回報" });
}
async function envcheck() { var j = await (await fetch("/envcheck")).json(); j.step = "Worker 設定"; log(j); }
async function single() { var j = await (await fetch("/rl?key=" + keyv())).json(); j.step = "單次"; log(j); }
</script></html>`;
