// @bun
// src/index.ts
import { exec } from "child_process";
import { promisify } from "util";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import http from "http";
import https from "https";
import os from "os";
var execAsync = promisify(exec);
var PROVIDER_ID = "deveco";
var BASE_URL = "https://cn.devecostudio.huawei.com";
var API_BASE = `${BASE_URL}/sse/codeGenie/maas/v2`;
var MODEL_CONFIG_URL = `${BASE_URL}/codeGenie/modelConfig`;
var OAUTH_DUMMY_KEY = "opencode-oauth-dummy-key";
var ACCESS_TOKEN_EXPIRES_MS = 30 * 60 * 1000;
var APP_ID = "1008";
var PLUGIN_VERSION = "0.1.0";
var AUTH_URL = `${BASE_URL}/console/DevEcoIDE/apply`;
var TEMP_TOKEN_CHECK_URL = `${BASE_URL}/authrouter/auth/api/temptoken/check`;
var JWT_CHECK_URL = `${BASE_URL}/authrouter/auth/api/jwToken/check`;
var SUCCESS_REDIRECT = `${BASE_URL}/console/DevEcoCode/loginSuccess`;
var FAILED_REDIRECT = `${BASE_URL}/console/DevEcoCode/loginFailed`;
var CONFIG_DIR = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config", "opencode");
var PLUGIN_DIR = path.join(CONFIG_DIR, "opencode-deveco-auth");
var JWT_FILE = path.join(PLUGIN_DIR, "jwt.json");
var LOG_FILE = path.join(PLUGIN_DIR, "plugin.log");
var DEFAULT_PORT = 10101;
var CALLBACK_TIMEOUT = 600000;
var DEVECO_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
var logDirReady = false;
function log(level, msg, extra) {
  try {
    if (!logDirReady) {
      fs.mkdirSync(PLUGIN_DIR, { recursive: true });
      logDirReady = true;
    }
    const ts = new Date().toISOString();
    const payload = extra ? ` ${JSON.stringify(extra)}` : "";
    fs.appendFileSync(LOG_FILE, `[${ts}] [${level.toUpperCase()}] ${msg}${payload}
`);
  } catch {}
}
var cachedJwt = undefined;
function saveJwtToken(token) {
  fs.mkdirSync(PLUGIN_DIR, { recursive: true });
  fs.writeFileSync(JWT_FILE, JSON.stringify({ jwtToken: token, savedAt: Date.now() }, null, 2), { mode: 384 });
  cachedJwt = token;
}
function loadJwtToken() {
  if (cachedJwt !== undefined)
    return cachedJwt;
  try {
    if (!fs.existsSync(JWT_FILE)) {
      cachedJwt = null;
      return null;
    }
    const data = JSON.parse(fs.readFileSync(JWT_FILE, "utf8"));
    cachedJwt = typeof data.jwtToken === "string" ? data.jwtToken : null;
    return cachedJwt;
  } catch {
    cachedJwt = null;
    return null;
  }
}
function httpRequest(url, opts) {
  const search = opts?.params ? "?" + new URLSearchParams(opts.params).toString() : "";
  const fullUrl = url + search;
  const parsed = new URL(fullUrl);
  const mod = parsed.protocol === "https:" ? https : http;
  const headers = {
    "User-Agent": DEVECO_UA,
    "accept-language": "zh-CN",
    ...opts?.headers
  };
  return new Promise((resolve, reject) => {
    const req = mod.request(fullUrl, { method: opts?.method ?? "GET", headers, timeout: opts?.timeout ?? 20000 }, (res) => {
      let data = "";
      res.on("data", (chunk) => data += chunk);
      res.on("end", () => resolve({ data, status: res.statusCode ?? 0 }));
    });
    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("Request timeout"));
    });
    req.end();
  });
}
var refreshInFlight = null;
var memAccessToken = null;
var memTokenExpiry = 0;
async function doRefresh() {
  const jwt = loadJwtToken();
  if (!jwt) {
    log("error", "Token refresh: no jwtToken on disk");
    return null;
  }
  try {
    const resp = await httpRequest(JWT_CHECK_URL, { headers: { refresh: "true", jwtToken: jwt } });
    if (resp.status !== 200) {
      log("error", "Token refresh HTTP error", { status: resp.status });
      return null;
    }
    const result = JSON.parse(resp.data);
    if (!result.status || !result.userInfo) {
      log("error", "Token refresh invalid response");
      return null;
    }
    memAccessToken = result.userInfo.accessToken;
    memTokenExpiry = Date.now() + ACCESS_TOKEN_EXPIRES_MS;
    log("info", "Access token refreshed");
    return memAccessToken;
  } catch (err) {
    log("error", "Token refresh error", { error: err instanceof Error ? err.message : String(err) });
    return null;
  }
}
function refreshToken() {
  if (refreshInFlight)
    return refreshInFlight;
  refreshInFlight = doRefresh().finally(() => {
    refreshInFlight = null;
  });
  return refreshInFlight;
}
async function getValidAccessToken(auth) {
  if (auth?.type === "oauth" && auth.access) {
    if (!auth.expires || auth.expires > Date.now())
      return auth.access;
  }
  if (memAccessToken && memTokenExpiry > Date.now())
    return memAccessToken;
  return refreshToken();
}
var MODEL_CACHE_FILE = path.join(PLUGIN_DIR, "model-cache.json");
var MODEL_CACHE_TTL_MS = 25 * 60 * 1000;
var cachedModels = null;
function readModelCache(staleOk = false) {
  try {
    if (!fs.existsSync(MODEL_CACHE_FILE))
      return null;
    const entry = JSON.parse(fs.readFileSync(MODEL_CACHE_FILE, "utf8"));
    if (!staleOk && Date.now() - entry.savedAt > MODEL_CACHE_TTL_MS)
      return null;
    return entry.models;
  } catch {
    return null;
  }
}
function writeModelCache(models) {
  try {
    fs.mkdirSync(PLUGIN_DIR, { recursive: true });
    const entry = { models, savedAt: Date.now() };
    fs.writeFileSync(MODEL_CACHE_FILE, JSON.stringify(entry, null, 2), { mode: 384 });
  } catch {}
}
async function fetchModels(accessToken) {
  try {
    const resp = await httpRequest(`${MODEL_CONFIG_URL}?localVersion=0&pluginVersion=CLI.${PLUGIN_VERSION}`, { headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" }, timeout: 1e4 });
    if (resp.status !== 200) {
      log("warn", "Model config HTTP error", { status: resp.status });
      return null;
    }
    const raw = JSON.parse(resp.data);
    if (raw.code !== 200) {
      log("warn", "Model config API error", { code: raw.code });
      return null;
    }
    const models = {};
    for (const group of raw.body?.inner_models ?? []) {
      for (const cfg of group.model_configs ?? []) {
        const model = { name: cfg.model_id };
        if (cfg.thinking_mode === "on")
          model.reasoning = true;
        model.tool_call = true;
        if (cfg.context_window) {
          model.limit = { context: cfg.context_window };
          const out = typeof cfg.output === "number" ? cfg.output : parseInt(cfg.output, 10);
          if (!isNaN(out))
            model.limit.output = out;
        }
        if (cfg.input_modalities?.length > 0) {
          model.modalities = { input: cfg.input_modalities, output: ["text"] };
        }
        models[cfg.model_id] = model;
      }
    }
    if (Object.keys(models).length === 0)
      return null;
    log("info", "Fetched models", { count: Object.keys(models).length, ids: Object.keys(models) });
    return models;
  } catch (err) {
    log("error", "Model fetch error", { error: err instanceof Error ? err.message : String(err) });
    return null;
  }
}
async function discoverModels() {
  if (cachedModels)
    return cachedModels;
  const fileCached = readModelCache(false);
  if (fileCached) {
    cachedModels = fileCached;
    log("info", "Model cache hit (file)", { count: Object.keys(fileCached).length });
    return fileCached;
  }
  const jwt = loadJwtToken();
  if (jwt) {
    try {
      const token = await refreshToken();
      if (token) {
        const dynamic = await fetchModels(token);
        if (dynamic) {
          cachedModels = dynamic;
          writeModelCache(dynamic);
          return dynamic;
        }
      }
    } catch {}
  }
  const stale = readModelCache(true);
  if (stale) {
    cachedModels = stale;
    log("warn", "Using stale model cache (HTTP failed)", { count: Object.keys(stale).length });
    return stale;
  }
  const bootstrap = { "GLM-5.1": { name: "GLM-5.1", reasoning: true, tool_call: true } };
  return bootstrap;
}
function startLocalAuthServer(port, clientSecret) {
  const ports = [port, 34567, 34568, 34569, 34570];
  return new Promise(async (resolve, reject) => {
    for (const p of ports) {
      try {
        resolve(await tryPort(p, clientSecret));
        return;
      } catch {
        if (p === ports[ports.length - 1])
          reject(new Error("All auth ports are in use"));
      }
    }
  });
}
function tryPort(port, clientSecret) {
  return new Promise((resolve, reject) => {
    let resolveCb;
    let rejectCb;
    const callbackPromise = new Promise((res, rej) => {
      resolveCb = res;
      rejectCb = rej;
    });
    const timer = setTimeout(() => rejectCb(new Error("Login callback timeout")), CALLBACK_TIMEOUT);
    const server = http.createServer((req, res) => {
      const host = req.headers.host || `localhost:${port}`;
      const url = new URL(req.url ?? "", `http://${host}`);
      if (url.pathname !== "/callback") {
        res.writeHead(404);
        res.end("Not Found");
        return;
      }
      const urlParams = url.searchParams;
      if (req.method === "POST") {
        let body = "";
        req.on("data", (chunk) => body += chunk.toString());
        req.on("end", () => processCallback(urlParams, body));
      } else {
        processCallback(urlParams, "");
      }
      function processCallback(urlParams2, body) {
        const params = body && body.trim() ? new URLSearchParams(body) : urlParams2;
        const code = params.get("code");
        const tempToken = params.get("tempToken");
        const siteId = params.get("siteId");
        const quit = params.get("quit");
        if (!code || code !== clientSecret)
          return;
        if (quit === "true" || quit === "access_denied") {
          rejectCb(new Error(quit === "access_denied" ? "Access denied" : "Login cancelled"));
          res.writeHead(302, { Location: FAILED_REDIRECT });
          res.end();
          return;
        }
        if (!tempToken || !siteId) {
          rejectCb(new Error("Missing tempToken or siteId"));
          res.writeHead(302, { Location: FAILED_REDIRECT });
          res.end();
          return;
        }
        if (siteId !== "1") {
          rejectCb(new Error("Only China site accounts are supported"));
          res.writeHead(302, { Location: FAILED_REDIRECT });
          res.end();
          return;
        }
        clearTimeout(timer);
        resolveCb({ tempToken: tempToken.split("&")[0], siteId });
        res.writeHead(302, { Location: SUCCESS_REDIRECT });
        res.end();
      }
    });
    server.on("error", (err) => {
      if (err.code === "EADDRINUSE")
        reject(new Error("Port in use"));
      else
        reject(err);
    });
    server.listen(port, "127.0.0.1", () => resolve({ server, port, callbackPromise }));
  });
}
async function loginWithHuawei() {
  const clientSecret = crypto.randomUUID().replace(/-/g, "");
  let authServer;
  try {
    authServer = await startLocalAuthServer(DEFAULT_PORT, clientSecret);
  } catch (err) {
    return { success: false, error: `Failed to start auth server: ${err}` };
  }
  try {
    const loginUrl = `${AUTH_URL}?port=${authServer.port}&appid=${APP_ID}&code=${clientSecret}`;
    const platform = process.platform;
    const cmd = platform === "win32" ? `start "" "${loginUrl}"` : platform === "darwin" ? `open "${loginUrl}"` : `xdg-open "${loginUrl}"`;
    try {
      await execAsync(cmd);
    } catch {
      log("warn", "Failed to auto-open browser, open manually", { url: loginUrl });
    }
    log("info", "Waiting for callback", { port: authServer.port });
    const { tempToken } = await authServer.callbackPromise;
    const tempResp = await httpRequest(TEMP_TOKEN_CHECK_URL, {
      params: { tempToken, site: "CN", version: "1.0.0", appid: APP_ID }
    });
    if (tempResp.status !== 200)
      return { success: false, error: `tempToken check failed: HTTP ${tempResp.status}` };
    const jwtToken = tempResp.data.trim();
    if (jwtToken.split(".").length !== 3)
      return { success: false, error: "Invalid jwtToken format" };
    const jwtResp = await httpRequest(JWT_CHECK_URL, { headers: { refresh: "false", jwtToken } });
    if (jwtResp.status !== 200)
      return { success: false, error: `jwtToken check failed: HTTP ${jwtResp.status}` };
    const tokenInfo = JSON.parse(jwtResp.data);
    if (!tokenInfo.status || !tokenInfo.userInfo) {
      return { success: false, error: "Invalid jwtToken: missing userInfo" };
    }
    const accessToken = tokenInfo.userInfo.accessToken;
    saveJwtToken(jwtToken);
    memAccessToken = accessToken;
    memTokenExpiry = Date.now() + ACCESS_TOKEN_EXPIRES_MS;
    cachedModels = null;
    try {
      fs.unlinkSync(MODEL_CACHE_FILE);
    } catch {}
    log("info", "Login successful");
    return { success: true, accessToken, refreshToken: tokenInfo.userInfo.refreshToken ?? "", jwtToken };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes("cancelled") || msg.includes("denied")) {
      return { success: false, cancelled: true, error: msg };
    }
    log("error", "Login error", { error: msg });
    return { success: false, error: msg };
  } finally {
    authServer.server.close();
  }
}
var src_default = {
  id: "opencode-deveco-auth",
  async server(input) {
    const sessionChatIdMap = new Map;
    return {
      async config(cfg) {
        if (!cfg.provider)
          cfg.provider = {};
        if (!cfg.provider[PROVIDER_ID]) {
          const models = await discoverModels();
          cfg.provider[PROVIDER_ID] = {
            name: "DevEco Code",
            npm: "@ai-sdk/openai-compatible",
            options: { baseURL: API_BASE },
            models
          };
          log("info", "Injected deveco provider", { models: Object.keys(models) });
        }
      },
      auth: {
        provider: PROVIDER_ID,
        async loader(getAuth) {
          return {
            apiKey: OAUTH_DUMMY_KEY,
            async fetch(requestInput, init) {
              const currentAuth = await getAuth();
              if (currentAuth?.type !== "oauth") {
                return new Response(JSON.stringify({ error: "DevEco Code not authenticated. Run: opencode auth login --provider deveco" }), { status: 401, headers: { "Content-Type": "application/json" } });
              }
              const token = await getValidAccessToken(currentAuth);
              if (!token) {
                return new Response(JSON.stringify({ error: "DevEco token refresh failed. Please re-login." }), { status: 401, headers: { "Content-Type": "application/json" } });
              }
              if (token !== currentAuth.access) {
                await input.client.auth.set({
                  path: { id: PROVIDER_ID },
                  body: {
                    type: "oauth",
                    access: token,
                    refresh: currentAuth.refresh ?? "",
                    expires: memTokenExpiry
                  }
                });
              }
              const headers = new Headers;
              if (init?.headers) {
                if (init.headers instanceof Headers) {
                  init.headers.forEach((v, k) => {
                    if (k.toLowerCase() !== "authorization")
                      headers.set(k, v);
                  });
                } else if (Array.isArray(init.headers)) {
                  for (const [k, v] of init.headers) {
                    if (k.toLowerCase() !== "authorization" && v !== undefined)
                      headers.set(k, String(v));
                  }
                } else {
                  for (const [k, v] of Object.entries(init.headers)) {
                    if (k.toLowerCase() !== "authorization" && v !== undefined)
                      headers.set(k, String(v));
                  }
                }
              }
              headers.set("authorization", `Bearer ${token}`);
              headers.set("lang", "en");
              const sessionId = headers.get("x-deveco-session") || headers.get("x-session-affinity");
              const chatId = sessionId && sessionChatIdMap.get(sessionId) || crypto.randomUUID().replace(/-/g, "");
              headers.set("Chat-Id", chatId);
              if (sessionId) {
                headers.set("Session-Id", sessionId);
                sessionChatIdMap.set(sessionId, chatId);
              }
              let finalInput = requestInput;
              let reqBody = null;
              if (typeof init?.body === "string") {
                try {
                  reqBody = JSON.parse(init.body);
                  if (reqBody.stream !== true) {
                    const u = requestInput instanceof URL ? new URL(requestInput.toString()) : new URL(typeof requestInput === "string" ? requestInput : requestInput.url);
                    u.pathname = u.pathname.replace(/\/$/, "").replace(/\/chat\/completions$/, "/no-stream/chat/completions");
                    finalInput = u;
                  }
                } catch {}
              }
              const fetchOpts = { ...init, headers, body: init?.body };
              const isQwen3 = reqBody?.model?.includes("Qwen3") && (reqBody?.tools?.length ?? 0) > 0;
              if (isQwen3 && reqBody?.stream === true) {
                const resp = await fetch(finalInput, fetchOpts);
                const respText = await resp.text();
                let hasContent = false;
                let hasToolCalls = false;
                let completionTokens = 0;
                for (const line of respText.split(`
`)) {
                  const trimmed = line.trim();
                  if (!trimmed.startsWith("data: ") || trimmed === "data: [DONE]")
                    continue;
                  try {
                    const chunk = JSON.parse(trimmed.slice(6));
                    const choice = chunk.choices?.[0];
                    if (choice?.delta?.content)
                      hasContent = true;
                    if (choice?.delta?.tool_calls)
                      hasToolCalls = true;
                    if (chunk.usage?.completion_tokens)
                      completionTokens = chunk.usage.completion_tokens;
                  } catch {}
                }
                if (!hasContent && !hasToolCalls && completionTokens > 0) {
                  log("warn", "Qwen3 empty response detected, retrying with tool_choice: required", {
                    tokens: completionTokens
                  });
                  reqBody.tool_choice = "required";
                  return fetch(finalInput, { ...fetchOpts, body: JSON.stringify(reqBody) });
                }
                return new Response(respText, {
                  status: resp.status,
                  statusText: resp.statusText,
                  headers: resp.headers
                });
              }
              return fetch(finalInput, fetchOpts);
            }
          };
        },
        methods: [
          {
            type: "oauth",
            label: "Login with Huawei DevEco Account",
            async authorize() {
              return {
                url: "",
                instructions: "Opening browser for Huawei login...",
                method: "auto",
                async callback() {
                  const result = await loginWithHuawei();
                  if (!result.success) {
                    return { type: "failed", error: result.cancelled ? "Login cancelled" : result.error };
                  }
                  return {
                    type: "success",
                    provider: PROVIDER_ID,
                    access: result.accessToken,
                    refresh: result.refreshToken ?? "",
                    expires: Date.now() + ACCESS_TOKEN_EXPIRES_MS
                  };
                }
              };
            }
          }
        ]
      }
    };
  }
};
export {
  src_default as default
};
