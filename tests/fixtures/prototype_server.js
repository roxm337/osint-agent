// A minimal JSON API used to test modules/prototype_pollution.py.
//
//   node server.js <port> <mode>
//
// mode "vulnerable" merges the request body into a plain object with a naive
// deep merge, so a __proto__ payload reaches Object.prototype.
// mode "literal"   stores __proto__ as an ordinary key, which is what a
//                  framework that filters the literal key but still walks the
//                  chain would do — the payload must NOT reach the prototype.
// mode "safe"      deep-merges into a null-prototype object and refuses
//                  __proto__/constructor/prototype outright.
//
// /reflect returns a freshly created {} every time. If the prototype really
// was polluted the injected key shows up in that response, which is the
// signal the module keys on.

const http = require("http");

const port = parseInt(process.argv[2], 10) || 0;
const mode = process.argv[3] || "safe";
const FORBIDDEN = ["__proto__", "constructor", "prototype"];

function hasForbiddenKey(value) {
  if (value === null || typeof value !== "object") return false;
  for (const key of Object.keys(value)) {
    if (FORBIDDEN.includes(key)) return true;
    if (hasForbiddenKey(value[key])) return true;
  }
  return false;
}

function naiveMerge(target, source) {
  for (const key of Object.keys(source)) {
    const value = source[key];
    if (value && typeof value === "object" && !Array.isArray(value)) {
      if (!target[key]) target[key] = {};
      naiveMerge(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
}

function guardedMerge(target, source) {
  if (hasForbiddenKey(source)) return target;
  for (const key of Object.keys(source)) {
    const value = source[key];
    if (value && typeof value === "object" && !Array.isArray(value)) {
      const child = Object.create(null);
      guardedMerge(child, value);
      target[key] = child;
    } else {
      target[key] = value;
    }
  }
  return target;
}

const records = new Map();
const requests = [];
let lastBody = {};

function readBody(req) {
  return new Promise((resolve) => {
    let raw = "";
    req.on("data", (chunk) => { raw += chunk; });
    req.on("end", () => {
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        resolve(null);
      }
    });
  });
}

function send(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  requests.push(`${req.method} ${url.pathname}`);

  if (url.pathname === "/requests") {
    return send(res, 200, { requests });
  }

  // A target that always refuses writes. The module must treat a 429 as a
  // rate-limit signal to record, not as a clean run.
  if (url.pathname === "/api/throttled") {
    return send(res, 429, { error: "too many requests" });
  }

  // Refuses writes on principle, rather than because of load.
  if (url.pathname === "/api/forbidden") {
    return send(res, 403, { error: "forbidden" });
  }

  if (url.pathname === "/reflect") {
    // A brand new object, enumerated with for...in so that *inherited*
    // properties show up. Plain JSON.stringify({}) would not do: it walks
    // own properties only, so a genuinely polluted prototype would be
    // invisible here and the whole test would pass for the wrong reason.
    // mode "echo": the endpoint returns whatever it last received. Every
    // prototype-pollution scanner that trusts such an endpoint reports a
    // finding on every request, so the module has to notice and stand down.
    if (mode === "echo") {
      return send(res, 200, lastBody);
    }
    const inherited = {};
    for (const key in {}) inherited[key] = { inherited: true };
    return send(res, 200, inherited);
  }

  if (url.pathname === "/api/profile") {
    if (req.method === "GET") {
      return send(res, 200, records.get("profile") || { id: 1, name: "tester" });
    }
    if (req.method !== "POST" && req.method !== "PUT") {
      return send(res, 405, { error: "method not allowed" });
    }
    const body = await readBody(req);
    if (body === null) return send(res, 400, { error: "bad json" });
    lastBody = body;

    if (mode === "vulnerable" || mode === "echo") {
      const merged = naiveMerge({ id: 1, name: "tester" }, body);
      records.set("profile", merged);
    } else if (mode === "literal") {
      // Deep merge, but a literal __proto__ key is copied as a normal key.
      // This is the shape that is NOT vulnerable and must not be reported.
      const merged = {};
      for (const key of Object.keys(body)) merged[key] = body[key];
      records.set("profile", Object.assign({ id: 1, name: "tester" }, merged));
    } else {
      const merged = guardedMerge(Object.create(null), body);
      merged.id = 1;
      merged.name = "tester";
      records.set("profile", merged);
    }
    return send(res, 200, records.get("profile"));
  }

  if (url.pathname === "/api/echo") {
    if (req.method !== "POST" && req.method !== "PUT") {
      return send(res, 405, { error: "method not allowed" });
    }
    const body = await readBody(req);
    if (body === null) return send(res, 400, { error: "bad json" });
    if (mode === "vulnerable") {
      naiveMerge({ id: 1 }, body);
    } else {
      guardedMerge(Object.create(null), body);
    }
    return send(res, 200, { ok: true });
  }

  send(res, 404, { error: "not found" });
});

server.listen(port, "127.0.0.1", () => {
  process.stdout.write(`listening ${server.address().port}\n`);
});

process.on("SIGTERM", () => server.close(() => process.exit(0)));
process.on("SIGINT", () => server.close(() => process.exit(0)));
