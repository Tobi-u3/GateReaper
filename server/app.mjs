import express from "express";
import helmet from "helmet";
import { rateLimit } from "express-rate-limit";
import jwt from "jsonwebtoken";
import { WebSocketServer } from "ws";
import { createServer } from "node:http";
import {
  randomBytes,
  randomUUID,
  scryptSync,
  timingSafeEqual,
  createHmac,
} from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { createStore } from "./store.mjs";
import { normalize, score, tools, parseReport } from "./domain.mjs";
const store = await createStore();
let state = (await store.read()) ?? {
  repos: [],
  sessions: [],
  audit: [],
  deliveries: [],
  user: null,
  jwtKey: randomBytes(48).toString("hex"),
};
// Old normalized Sonar reports lost classification; keep their gates blocked until reimport.
for (const session of state.sessions) {
  if (session.status === "completed") {
    session.score = score(session.findings, session.threshold);
    if (!session.score.classificationComplete) {
      session.status = "awaiting_reports";
      delete session.reports.sonar;
      session.received = Object.keys(session.reports);
      session.score = null;
    }
  }
}
await store.write(state);
let lock = Promise.resolve();
function transaction(fn) {
  const next = lock.then(async () => {
    const backup = structuredClone(state);
    try {
      const out = await fn();
      await store.write(state);
      broadcast();
      return out;
    } catch (e) {
      state = backup;
      throw e;
    }
  });
  lock = next.catch(() => {});
  return next;
}
function audit(action, detail) {
  state.audit.unshift({
    id: randomUUID(),
    time: new Date().toISOString(),
    action,
    detail,
  });
  state.audit = state.audit.slice(0, 2000);
}
function check(condition, msg) {
  if (!condition) {
    const e = Error(msg);
    e.status = 400;
    throw e;
  }
}
function safeSession(s) {
  return { ...s, reports: undefined };
}
function snapshot() {
  return {
    repos: state.repos,
    sessions: state.sessions.map(safeSession),
    audit: state.audit,
  };
}
const app = express();
app.disable("x-powered-by");
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: { "connect-src": ["'self'", "ws:", "wss:"] },
    },
  }),
);
app.use(
  express.json({
    limit: "8mb",
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  }),
);
app.use(
  "/api",
  rateLimit({
    windowMs: 60000,
    limit: 180,
    standardHeaders: "draft-8",
    legacyHeaders: false,
  }),
);
const authLimit = rateLimit({
  windowMs: 900000,
  limit: 20,
  standardHeaders: "draft-8",
  legacyHeaders: false,
});
const tokenOf = (req) => req.headers.authorization?.replace(/^Bearer /, "");
function authenticate(req, res, next) {
  try {
    req.user = jwt.verify(tokenOf(req), state.jwtKey, {
      algorithms: ["HS256"],
    });
    next();
  } catch {
    res.status(401).json({ error: "Sign in to continue" });
  }
}
app.get("/api/health", (_, res) => res.json({ ok: true }));
app.get("/api/auth/status", (_, res) =>
  res.json({ setupRequired: !state.user }),
);
app.post("/api/auth/setup", authLimit, async (req, res) => {
  const token = await transaction(() => {
    check(!state.user, "An administrator already exists");
    const { email, password } = req.body;
    check(
      typeof email === "string" && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email),
      "Enter a valid email",
    );
    check(
      typeof password === "string" &&
        password.length >= 15 &&
        password.length <= 256,
      "Use a password of 15–256 characters",
    );
    const salt = randomBytes(16).toString("hex");
    state.user = {
      email,
      salt,
      hash: scryptSync(password, salt, 64).toString("hex"),
    };
    audit("Account created", email);
    return jwt.sign({ sub: email }, state.jwtKey, { expiresIn: "8h" });
  });
  res.json({ token });
});
app.post("/api/auth/login", authLimit, (req, res) => {
  const u = state.user;
  const p = req.body.password;
  const good =
    u &&
    typeof p === "string" &&
    p.length <= 256 &&
    timingSafeEqual(scryptSync(p, u.salt, 64), Buffer.from(u.hash, "hex")) &&
    req.body.email === u.email;
  if (!good)
    return res.status(401).json({ error: "Email or password is incorrect" });
  res.json({
    token: jwt.sign({ sub: u.email }, state.jwtKey, { expiresIn: "8h" }),
  });
});
const webLimit = rateLimit({
  windowMs: 60000,
  limit: 10,
  keyGenerator: (req) => req.params.id,
  standardHeaders: "draft-8",
  legacyHeaders: false,
});
app.post("/api/webhooks/:id", webLimit, async (req, res) => {
  const secret = process.env.WEBHOOK_SECRET;
  check(
    secret && secret.length >= 32,
    "Webhook secret must be configured by the operator",
  );
  const supplied = req.headers["x-hub-signature-256"] ?? "";
  const expected =
    "sha256=" + createHmac("sha256", secret).update(req.rawBody).digest("hex");
  if (
    typeof supplied !== "string" ||
    supplied.length !== expected.length ||
    !timingSafeEqual(Buffer.from(supplied), Buffer.from(expected))
  )
    return res.status(401).json({ error: "Invalid signature" });
  check(
    req.headers["x-github-event"] === "push",
    "Only GitHub push events are supported",
  );
  const delivery = req.headers["x-github-delivery"];
  check(
    typeof delivery === "string" && delivery.length < 150,
    "Delivery ID required",
  );
  const result = await transaction(() => {
    const repo = state.repos.find((r) => r.id === req.params.id);
    check(repo, "Repository not found");
    check(!repo.demo, "Create a real repository for webhooks");
    check(
      req.body.repository?.html_url === repo.url,
      "Webhook repository does not match registered repository",
    );
    const previous = state.deliveries.find((d) => d.id === delivery);
    if (previous) return previous;
    check(
      /^[a-f0-9]{40}$/.test(req.body.after),
      "A full commit SHA is required",
    );
    const s = newSession(
      repo,
      req.body.after,
      String(req.body.ref ?? "").replace("refs/heads/", ""),
      "webhook",
    );
    state.sessions.unshift(s);
    const d = { id: delivery, sessionId: s.id };
    state.deliveries.push(d);
    audit("Webhook accepted", `${repo.name} • ${s.commit}`);
    return d;
  });
  res.status(202).json(result);
});
app.use("/api", authenticate);
app.get("/api/state", (_, res) => res.json(snapshot()));
app.post("/api/repos", async (req, res) => {
  const r = await transaction(() => {
    const { name, url, threshold = 80 } = req.body;
    check(
      typeof name === "string" && name.trim().length > 0 && name.length <= 80,
      "Name must be 1–80 characters",
    );
    let u;
    try {
      u = new URL(url);
    } catch {
      throw Error("Enter a valid repository URL");
    }
    check(
      u.protocol === "https:" && !u.username && !u.password,
      "Use an HTTPS URL without credentials",
    );
    check(
      Number.isInteger(threshold) && threshold >= 0 && threshold <= 100,
      "Threshold must be 0–100",
    );
    const r = {
      id: randomUUID(),
      name: name.trim(),
      url: u.href.replace(/\/$/, ""),
      threshold,
      demo: false,
    };
    state.repos.push(r);
    audit("Repository added", r.name);
    return r;
  });
  res.status(201).json(r);
});
app.patch("/api/repos/:id", async (req, res) => {
  await transaction(() => {
    const r = state.repos.find((r) => r.id === req.params.id);
    check(r, "Repository not found");
    check(
      Number.isInteger(req.body.threshold) &&
        req.body.threshold >= 0 &&
        req.body.threshold <= 100,
      "Threshold must be 0–100",
    );
    r.threshold = req.body.threshold;
    audit("Gate policy updated", `${r.name}: ${r.threshold}`);
  });
  res.json({ ok: true });
});
function newSession(repo, commit, branch, source) {
  return {
    id: randomUUID(),
    repoId: repo.id,
    commit,
    branch,
    source,
    demo: repo.demo,
    status: "awaiting_reports",
    createdAt: new Date().toISOString(),
    threshold: repo.threshold,
    reports: {},
    findings: [],
    score: null,
  };
}
app.post("/api/sessions", async (req, res) => {
  const s = await transaction(() => {
    const repo = state.repos.find((r) => r.id === req.body.repoId);
    check(repo, "Repository not found");
    check(
      typeof req.body.commit === "string" &&
        /^[a-f0-9]{7,40}$/.test(req.body.commit),
      "Enter a 7–40 character hexadecimal commit SHA",
    );
    check(
      typeof req.body.branch === "string" &&
        req.body.branch.length > 0 &&
        req.body.branch.length <= 200,
      "Branch is required",
    );
    const s = newSession(
      repo,
      req.body.commit,
      req.body.branch,
      "report-import",
    );
    state.sessions.unshift(s);
    audit("Scan session created", `${repo.name} • ${s.commit}`);
    return s;
  });
  res.status(201).json(safeSession(s));
});
async function applyReport({ sessionId, tool, findings }) {
  return transaction(() => {
    const s = state.sessions.find((s) => s.id === sessionId);
    check(s, "Session not found");
    check(
      s.status !== "completed",
      "Completed scans are immutable; create another session",
    );
    s.reports[tool] = findings;
    s.findings = Object.values(s.reports).flat();
    s.received = Object.keys(s.reports);
    s.status = "awaiting_reports";
    if (tools.every((t) => s.reports[t] !== undefined)) {
      s.score = score(s.findings, s.threshold);
      s.status = "completed";
      s.completedAt = new Date().toISOString();
      audit(
        "Security gate evaluated",
        `${s.id}: ${s.score.allowed ? "PASS" : "BLOCK"} (${s.score.value}/100)`,
      );
    } else
      audit("Scanner report imported", `${tool} • ${findings.length} findings`);
    return safeSession(s);
  });
}
let queue;
if (process.env.REDIS_URL) {
  const { Queue, Worker } = await import("bullmq");
  const { default: Redis } = await import("ioredis");
  queue = new Queue("blue-lock-reports", {
    connection: new Redis(process.env.REDIS_URL, { maxRetriesPerRequest: 1 }),
  });
  const worker = new Worker(
    "blue-lock-reports",
    async (job) => {
      const s = state.sessions.find((x) => x.id === job.data.sessionId);
      if (s?.status === "completed") return;
      await applyReport(job.data);
    },
    {
      connection: new Redis(process.env.REDIS_URL, {
        maxRetriesPerRequest: null,
      }),
      concurrency: 3,
    },
  );
  worker.on("failed", (job) =>
    transaction(() => {
      audit("Report processing failed", job?.id ?? "unknown");
    }).catch(() => {}),
  );
  worker.on("error", () => console.error("Queue worker connection error"));
}
app.post("/api/sessions/:id/reports/:tool", async (req, res) => {
  check(tools.includes(req.params.tool), "Unknown scanner");
  const s = state.sessions.find((s) => s.id === req.params.id);
  check(s && s.status !== "completed", "Session missing or already completed");
  const findings = normalize(
    req.params.tool,
    parseReport(req.params.tool, req.body.report),
  );
  const data = { sessionId: s.id, tool: req.params.tool, findings };
  if (queue) {
    await queue.add("normalize", data, {
      attempts: 3,
      backoff: { type: "exponential", delay: 1000 },
      removeOnComplete: 100,
      removeOnFail: 100,
    });
    return res.status(202).json({ queued: true });
  }
  res.json(await applyReport(data));
});
app.get("/api/sessions/:id/gate", (req, res) => {
  const s = state.sessions.find((s) => s.id === req.params.id);
  if (!s) return res.status(404).json({ error: "Session not found" });
  const r = state.repos.find((r) => r.id === s.repoId);
  const evaluation =
    s.status === "completed" ? score(s.findings, r.threshold) : null;
  res.json({
    sessionId: s.id,
    commit: s.commit,
    status: s.status,
    allowed: !s.demo && !!evaluation?.allowed,
    score: evaluation?.value ?? null,
    threshold: r.threshold,
    reason: s.demo
      ? "Sample data cannot authorize deployment"
      : !evaluation
        ? "Waiting for all three scanner reports"
        : !evaluation.classificationComplete
          ? "Reimport the raw Sonar report to restore missing classifications"
        : evaluation.allowed
          ? "Current policy satisfied"
          : "Score below current threshold",
  });
});
app.get("/api/sessions/:id/export", (req, res) => {
  const s = state.sessions.find((s) => s.id === req.params.id);
  if (!s) return res.status(404).json({ error: "Session not found" });
  res.attachment(`gatereaper-${s.id}.json`).json(safeSession(s));
});
app.post("/api/demo", async (_, res) => {
  await transaction(() => {
    check(!state.repos.some((r) => r.demo), "Sample workspace already loaded");
    const names = ["payment-service", "customer-portal", "identity-api"];
    for (let i = 0; i < 3; i++) {
      const repo = {
        id: randomUUID(),
        name: names[i],
        url: `https://github.com/example/${names[i]}`,
        threshold: 80,
        demo: true,
      };
      state.repos.push(repo);
      const s = newSession(
        repo,
        ["a1b2c3d", "d4e5f6a", "abc1234"][i],
        "main",
        "sample",
      );
      const sample = JSON.parse(readFileSync("samples/demo.json", "utf8"));
      s.reports = {
        sonar: normalize("sonar", i === 2 ? { issues: [] } : sample.sonar),
        trufflehog: normalize("trufflehog", i === 0 ? sample.trufflehog : []),
        "dependency-check": normalize(
          "dependency-check",
          i === 0 ? sample.dependency : { dependencies: [] },
        ),
      };
      s.findings = Object.values(s.reports).flat();
      s.received = tools;
      s.score = score(s.findings, 80);
      s.status = "completed";
      s.completedAt = s.createdAt;
      state.sessions.push(s);
    }
    audit(
      "Sample workspace loaded",
      "Illustrative results — no scanners were executed",
    );
  });
  res.json({ ok: true });
});
app.use("/api", (_, res) =>
  res.status(404).json({ error: "Endpoint not found" }),
);
app.use(express.static(resolve("dist")));
app.get("/{*path}", (_, res) => {
  if (existsSync("dist/index.html")) res.sendFile(resolve("dist/index.html"));
  else res.status(503).send("Build the dashboard first: npm run build");
});
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  res
    .status(err.status || 400)
    .json({
      error:
        err.type === "entity.too.large"
          ? "Report exceeds the 8 MB upload limit"
          : err.message || "Request failed",
    });
});
const server = createServer(app);
const wss = new WebSocketServer({ noServer: true, maxPayload: 4096 });
server.on("upgrade", (req, socket, head) => {
  if (req.url !== "/ws") return socket.destroy();
  wss.handleUpgrade(req, socket, head, (ws) => {
    ws.authed = false;
    const timer = setTimeout(() => ws.close(), 5000);
    ws.on("message", (data) => {
      try {
        const p = JSON.parse(data.toString());
        const user = jwt.verify(p.token, state.jwtKey, {
          algorithms: ["HS256"],
        });
        ws.authed = true;
        clearTimeout(timer);
        setTimeout(
          () => ws.close(),
          Math.max(0, user.exp * 1000 - Date.now()),
        ).unref();
        ws.send(JSON.stringify({ type: "refresh" }));
      } catch {
        ws.close();
      }
    });
  });
});
function broadcast() {
  for (const ws of wss.clients)
    if (ws.authed && ws.readyState === 1)
      ws.send(JSON.stringify({ type: "refresh" }));
}
server.listen(
  Number(process.env.PORT || 3000),
  process.env.HOST || "127.0.0.1",
  () =>
    console.log(
      `GateReaper ready at http://${process.env.HOST || "127.0.0.1"}:${process.env.PORT || 3000}`,
    ),
);
