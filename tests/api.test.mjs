import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { createHmac } from "node:crypto";
test("authenticated reports, persistent state, signed webhook and fail-closed gate", async () => {
  const dir = mkdtempSync(tmpdir() + "/blue-lock-");
  const secret = "test-webhook-secret-at-least-32-characters";
  let child;
  let token = "";
  async function start() {
    child = spawn(process.execPath, ["server/app.mjs"], {
      env: {
        ...process.env,
        PORT: "3189",
        DATA_DIR: dir,
        WEBHOOK_SECRET: secret,
        DATABASE_URL: "",
        REDIS_URL: "",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    await new Promise((ok, no) => {
      child.stdout.on("data", () => ok());
      child.on("error", no);
      child.on("exit", (c) => no(Error("Server exit " + c)));
    });
  }
  async function req(path, body, extra = {}) {
    const r = await fetch("http://127.0.0.1:3189/api" + path, {
      method: body ? "POST" : "GET",
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: "Bearer " + token } : {}),
        ...extra,
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    return { status: r.status, data: await r.json() };
  }
  async function stop() {
    const ended = new Promise((r) => child.once("exit", r));
    child.kill();
    await ended;
  }
  try {
    await start();
    assert.equal((await req("/state")).status, 401);
    token = (
      await req("/auth/setup", {
        email: "test@example.com",
        password: "a-long-test-password-2026",
      })
    ).data.token;
    assert.ok(token);
    const repo = (
      await req("/repos", {
        name: "Test",
        url: "https://github.com/example/test",
        threshold: 80,
      })
    ).data;
    const session = (
      await req("/sessions", {
        repoId: repo.id,
        commit: "abc1234",
        branch: "main",
      })
    ).data;
    assert.equal(
      (await req(`/sessions/${session.id}/gate`)).data.allowed,
      false,
    );
    for (const [tool, report] of [
      ["sonar", { issues: [] }],
      ["trufflehog", []],
      ["dependency-check", { dependencies: [] }],
    ])
      assert.equal(
        (await req(`/sessions/${session.id}/reports/${tool}`, { report }))
          .status,
        200,
      );
    assert.equal(
      (await req(`/sessions/${session.id}/gate`)).data.allowed,
      true,
    );
    assert.equal(
      (
        await req(`/sessions/${session.id}/reports/sonar`, {
          report: { issues: [] },
        })
      ).status,
      400,
    );
    const payload = {
      after: "a".repeat(40),
      ref: "refs/heads/main",
      repository: { html_url: repo.url },
    };
    const headers = {
      "x-github-event": "push",
      "x-github-delivery": "delivery-1",
      "x-hub-signature-256":
        "sha256=" +
        createHmac("sha256", secret)
          .update(JSON.stringify(payload))
          .digest("hex"),
    };
    const hook = await req("/webhooks/" + repo.id, payload, headers);
    assert.equal(hook.status, 202);
    assert.equal(
      (await req("/webhooks/" + repo.id, payload, headers)).data.sessionId,
      hook.data.sessionId,
    );
    assert.equal(
      (
        await req("/webhooks/" + repo.id, payload, {
          ...headers,
          "x-hub-signature-256": "sha256=" + "0".repeat(64),
        })
      ).status,
      401,
    );
    await req("/demo", {});
    const state = (await req("/state")).data;
    const sample = state.sessions.find((s) => s.demo && s.score.value === 100);
    assert.equal(
      (await req(`/sessions/${sample.id}/gate`)).data.allowed,
      false,
    );
    await stop();
    await start();
    assert.equal(
      (await req(`/sessions/${session.id}/gate`)).data.allowed,
      true,
    );
  } finally {
    if (child?.exitCode === null) await stop();
    rmSync(dir, { recursive: true, force: true });
  }
});
