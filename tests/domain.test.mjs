import test from "node:test";
import assert from "node:assert/strict";
import { normalize, score, parseReport } from "../server/domain.mjs";
test("weights, caps and no double-counting of secrets", () => {
  const f = [...Array(8)].map(() => ({
    severity: "critical",
    category: "sast",
  }));
  f.push(...Array(3).fill({ severity: "critical", category: "secret" }));
  const s = score(f);
  assert.equal(s.value, 0);
  assert.equal(s.breakdown.find((x) => x.key === "critical").deduction, 60);
  assert.equal(s.breakdown.find((x) => x.key === "secret").deduction, 50);
  assert.equal(score([{ severity: "critical", category: "secret" }]).value, 75);
});
test("threshold boundary and empty completed reports", () => {
  assert.equal(score([], 100).allowed, true);
  assert.equal(
    score([{ severity: "high", category: "sast" }], 92).allowed,
    true,
  );
  assert.equal(
    score([{ severity: "high", category: "sast" }], 93).allowed,
    false,
  );
});
test("TruffleHog secret and arbitrary fields never survive normalization", () => {
  const f = normalize("trufflehog", [
    {
      DetectorName: "AWS",
      Raw: "DO_NOT_PERSIST",
      Redacted: "STILL_SENSITIVE",
      SourceMetadata: { Data: { Git: { file: "x.env", line: 4 } } },
    },
  ]);
  assert.equal(f[0].category, "secret");
  assert.ok(!JSON.stringify(f).includes("DO_NOT_PERSIST"));
  assert.ok(!JSON.stringify(f).includes("STILL_SENSITIVE"));
});
test("reject incomplete, malformed and unknown severity reports", () => {
  assert.throws(() =>
    normalize("sonar", { issues: [], paging: { total: 100 } }),
  );
  assert.throws(() =>
    normalize("sonar", { issues: [{ severity: "UNKNOWN" }] }),
  );
  assert.throws(() => normalize("dependency-check", {}));
  assert.throws(() => normalize("trufflehog", [{}]));
  assert.throws(() => normalize("other", {}));
});
test("deduplicate identical issues and parse JSONL", () => {
  const x = {
    severity: "MAJOR",
    component: "a",
    line: 4,
    rule: "R",
    message: "Issue",
  };
  assert.equal(normalize("sonar", { issues: [x, x] }).length, 1);
  assert.deepEqual(parseReport("trufflehog", ""), []);
  assert.deepEqual(parseReport("trufflehog", '{"a":1}\n{"a":2}'), [
    { a: 1 },
    { a: 2 },
  ]);
});
test("CVSS severity boundaries", () => {
  const f = normalize("dependency-check", {
    dependencies: [
      {
        fileName: "a",
        vulnerabilities: [0, 3.9, 4, 7, 9].map((v, i) => ({
          name: String(i),
          cvssv3: { baseScore: v },
        })),
      },
    ],
  });
  assert.deepEqual(
    f.map((x) => x.severity),
    ["info", "low", "medium", "high", "critical"],
  );
});
test("Sonar quality classification controls the gate and retains impacts", () => {
  const base = { severity: "CRITICAL", component: "a", line: 1, message: "complexity" };
  const findings = normalize("sonar", { issues: [
    {...base, rule: "complexity", type: "CODE_SMELL", impacts: [{softwareQuality: "MAINTAINABILITY", severity: "HIGH"}]},
    {...base, rule: "bug", type: "BUG"},
    {...base, rule: "security-review", severity: "MINOR", type: "CODE_SMELL", impacts: [{softwareQuality: "SECURITY", severity: "LOW"}]},
    {...base, rule: "vulnerability", severity: "MAJOR", type: "VULNERABILITY"},
  ]});
  assert.equal(findings[0].issueType, "CODE_SMELL");
  assert.equal(findings[0].impacts[0].severity, "HIGH");
  assert.deepEqual(score(findings).qualityCounts, {security: 2, reliability: 1, maintainability: 1, unknown: 0});
  assert.equal(score(findings).value, 96);
  assert.equal(score(findings).allowed, true);
  assert.equal(score([{tool: "sonar", severity: "high", category: "sast"}]).allowed, false);
  assert.equal(score(normalize("sonar", {issues: [{...base, rule: "unclassified"}]})).classificationComplete, false);
});
