import { createHash } from "node:crypto";
import Ajv from "ajv";
export const tools = ["sonar", "trufflehog", "dependency-check"];
const validate = new Ajv().compile({
  type: "object",
  additionalProperties: false,
  required: [
    "id",
    "tool",
    "severity",
    "category",
    "file",
    "line",
    "rule",
    "description",
  ],
  properties: {
    issueType: { type: "string" },
    quality: { enum: ["security", "reliability", "maintainability", "unknown"] },
    impacts: { type: "array", items: { type: "object", required: ["softwareQuality", "severity"], additionalProperties: false, properties: { softwareQuality: { type: "string" }, severity: { type: "string" } } } },
    id: { type: "string" },
    tool: { enum: tools },
    severity: { enum: ["critical", "high", "medium", "low", "info"] },
    category: { enum: ["sast", "secret", "dependency"] },
    file: { type: "string", maxLength: 1000 },
    line: { type: "integer", minimum: 0 },
    rule: { type: "string", maxLength: 300 },
    description: { type: "string", maxLength: 4000 },
  },
});
const text = (x, n = 1000) => String(x ?? "").slice(0, n);
function finding(tool, severity, category, file, line, rule, description) {
  const f = {
    tool,
    severity,
    category,
    file: text(file),
    line: Math.max(0, Math.floor(Number(line) || 0)),
    rule: text(rule, 300),
    description: text(description, 4000),
  };
  f.id = createHash("sha256")
    .update(JSON.stringify(f))
    .digest("hex")
    .slice(0, 24);
  if (!validate(f)) throw Error("Finding did not pass schema validation");
  return f;
}
export function normalize(tool, raw) {
  let rows = [];
  if (tool === "sonar") {
    if (!raw || !Array.isArray(raw.issues))
      throw Error("Sonar report must contain an issues array");
    const total = raw.paging?.total ?? raw.total;
    if (total !== undefined && Number(total) > raw.issues.length)
      throw Error(
        "Incomplete Sonar export: combine every page before importing",
      );
    rows = raw.issues.map((x) => {
      const sev = {
        BLOCKER: "critical",
        CRITICAL: "high",
        MAJOR: "medium",
        MINOR: "low",
        INFO: "info",
      }[x.severity];
      if (!sev)
        throw Error(
          "Unsupported Sonar severity; export classic severity values",
        );
      const f = finding(tool, sev, "sast", x.component, x.line, x.rule, x.message);
      f.issueType = text(x.type || "UNKNOWN", 100);
      f.impacts = (Array.isArray(x.impacts) ? x.impacts : []).map(i => ({ softwareQuality: text(i.softwareQuality, 100), severity: text(i.severity, 100) }));
      const qualities = f.impacts.map(i => i.softwareQuality);
      f.quality = qualities.includes("SECURITY") || x.type === "VULNERABILITY" || x.type === "SECURITY_HOTSPOT" ? "security"
        : qualities.includes("RELIABILITY") || x.type === "BUG" ? "reliability"
        : qualities.includes("MAINTAINABILITY") || x.type === "CODE_SMELL" ? "maintainability" : "unknown";
      if (!validate(f)) throw Error("Invalid Sonar classification");
      return f;
    });
  } else if (tool === "trufflehog") {
    if (!Array.isArray(raw))
      throw Error("TruffleHog report must be a JSON array or JSONL");
    rows = raw.map((x) => {
      if (!x.DetectorName || !x.SourceMetadata)
        throw Error("Invalid TruffleHog finding");
      const s =
        x.SourceMetadata.Data?.Git ?? x.SourceMetadata.Data?.Filesystem ?? {};
      return finding(
        tool,
        "critical",
        "secret",
        s.file,
        s.line,
        x.DetectorName,
        `Potential credential detected by ${text(x.DetectorName, 100)}. Revoke and rotate the credential, then remove it from source and history. Secret value intentionally discarded.`,
      );
    });
  } else if (tool === "dependency-check") {
    if (!raw || !Array.isArray(raw.dependencies))
      throw Error("Dependency-Check report must contain a dependencies array");
    rows = raw.dependencies.flatMap((d) =>
      (d.vulnerabilities ?? []).map((v) => {
        const cvss = Number(v.cvssv3?.baseScore ?? v.cvssv2?.score);
        let sev = Number.isFinite(cvss)
          ? cvss >= 9
            ? "critical"
            : cvss >= 7
              ? "high"
              : cvss >= 4
                ? "medium"
                : cvss > 0
                  ? "low"
                  : "info"
          : {
              CRITICAL: "critical",
              HIGH: "high",
              MEDIUM: "medium",
              LOW: "low",
              INFO: "info",
            }[v.severity];
        if (!sev)
          throw Error(
            "Dependency vulnerability has no recognized severity or CVSS score",
          );
        return finding(
          tool,
          sev,
          "dependency",
          d.fileName,
          0,
          v.name,
          v.description,
        );
      }),
    );
  } else throw Error("Unknown scanner");
  if (rows.length > 20000) throw Error("Too many findings in a single report");
  return [...new Map(rows.map((f) => [f.id, f])).values()];
}
export function score(findings, threshold = 80) {
  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    secret: 0,
  };
  const qualityCounts = { security: 0, reliability: 0, maintainability: 0, unknown: 0 };
  for (const f of findings) {
    const quality = f.tool === "sonar" ? (f.quality || "unknown") : "security";
    qualityCounts[quality]++;
    if (quality === "security") counts[f.category === "secret" ? "secret" : f.severity]++;
  }
  const weights = {
    critical: [15, 60],
    high: [8, 32],
    medium: [3, 15],
    low: [1, 5],
    info: [0, 0],
    secret: [25, 50],
  };
  const breakdown = Object.entries(weights).map(([key, [weight, cap]]) => ({
    key,
    count: counts[key],
    weight,
    cap,
    deduction: Math.min(counts[key] * weight, cap),
  }));
  const value = Math.max(
    0,
    100 - breakdown.reduce((n, x) => n + x.deduction, 0),
  );
  return {
    value,
    threshold,
    band:
      value >= 90
        ? "Excellent"
        : value >= 75
          ? "Good"
          : value >= 50
            ? "Fair"
            : value >= 25
              ? "Poor"
              : "Critical",
    allowed: value >= threshold && qualityCounts.unknown === 0,
    classificationComplete: qualityCounts.unknown === 0,
    qualityCounts,
    breakdown,
  };
}
export function parseReport(tool, input) {
  if (typeof input !== "string") return input;
  if (tool === "trufflehog" && !input.trim()) return [];
  try {
    return JSON.parse(input);
  } catch {
    if (tool === "trufflehog")
      return input
        .trim()
        .split(/\r?\n/)
        .map((x) => JSON.parse(x));
    throw Error("Report is not valid JSON");
  }
}
