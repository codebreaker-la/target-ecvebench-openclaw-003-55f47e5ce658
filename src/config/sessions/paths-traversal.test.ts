/**
 * GHSA-rqpp-rjj8-7wv8 — Path traversal via agentId in session directory resolution
 *
 * resolveAgentSessionsDir and resolveSiblingAgentSessionsDir construct filesystem
 * paths using path.join(root, "agents", normalizeAgentId(agentId), "sessions").
 * Neither function validates that the resulting path stays within the intended
 * state directory.  The only barrier is normalizeAgentId, which currently strips
 * dots and slashes.  A sibling helper (resolvePathFromAgentSessionsDir) performs
 * an explicit traversal check—showing the codebase is aware of the threat—but
 * the two agent-sessions-dir builders do not.
 *
 * This test demonstrates:
 *  1. path.join with an unsanitized traversal segment escapes the root directory
 *  2. The exported wrappers are only safe because normalizeAgentId happens to
 *     strip traversal characters; no post-construction containment check exists
 *  3. resolveSiblingAgentSessionsDir has the same gap
 *
 * Run: pnpm test src/config/sessions/paths-traversal.test.ts
 */
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import { normalizeAgentId } from "../../routing/session-key.js";
import { resolveDefaultSessionStorePath, resolveSessionTranscriptsDirForAgent } from "./paths.js";

// Controlled env so resolveStateDir returns a predictable root.
const STATE_DIR = "/tmp/openclaw-repro-state";
const fakeEnv: NodeJS.ProcessEnv = {
  OPENCLAW_STATE_DIR: STATE_DIR,
  OPENCLAW_TEST_FAST: "1",
};
const fakeHomedir = () => "/tmp/openclaw-repro-home";

describe("GHSA-rqpp-rjj8-7wv8: path traversal via agentId", () => {
  // ── 1. Structural proof: path.join does not prevent traversal ────────────
  describe("path.join allows traversal when segment contains '..'", () => {
    it("escapes the root with ../../<target>", () => {
      const root = "/home/user/.openclaw";
      // This mirrors the body of resolveAgentSessionsDir:
      //   path.join(root, "agents", id, "sessions")
      const escaped = path.join(root, "agents", "../../etc", "sessions");
      // path.join resolves the ".." segments:
      //   /home/user/.openclaw/agents + ../.. = /home/user
      //   /home/user + etc/sessions = /home/user/etc/sessions
      expect(escaped).toBe(path.join("/home/user", "etc", "sessions"));
      expect(escaped.startsWith(path.join(root, "agents"))).toBe(false);
    });

    it("reaches the filesystem root with enough ../ levels", () => {
      const root = "/home/user/.openclaw";
      const escaped = path.join(root, "agents", "../../../../etc/shadow", "sessions");
      expect(escaped.startsWith(root)).toBe(false);
    });
  });

  // ── 2. normalizeAgentId currently strips traversal chars ─────────────────
  describe("normalizeAgentId strips dots and slashes (current mitigation)", () => {
    const traversalPayloads = [
      { input: "../../etc", expected: "etc" },
      { input: "../../../etc/passwd", expected: "etc-passwd" },
      { input: "a/../../../etc", expected: "a-etc" },
      { input: "..%2f..%2fetc", expected: "2f-2fetc" },
      { input: "....//....//etc", expected: "etc" },
      { input: "..", expected: "main" }, // collapses to empty → DEFAULT_AGENT_ID
    ];

    for (const { input, expected } of traversalPayloads) {
      it(`normalizes "${input}" → "${expected}"`, () => {
        expect(normalizeAgentId(input)).toBe(expected);
      });
    }
  });

  // ── 3. Exported wrappers stay in-bounds only via normalizeAgentId ────────
  describe("resolveSessionTranscriptsDirForAgent", () => {
    const cases = ["../../etc", "../../../etc/passwd", "a/../../../etc"];

    for (const maliciousId of cases) {
      it(`"${maliciousId}" resolves inside state dir (current defense)`, () => {
        const result = resolveSessionTranscriptsDirForAgent(maliciousId, fakeEnv, fakeHomedir);
        const agentsPrefix = path.join(STATE_DIR, "agents");
        expect(result.startsWith(agentsPrefix)).toBe(true);
      });
    }

    it("no explicit containment check — relies solely on normalizeAgentId", () => {
      // resolveAgentSessionsDir calls normalizeAgentId then path.join; it does
      // NOT verify the result starts with the state dir.  If normalizeAgentId
      // were ever relaxed (e.g. to allow dotted ids like "team.agent"), the
      // exact same path.join call would produce an escaped path.
      //
      // Contrast with resolvePathFromAgentSessionsDir (same file) which checks:
      //   if (relative.startsWith("..") || path.isAbsolute(relative)) return undefined;
      const result = resolveSessionTranscriptsDirForAgent("safe-id", fakeEnv, fakeHomedir);
      expect(result).toBe(path.join(STATE_DIR, "agents", "safe-id", "sessions"));
    });
  });

  // ── 4. resolveDefaultSessionStorePath — same gap ─────────────────────────
  describe("resolveDefaultSessionStorePath", () => {
    it("traversal payload neutralized by normalizeAgentId", () => {
      // We can't inject env here (no param), but the structure is the same:
      // path.join(resolveAgentSessionsDir(agentId), "sessions.json")
      const result = resolveDefaultSessionStorePath("../../etc");
      // normalizeAgentId("../../etc") → "etc"
      expect(result).toContain(path.join("agents", "etc", "sessions", "sessions.json"));
    });
  });

  // ── 5. Simulate what happens without normalizeAgentId sanitization ───────
  describe("without normalizeAgentId (mocked pass-through)", () => {
    it("resolveSessionTranscriptsDirForAgent escapes the state directory", async () => {
      // Reset module registry so paths.js picks up the mocked session-key.
      vi.resetModules();
      vi.doMock("../../routing/session-key.js", async () => {
        const actual = await vi.importActual<typeof import("../../routing/session-key.js")>(
          "../../routing/session-key.js",
        );
        return {
          ...actual,
          // Pass-through: simulate a future change that allows dots
          normalizeAgentId: (v: string | undefined | null) => (v ?? "").trim() || "main",
        };
      });

      const { resolveSessionTranscriptsDirForAgent: resolveUnsafe } = await import("./paths.js");
      const agentsPrefix = path.join(STATE_DIR, "agents");

      const result = resolveUnsafe("../../etc", fakeEnv, fakeHomedir);
      // path.join(STATE_DIR, "agents", "../../etc", "sessions")
      //   resolves ../ twice from "agents": up to STATE_DIR parent
      expect(result.startsWith(agentsPrefix)).toBe(false);

      vi.doUnmock("../../routing/session-key.js");
      vi.resetModules();
    });
  });
});
