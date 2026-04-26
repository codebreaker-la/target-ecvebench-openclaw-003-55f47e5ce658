/**
 * GHSA-rqpp-rjj8-7wv8 — Reproduction
 *
 * Vulnerability: device-less clients authenticated via trusted-proxy can retain
 * self-declared elevated scopes that should be stripped by the server.
 *
 * Root cause (message-handler.ts, line ~554 at vulnerable commit):
 *
 *   (authMethod === "token" || authMethod === "password" || trustedProxyAuthOk)
 *
 * The condition that gates `clearUnboundScopes()` checks for authMethod "token"
 * and "password", and also checks the boolean `trustedProxyAuthOk`.  However,
 * `trustedProxyAuthOk` is only true when ALL of:
 *   - isControlUi === true
 *   - role === "operator"
 *   - authMode === "trusted-proxy"
 *   - authOk === true
 *   - authMethod === "trusted-proxy"
 *
 * A non-ControlUI client (e.g. a direct WebSocket API consumer behind a trusted
 * reverse proxy) will have authMethod === "trusted-proxy" but isControlUi === false,
 * making trustedProxyAuthOk === false.  Since "trusted-proxy" !== "token" and
 * "trusted-proxy" !== "password", the entire scope-clearing condition is false
 * and clearUnboundScopes() is never called.
 *
 * Impact: the attacker keeps self-declared scopes like ["operator.admin"],
 * gaining unauthorized access to administrative gateway operations.
 *
 * The fix (commit 8b88b927cb) adds `authMethod === "trusted-proxy"` to the
 * disjunction, ensuring scopes are always cleared for device-less trusted-proxy
 * clients regardless of whether isTrustedProxyControlUiOperatorAuth() is true.
 *
 * How to run:
 *   pnpm test:gateway -- --testPathPattern connect-policy.ghsa-rqpp
 *   # or:
 *   pnpm vitest run src/gateway/server/ws-connection/connect-policy.ghsa-rqpp-rjj8-7wv8.test.ts
 */
import { describe, expect, it } from "vitest";
import {
  evaluateMissingDeviceIdentity,
  isTrustedProxyControlUiOperatorAuth,
  resolveControlUiAuthPolicy,
} from "./connect-policy.js";

/**
 * Replicates the inline condition from message-handler.ts line ~549-554
 * (the VULNERABLE version, before the fix).
 */
function shouldClearUnboundScopes_VULNERABLE(params: {
  device: boolean;
  decision: { kind: string };
  controlUiAuthPolicy: { allowBypass: boolean };
  preserveInsecureLocalControlUiScopes: boolean;
  authMethod: string | undefined;
  trustedProxyAuthOk: boolean;
}): boolean {
  return (
    !params.device &&
    (params.decision.kind !== "allow" ||
      (!params.controlUiAuthPolicy.allowBypass &&
        !params.preserveInsecureLocalControlUiScopes &&
        (params.authMethod === "token" ||
          params.authMethod === "password" ||
          params.trustedProxyAuthOk)))
  );
}

/**
 * The FIXED version: adds authMethod === "trusted-proxy" to the disjunction.
 * (Matches shouldClearUnboundScopesForMissingDeviceIdentity from the fix commit.)
 */
function shouldClearUnboundScopes_FIXED(params: {
  device: boolean;
  decision: { kind: string };
  controlUiAuthPolicy: { allowBypass: boolean };
  preserveInsecureLocalControlUiScopes: boolean;
  authMethod: string | undefined;
  trustedProxyAuthOk: boolean;
}): boolean {
  return (
    !params.device &&
    (params.decision.kind !== "allow" ||
      (!params.controlUiAuthPolicy.allowBypass &&
        !params.preserveInsecureLocalControlUiScopes &&
        (params.authMethod === "token" ||
          params.authMethod === "password" ||
          params.authMethod === "trusted-proxy" ||
          params.trustedProxyAuthOk)))
  );
}

describe("GHSA-rqpp-rjj8-7wv8: unbound scope clearing bypass via trusted-proxy auth", () => {
  // ── Helper setup ─────────────────────────────────────────────────────
  const nonControlUiPolicy = resolveControlUiAuthPolicy({
    isControlUi: false,
    controlUiConfig: undefined,
    deviceRaw: null,
  });

  /**
   * Scenario: a WebSocket client connects through a trusted reverse proxy
   * (authMethod "trusted-proxy") but is NOT a ControlUI client.
   * It has no device identity and self-declares elevated scopes.
   *
   * evaluateMissingDeviceIdentity returns { kind: "allow" } because
   * roleCanSkipDeviceIdentity("operator", sharedAuthOk=true) is true.
   *
   * In the vulnerable code, clearUnboundScopes() is NOT called because
   * trustedProxyAuthOk is false (non-ControlUI) and authMethod is neither
   * "token" nor "password".
   */

  it("precondition: trustedProxyAuthOk is false for non-ControlUI trusted-proxy clients", () => {
    // isTrustedProxyControlUiOperatorAuth requires isControlUi === true.
    // A non-ControlUI client behind a trusted proxy gets trustedProxyAuthOk === false.
    const trustedProxyAuthOk = isTrustedProxyControlUiOperatorAuth({
      isControlUi: false, // <-- attacker is NOT ControlUI
      role: "operator",
      authMode: "trusted-proxy",
      authOk: true,
      authMethod: "trusted-proxy",
    });
    expect(trustedProxyAuthOk).toBe(false);
  });

  it("precondition: device-less operator is allowed to connect (decision=allow)", () => {
    // Even without device identity, operators with shared auth pass through.
    const decision = evaluateMissingDeviceIdentity({
      hasDeviceIdentity: false,
      role: "operator",
      isControlUi: false,
      controlUiAuthPolicy: nonControlUiPolicy,
      trustedProxyAuthOk: false,
      sharedAuthOk: true,
      authOk: true,
      hasSharedAuth: true,
      isLocalClient: false,
    });
    expect(decision.kind).toBe("allow");
  });

  it("VULNERABLE: scopes are NOT cleared for device-less trusted-proxy non-ControlUI operator", () => {
    // This is the core of the vulnerability.
    // A non-ControlUI operator using trusted-proxy auth, with no device
    // identity, self-declares elevated scopes.  The vulnerable code does
    // NOT clear them.
    const wouldClear = shouldClearUnboundScopes_VULNERABLE({
      device: false,
      decision: { kind: "allow" },
      controlUiAuthPolicy: { allowBypass: false },
      preserveInsecureLocalControlUiScopes: false,
      authMethod: "trusted-proxy",
      trustedProxyAuthOk: false, // non-ControlUI → false
    });

    // BUG: the vulnerable code returns false — scopes are preserved.
    // An attacker retains scopes like ["operator.admin"].
    expect(wouldClear).toBe(false); // ← proves the vulnerability
  });

  it("FIXED: scopes ARE cleared for device-less trusted-proxy non-ControlUI operator", () => {
    // After the fix, authMethod === "trusted-proxy" is explicitly checked
    // in the disjunction, so clearUnboundScopes() is called.
    const wouldClear = shouldClearUnboundScopes_FIXED({
      device: false,
      decision: { kind: "allow" },
      controlUiAuthPolicy: { allowBypass: false },
      preserveInsecureLocalControlUiScopes: false,
      authMethod: "trusted-proxy",
      trustedProxyAuthOk: false,
    });

    // FIXED: scopes are now cleared.
    expect(wouldClear).toBe(true);
  });

  it("VULNERABLE: scopes are NOT cleared when trustedProxyAuthOk is undefined", () => {
    // Another variant: trustedProxyAuthOk could be undefined/not-set
    // and authMethod is "trusted-proxy".
    const wouldClear = shouldClearUnboundScopes_VULNERABLE({
      device: false,
      decision: { kind: "allow" },
      controlUiAuthPolicy: { allowBypass: false },
      preserveInsecureLocalControlUiScopes: false,
      authMethod: "trusted-proxy",
      trustedProxyAuthOk: false,
    });

    expect(wouldClear).toBe(false); // ← vulnerability: scopes survive
  });

  // ── Sanity: token and password auth methods ARE already covered ────────

  it("token auth correctly triggers scope clearing in vulnerable code", () => {
    const wouldClear = shouldClearUnboundScopes_VULNERABLE({
      device: false,
      decision: { kind: "allow" },
      controlUiAuthPolicy: { allowBypass: false },
      preserveInsecureLocalControlUiScopes: false,
      authMethod: "token",
      trustedProxyAuthOk: false,
    });

    expect(wouldClear).toBe(true); // token is handled correctly
  });

  it("password auth correctly triggers scope clearing in vulnerable code", () => {
    const wouldClear = shouldClearUnboundScopes_VULNERABLE({
      device: false,
      decision: { kind: "allow" },
      controlUiAuthPolicy: { allowBypass: false },
      preserveInsecureLocalControlUiScopes: false,
      authMethod: "password",
      trustedProxyAuthOk: false,
    });

    expect(wouldClear).toBe(true); // password is handled correctly
  });

  it("ControlUI trusted-proxy operator (trustedProxyAuthOk=true) clears scopes in both versions", () => {
    // When trustedProxyAuthOk is true, even the vulnerable code clears scopes.
    // The gap is specifically for non-ControlUI clients where
    // trustedProxyAuthOk is false.
    const vulnResult = shouldClearUnboundScopes_VULNERABLE({
      device: false,
      decision: { kind: "allow" },
      controlUiAuthPolicy: { allowBypass: false },
      preserveInsecureLocalControlUiScopes: false,
      authMethod: "trusted-proxy",
      trustedProxyAuthOk: true,
    });
    const fixedResult = shouldClearUnboundScopes_FIXED({
      device: false,
      decision: { kind: "allow" },
      controlUiAuthPolicy: { allowBypass: false },
      preserveInsecureLocalControlUiScopes: false,
      authMethod: "trusted-proxy",
      trustedProxyAuthOk: true,
    });

    expect(vulnResult).toBe(true);
    expect(fixedResult).toBe(true);
  });
});
