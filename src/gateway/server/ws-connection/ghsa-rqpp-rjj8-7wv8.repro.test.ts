/**
 * GHSA-rqpp-rjj8-7wv8 — Reproduction
 *
 * Vulnerability: device-less shared-token operators can self-declare elevated
 * scopes (e.g. "operator.admin") and the gateway retains them.
 *
 * Root cause (pre-fix): `clearUnboundScopes()` in message-handler.ts guarded
 * the clearing logic with `!sharedAuthOk`. Because shared-token/password
 * authenticated connections set `sharedAuthOk = true`, the condition
 * `!sharedAuthOk` short-circuited to `false` and scopes were never cleared.
 * Combined with `roleCanSkipDeviceIdentity(role, sharedAuthOk)` returning
 * `true` for operators with shared auth, any shared-token client could:
 *
 *   1. Connect with a valid shared token and no device identity
 *   2. Self-declare arbitrary scopes like `["operator.admin"]`
 *   3. Be accepted (decision = "allow") because roleCanSkipDeviceIdentity
 *      permits device-less operator connections with shared auth
 *   4. Retain the elevated scopes because clearUnboundScopes() was a no-op
 *      when sharedAuthOk was true
 *
 * Fix (commit 5e389d5e7c, PR #44306): removed the `!sharedAuthOk` guard from
 * `clearUnboundScopes()` and introduced `shouldClearUnboundScopesForMissingDeviceIdentity()`
 * (later refined in commit 8b88b927cb) to properly clear self-declared scopes
 * for all device-less shared-auth connections, with narrow exceptions for
 * allowBypass and local insecure control-UI paths.
 *
 * HOW TO RUN:
 *   pnpm test src/gateway/server/ws-connection/ghsa-rqpp-rjj8-7wv8.repro.test.ts
 *
 * WHAT PROVES THE BUG:
 *   Part 1 (unit): Simulates the pre-fix clearUnboundScopes logic inline and
 *     asserts that scopes survive (the vulnerability). Then asserts the fixed
 *     shouldClearUnboundScopesForMissingDeviceIdentity correctly strips them.
 *   Part 2 (unit): Verifies evaluateMissingDeviceIdentity allows device-less
 *     shared-token operators, confirming the prerequisite for the exploit.
 */
import { describe, expect, test } from "vitest";
import {
  evaluateMissingDeviceIdentity,
  resolveControlUiAuthPolicy,
  shouldClearUnboundScopesForMissingDeviceIdentity,
  type ControlUiAuthPolicy,
} from "./connect-policy.js";

describe("GHSA-rqpp-rjj8-7wv8: shared-token scope retention bypass", () => {
  // Simulate the common scenario: a non-control-UI operator client connecting
  // with a shared token and no device identity.
  const nonControlUiPolicy: ControlUiAuthPolicy = resolveControlUiAuthPolicy({
    isControlUi: false,
    controlUiConfig: undefined,
    deviceRaw: null,
  });

  describe("Part 1: vulnerable clearUnboundScopes logic (pre-fix simulation)", () => {
    /**
     * Simulates the VULNERABLE clearUnboundScopes function that existed before
     * commit 5e389d5e7c:
     *
     *   const clearUnboundScopes = () => {
     *     if (scopes.length > 0 && !controlUiAuthPolicy.allowBypass && !sharedAuthOk) {
     *       scopes = [];
     *       connectParams.scopes = scopes;
     *     }
     *   };
     *
     * The `!sharedAuthOk` guard is the bug: it prevents clearing when the
     * client authenticated via shared token/password.
     */
    function vulnerableClearUnboundScopes(params: {
      scopes: string[];
      allowBypass: boolean;
      sharedAuthOk: boolean;
    }): string[] {
      const scopes = [...params.scopes];
      if (scopes.length > 0 && !params.allowBypass && !params.sharedAuthOk) {
        return [];
      }
      return scopes;
    }

    test("VULNERABLE: shared-token auth retains self-declared admin scopes (the exploit)", () => {
      // An attacker connects with valid shared token (sharedAuthOk = true),
      // no device identity, and self-declares operator.admin scope.
      const result = vulnerableClearUnboundScopes({
        scopes: ["operator.admin"],
        allowBypass: false,
        sharedAuthOk: true, // shared token authentication succeeded
      });
      // BUG: scopes are NOT cleared because !sharedAuthOk is false
      expect(result).toEqual(["operator.admin"]);
    });

    test("VULNERABLE: shared-password auth also retains self-declared scopes", () => {
      const result = vulnerableClearUnboundScopes({
        scopes: ["operator.admin", "operator.config"],
        allowBypass: false,
        sharedAuthOk: true,
      });
      expect(result).toEqual(["operator.admin", "operator.config"]);
    });

    test("non-shared-auth correctly clears scopes even in vulnerable code", () => {
      // Without shared auth, the vulnerable code still cleared scopes
      const result = vulnerableClearUnboundScopes({
        scopes: ["operator.admin"],
        allowBypass: false,
        sharedAuthOk: false,
      });
      expect(result).toEqual([]);
    });
  });

  describe("Part 2: prerequisite — device-less shared-token operators are allowed", () => {
    test("roleCanSkipDeviceIdentity allows device-less operator with sharedAuthOk", () => {
      // This is the prerequisite that makes the exploit possible: operators
      // with shared auth can skip device identity entirely.
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
      // The connection is allowed — this is by design for shared-token operators.
      // The problem was that scopes were not cleared afterward.
      expect(decision.kind).toBe("allow");
    });

    test("node role is still rejected without device identity (not exploitable)", () => {
      const decision = evaluateMissingDeviceIdentity({
        hasDeviceIdentity: false,
        role: "node",
        isControlUi: false,
        controlUiAuthPolicy: nonControlUiPolicy,
        trustedProxyAuthOk: false,
        sharedAuthOk: true,
        authOk: true,
        hasSharedAuth: true,
        isLocalClient: false,
      });
      expect(decision.kind).toBe("reject-device-required");
    });
  });

  describe("Part 3: fix verification — shouldClearUnboundScopesForMissingDeviceIdentity", () => {
    test("FIXED: shared-token auth now clears self-declared scopes", () => {
      const shouldClear = shouldClearUnboundScopesForMissingDeviceIdentity({
        decision: { kind: "allow" },
        controlUiAuthPolicy: nonControlUiPolicy,
        preserveInsecureLocalControlUiScopes: false,
        authMethod: "token",
      });
      expect(shouldClear).toBe(true);
    });

    test("FIXED: shared-password auth now clears self-declared scopes", () => {
      const shouldClear = shouldClearUnboundScopesForMissingDeviceIdentity({
        decision: { kind: "allow" },
        controlUiAuthPolicy: nonControlUiPolicy,
        preserveInsecureLocalControlUiScopes: false,
        authMethod: "password",
      });
      expect(shouldClear).toBe(true);
    });

    test("FIXED: trusted-proxy auth now clears self-declared scopes", () => {
      const shouldClear = shouldClearUnboundScopesForMissingDeviceIdentity({
        decision: { kind: "allow" },
        controlUiAuthPolicy: nonControlUiPolicy,
        preserveInsecureLocalControlUiScopes: false,
        authMethod: "trusted-proxy",
      });
      expect(shouldClear).toBe(true);
    });

    test("allowBypass preserves scopes (intentional break-glass path)", () => {
      const bypassPolicy = resolveControlUiAuthPolicy({
        isControlUi: true,
        controlUiConfig: { dangerouslyDisableDeviceAuth: true },
        deviceRaw: null,
      });
      const shouldClear = shouldClearUnboundScopesForMissingDeviceIdentity({
        decision: { kind: "allow" },
        controlUiAuthPolicy: bypassPolicy,
        preserveInsecureLocalControlUiScopes: false,
        authMethod: "token",
      });
      expect(shouldClear).toBe(false);
    });

    test("rejected decisions always clear scopes", () => {
      const shouldClear = shouldClearUnboundScopesForMissingDeviceIdentity({
        decision: { kind: "reject-device-required" },
        controlUiAuthPolicy: nonControlUiPolicy,
        preserveInsecureLocalControlUiScopes: false,
        authMethod: undefined,
      });
      expect(shouldClear).toBe(true);
    });
  });
});
