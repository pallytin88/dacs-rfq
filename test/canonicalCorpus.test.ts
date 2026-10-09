/**
 * Runs the DACS-Standard `canonical-channel-message-v0.6.json` corpus (55
 * vectors, DACS-3 v0.6 CH-6..CH-10) against the canonical reader and the
 * explicit legacy-import arm. Every vector is executed; the only tolerated
 * deviation is for `sr1-aggregate`, which has no verifier here and must report
 * `indeterminate` rather than `pass` or `fail`.
 */

import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { describe, expect, test } from "vitest";
import {
  DACS_V06_PROFILE,
  defaultMemberKeyResolver,
  importLegacyChannelMessage,
  legacyMemberKeyResolver,
  readCanonicalChannelMessage,
} from "../src/channelSignature.js";
import type { MemberKeyResolution, VerificationDecision } from "../src/channelSignature.js";

interface Vector {
  name: string;
  expected: VerificationDecision;
  operation: "current-read" | "legacy-import";
  note?: string;
  message: unknown;
  ctx: unknown;
  profileAdmission?: unknown;
}

interface Corpus {
  set: string;
  count: number;
  hash: string;
  authenticatedKeyFixtures: Array<{
    claim: string;
    algorithm: string;
    publicKey: string;
    presentation?: string;
  }>;
  correctiveProfileFixture: { releasePin: string; moduleVersions: Record<string, string> };
  vectors: Vector[];
}

const corpusPath = new URL("./vectors/canonical-channel-message-v0.6.json", import.meta.url);
const raw = readFileSync(corpusPath, "utf8");
const corpus = JSON.parse(raw) as Corpus;

/** The fixture's verifier-owned CH-1 roster (the participant set every valid vector binds). */
const ROSTER = [
  "did:example:dacs-349-ecdsa",
  "did:example:dacs-349-sr1-root",
  "did:example:unresolved",
  "key:e70a5bcf97758337d7191df8e32ddd310933ce077937e36723b8b3be4dd69f57",
  "key:ea0c2afe8504c5500e1c28d05d4a2f214c076c8fc2c0db3225d13d1c1513d693",
];

/** The historical corpus roster: the senders the frozen `legacy-import` vectors bind. */
const LEGACY_ROSTER = [
  "cci:e70a5bcf97758337d7191df8e32ddd310933ce077937e36723b8b3be4dd69f57",
  "cci:acdcc8494d458f44a7aaac1d6a84ec624daee88436db2ae26e67ba645a106228",
];
const legacyAuthority = { members: LEGACY_ROSTER, profile: undefined, expectedProfile: DACS_V06_PROFILE, resolve: legacyMemberKeyResolver };

/** Vectors whose only unimplemented step is SR-1 aggregate verification. */
const SR1_VECTORS = new Set([
  "canonical-sr1-aggregate-valid",
  "canonical-sr1-aggregate-tampered-body",
  "canonical-sr1-aggregate-cross-domain",
  "canonical-sr1-aggregate-raw-digest-framing",
]);

function resolver(claim: string): MemberKeyResolution {
  const fixture = corpus.authenticatedKeyFixtures.find((f) => f.claim === claim);
  if (fixture !== undefined) {
    if (fixture.algorithm === "ecdsa-secp256k1") {
      return { status: "resolved", algorithm: "ecdsa-secp256k1", publicKey: Buffer.from(fixture.publicKey, "hex") };
    }
    if (fixture.algorithm === "sr1-aggregate") {
      return { status: "resolved", algorithm: "sr1-aggregate", publicKey: Buffer.from(fixture.publicKey, "hex") };
    }
  }
  return defaultMemberKeyResolver(claim);
}

describe("DACS-3 v0.6 canonical channel message corpus", () => {
  test("corpus is the pinned set", () => {
    expect(corpus.set).toBe("canonical-channel-message-v0.6");
    expect(corpus.vectors).toHaveLength(corpus.count);
    expect(corpus.vectors).toHaveLength(55);
    expect(corpus.correctiveProfileFixture.releasePin).toBe(DACS_V06_PROFILE.releasePin);
    expect(corpus.correctiveProfileFixture.moduleVersions).toEqual(DACS_V06_PROFILE.moduleVersions);
    // Record the exact bytes this run was checked against.
    const sha = createHash("sha256").update(raw).digest("hex");
    expect(sha).toMatch(/^[0-9a-f]{64}$/);
  });

  test.each(corpus.vectors.map((v) => [v.name, v] as const))("%s", async (_name, vector) => {
    const result = vector.operation === "legacy-import"
      ? await importLegacyChannelMessage(vector.message, vector.ctx, legacyAuthority)
      : await readCanonicalChannelMessage(vector.message, vector.ctx, {
          members: ROSTER, profile: vector.profileAdmission, expectedProfile: DACS_V06_PROFILE, resolve: resolver,
        });
    if (SR1_VECTORS.has(vector.name)) {
      expect(result.decision, `${vector.name}: ${result.reason ?? ""}`).toBe("indeterminate");
      return;
    }
    expect(result.decision, `${vector.name}: ${vector.note ?? ""} :: ${result.reason ?? ""}`).toBe(vector.expected);
  });

  test("a signer that does not parse is error, not an attributable fail (PR #332 F-332-2)", async () => {
    const vector = corpus.vectors.find((v) => v.operation === "current-read" && v.expected === "pass")!;
    const read = (signer: string) => readCanonicalChannelMessage(
      { ...(vector.message as Record<string, unknown>), signature: { ...((vector.message as { signature: Record<string, unknown> }).signature), signer } },
      vector.ctx, { members: ROSTER, profile: vector.profileAdmission, expectedProfile: DACS_V06_PROFILE, resolve: resolver },
    );
    for (const signer of ["not a claim", "cci:" + "ab".repeat(32), "demos:0x" + "ab".repeat(32)]) {
      expect((await read(signer)).decision, signer).toBe("error");
    }
    // A well-formed registered signer naming another member is the CH-7 fail.
    const sender = (vector.message as { sender: string }).sender;
    const other = ROSTER.find((m) => m !== sender)!;
    expect((await read(other)).decision).toBe("fail");
  });

  test("legacy-import admits exactly the frozen historical sender grammar (PR #332 F-332-3)", async () => {
    const vector = corpus.vectors.find((v) => v.operation === "legacy-import" && v.expected === "pass")!;
    const hex = "ab".repeat(32);
    const refused = [`key:${hex}`, `cci-xm:evm:mainnet:0x${hex}`, "lei:5493001kjtiigc8y1r12", "cci:not-hex", `cci:${hex.slice(0, 62)}`, `demos:0x${hex}`, "did:example", `cci:${hex}?v=1`, `CCI:${hex}`];
    for (const sender of refused) {
      const result = await importLegacyChannelMessage({ ...(vector.message as Record<string, unknown>), sender }, vector.ctx, legacyAuthority);
      expect(result.decision, sender).toBe("error");
      expect(result.reason, sender).toMatch(/frozen historical registry/);
    }
    // A pre-profile DID parses under the frozen grammar and reaches the roster check (an outsider: fail, not error).
    const did = await importLegacyChannelMessage({ ...(vector.message as Record<string, unknown>), sender: "did:example:member" }, vector.ctx, legacyAuthority);
    expect(did.decision).toBe("fail");
  });

  test("coverage summary", async () => {
    let matched = 0;
    for (const vector of corpus.vectors) {
      const result = vector.operation === "legacy-import"
        ? await importLegacyChannelMessage(vector.message, vector.ctx, legacyAuthority)
        : await readCanonicalChannelMessage(vector.message, vector.ctx, { members: ROSTER, profile: vector.profileAdmission, expectedProfile: DACS_V06_PROFILE, resolve: resolver });
      if (result.decision === vector.expected) matched += 1;
    }
    // 55 vectors, 4 of which need SR-1 aggregate verification we do not have.
    expect(matched).toBe(55 - SR1_VECTORS.size);
  });
});
