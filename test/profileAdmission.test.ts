import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";
import { DEPLOYMENT_CORRECTIVE_PROFILE, createProfileAdmission } from "../src/profileAdmission.js";

const BUYER = "did:demos:agent:" + "c0".repeat(32);
const SELLER = "did:demos:agent:" + "70".repeat(32);
const OTHER = "did:demos:agent:" + "11".repeat(32);
const request = (participants: readonly [string, string], channelId = "rfq-chan-1") => ({ role: "seller" as const, jobId: "01M4DZJS6XXKHB721MSRVVT1RQ", channelId, participantIdentities: participants });

describe("deployment corrective profile", () => {
  test("is exactly the corpus fixture's pin and complete module tuple", () => {
    const corpus = JSON.parse(readFileSync(new URL("./vectors/canonical-channel-message-v0.6.json", import.meta.url), "utf8")) as { correctiveProfileFixture: { releasePin: string; moduleVersions: Record<string, string> } };
    expect(DEPLOYMENT_CORRECTIVE_PROFILE.releasePin).toBe(corpus.correctiveProfileFixture.releasePin);
    expect({ ...DEPLOYMENT_CORRECTIVE_PROFILE.moduleVersions }).toEqual(corpus.correctiveProfileFixture.moduleVersions);
  });
});

describe("createProfileAdmission", () => {
  test("admits a session between this role and an admitted member, bound to that exact session and those two participants", () => {
    const events: Record<string, unknown>[] = [];
    const admit = createProfileAdmission({ self: SELLER, members: () => [BUYER], log: (e) => events.push({ ...e }) });
    const granted = admit(request([BUYER, SELLER]));
    expect(granted).toMatchObject({
      profile: DEPLOYMENT_CORRECTIVE_PROFILE,
      authority: { authenticated: true, sessionId: "rfq-chan-1", participantIdentities: [BUYER, SELLER], releasePin: DEPLOYMENT_CORRECTIVE_PROFILE.releasePin, moduleVersions: DEPLOYMENT_CORRECTIVE_PROFILE.moduleVersions },
    });
    expect(granted).not.toHaveProperty("participantIdentities");
    // A CH-7 parameter-qualified spelling of a member resolves to that member.
    expect(admit(request([`${BUYER}?role=buyer`, SELLER]))).toBeDefined();
    expect(events).toHaveLength(0);
  });

  test("withholds authority for a stranger, a session without this role, a self-session, or a malformed participant list", () => {
    const events: Record<string, unknown>[] = [];
    const admit = createProfileAdmission({ self: SELLER, members: () => [BUYER], log: (e) => events.push({ ...e }) });
    expect(admit(request([OTHER, SELLER]))).toBeUndefined();
    expect(admit(request([BUYER, OTHER]))).toBeUndefined();
    expect(admit(request([SELLER, SELLER]))).toBeUndefined();
    expect(admit(request(["not-a-claim", SELLER]))).toBeUndefined();
    expect(events.map((e) => e["event"])).toEqual(Array(4).fill("profile-admission-withheld"));
  });

  test("the member view is live: a registration admitted later is honoured without rebuilding the resolver", () => {
    const members = new Set<string>();
    const admit = createProfileAdmission({ self: SELLER, members: () => members });
    expect(admit(request([OTHER, SELLER]))).toBeUndefined();
    members.add(OTHER);
    expect(admit(request([OTHER, SELLER]))).toBeDefined();
  });
});
