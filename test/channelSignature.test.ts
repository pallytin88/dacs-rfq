import { generateKeyPairSync } from "node:crypto";
import { describe, expect, test } from "vitest";
import { rawPublicKey } from "@kynesyslabs/dacs/crypto";
import { admitChannelMessage, prepareChannelMessageSigningInput } from "@kynesyslabs/dacs/negotiate";
import type { ChannelMessage, ChannelMessageSigningInput, RfqTurnBody, UnsignedChannelMessage } from "@kynesyslabs/dacs/negotiate";
import {
  CANONICAL_PROFILE_ID,
  PROVISIONAL_PROFILE_ID,
  createChannelSignatureAdapter,
  readCanonicalChannelMessage,
  signCanonicalChannelMessage,
  staticMemberAuthority,
  DACS_V06_PROFILE,
  defaultMemberKeyResolver,
} from "../src/channelSignature.js";
import { keyObjectSigner } from "../src/signer.js";
import type { ChannelMessageSignatureV1 } from "../src/channelSignature.js";

const BUYER = "did:demos:buyer-sig";
const SELLER = "did:demos:seller-sig";
const buyerKeys = generateKeyPairSync("ed25519");
const sellerKeys = generateKeyPairSync("ed25519");
const strangerKeys = generateKeyPairSync("ed25519");
const authority = staticMemberAuthority(new Map([
  [BUYER, rawPublicKey(buyerKeys.publicKey)],
  [SELLER, rawPublicKey(sellerKeys.publicKey)],
]));

const body: RfqTurnBody = {
  rfqBodyVersion: "1",
  proposal: { rfqProposalVersion: "1", price: { amount: "10", currency: "DEM" } },
};

function unsigned(sequence: number, sender = BUYER): UnsignedChannelMessage<RfqTurnBody> {
  return { canonicalChannelMessageVersion: "1", channelId: "chan-sig-1", sequence, sender, sentAt: 1_780_000_000_000, type: "offer", body } as UnsignedChannelMessage<RfqTurnBody>;
}

const ctx = { sessionChannelId: "chan-sig-1", lastSequence: 0, priorChannelIds: [] as string[] };

describe("channel signature adapter through the SDK seams", () => {
  const buyer = createChannelSignatureAdapter({ profile: CANONICAL_PROFILE_ID, signer: keyObjectSigner(BUYER, buyerKeys.privateKey), authority });
  const seller = createChannelSignatureAdapter({ profile: CANONICAL_PROFILE_ID, signer: keyObjectSigner(SELLER, sellerKeys.privateKey), authority });

  async function sign(envelope: UnsignedChannelMessage<RfqTurnBody>, adapter = buyer): Promise<ChannelMessage<RfqTurnBody, ChannelMessageSignatureV1>> {
    const input = prepareChannelMessageSigningInput(envelope) as Readonly<ChannelMessageSigningInput<RfqTurnBody>>;
    return { ...envelope, signature: await adapter.signChannelMessage(input) };
  }

  test("a message signed by one role verifies on the other", async () => {
    const message = await sign(unsigned(1));
    const admitted = await admitChannelMessage(message, ctx, seller.verifyChannelMessage);
    expect(admitted.decision).toBe("pass");
    expect(message.signature).toMatchObject({ signatureVersion: "1", signer: BUYER, algorithm: "ed25519" });
    expect(buyer.profileId).toBe(CANONICAL_PROFILE_ID);
  });

  test("a tampered envelope is rejected", async () => {
    const message = await sign(unsigned(1));
    const tampered = { ...message, body: { ...body, proposal: { rfqProposalVersion: "1", price: { amount: "1", currency: "DEM" } } } };
    const admitted = await admitChannelMessage(tampered, ctx, seller.verifyChannelMessage);
    expect(admitted.decision).toBe("fail");
  });

  test("a wrong sender is rejected even with a valid signature from the real key", async () => {
    // Stranger signs a message claiming to be the buyer.
    const stranger = createChannelSignatureAdapter({ profile: CANONICAL_PROFILE_ID, signer: keyObjectSigner(BUYER, strangerKeys.privateKey), authority });
    const forged = await sign(unsigned(1), stranger);
    expect((await admitChannelMessage(forged, ctx, seller.verifyChannelMessage)).decision).toBe("fail");

    // Seller's own key, but the envelope names the buyer as sender.
    const input = prepareChannelMessageSigningInput(unsigned(1, BUYER)) as Readonly<ChannelMessageSigningInput<RfqTurnBody>>;
    const sellerSig = createChannelSignatureAdapter({ profile: CANONICAL_PROFILE_ID, signer: keyObjectSigner(SELLER, sellerKeys.privateKey), authority });
    await expect(sellerSig.signChannelMessage(input)).rejects.toThrow(/does not match/);
    const mismatched = { ...unsigned(1, BUYER), signature: { ...(await sign(unsigned(1, SELLER), seller)).signature } };
    expect((await admitChannelMessage(mismatched, ctx, seller.verifyChannelMessage)).decision).toBe("fail");
  });

  test("a non-member sender is rejected", async () => {
    const outsider = createChannelSignatureAdapter({ profile: CANONICAL_PROFILE_ID, signer: keyObjectSigner("did:demos:outsider", strangerKeys.privateKey), authority });
    const message = await sign(unsigned(1, "did:demos:outsider"), outsider);
    expect((await admitChannelMessage(message, ctx, seller.verifyChannelMessage)).decision).toBe("fail");
  });

  test("a replayed sequence is rejected by the SDK admission gate", async () => {
    const message = await sign(unsigned(1));
    const first = await admitChannelMessage(message, ctx, seller.verifyChannelMessage);
    expect(first.decision).toBe("pass");
    const replay = await admitChannelMessage(message, { ...ctx, lastSequence: 1 }, seller.verifyChannelMessage);
    expect(replay.decision).toBe("fail");
  });

  test("the canonical profile signs the SDK's CH-8 bytes on an SDK at or after dacs-sdk#330", async () => {
    const canonical = createChannelSignatureAdapter({ profile: CANONICAL_PROFILE_ID, signer: keyObjectSigner(BUYER, buyerKeys.privateKey), authority });
    const input = prepareChannelMessageSigningInput(unsigned(1)) as Readonly<ChannelMessageSigningInput<RfqTurnBody>>;
    const message = { ...unsigned(1), signature: await canonical.signChannelMessage(input) };
    expect((await admitChannelMessage(message, ctx, seller.verifyChannelMessage)).decision).toBe("pass");
  });

  test("a message signed through the SDK seam also passes the standalone canonical reader", async () => {
    const message = await sign(unsigned(1));
    const result = await readCanonicalChannelMessage(message, ctx, {
      members: [BUYER, SELLER],
      profile: { authenticated: true, sessionId: "chan-sig-1", participantIdentities: [BUYER, SELLER], ...DACS_V06_PROFILE },
      expectedProfile: DACS_V06_PROFILE,
      resolve: authority.resolve,
    });
    expect(result.decision).toBe("pass");
  });
});

describe("canonical producer", () => {
  test("signs a discriminated message that the canonical reader accepts", async () => {
    const keys = generateKeyPairSync("ed25519");
    const claim = `key:${Buffer.from(rawPublicKey(keys.publicKey)).toString("hex")}`;
    const message = await signCanonicalChannelMessage({
      canonicalChannelMessageVersion: "1", channelId: "chan-c", sequence: 1, sender: claim,
      sentAt: 1, type: "offer", body: { price: "1" }, experimentalHint: { future: true },
    }, keyObjectSigner(claim, keys.privateKey));
    const result = await readCanonicalChannelMessage(message, { sessionChannelId: "chan-c", lastSequence: 0, priorChannelIds: [] }, {
      members: [claim, "key:" + "0".repeat(64)],
      profile: { authenticated: true, sessionId: "chan-c", participantIdentities: [claim, "key:" + "0".repeat(64)], ...DACS_V06_PROFILE },
      expectedProfile: DACS_V06_PROFILE,
      resolve: defaultMemberKeyResolver,
    });
    expect(result.decision).toBe("pass");
    expect(result.message?.experimentalHint).toEqual({ future: true });
  });
});
