/**
 * CORE §11.1.2(3) corrective-profile admission for this deployment.
 *
 * The SDK refuses every live RFQ operation until a verifier-owned authority
 * says that this exact profile (release pin plus the complete module tuple)
 * is what every participant of the session runs. That authority has to come
 * from trusted context the caller cannot supply: here it is the operator's
 * configured profile and the operator's peer table (the configured counterpart
 * and the registrations the operator admitted). A session is admitted only
 * when both participants are canonical members of that table and one of them
 * is this role itself; anything else is left unresolved, which the SDK turns
 * into an `indeterminate` refusal before any signer, policy or store write.
 */

import type { ChannelCorrectiveProfile, RfqLifecycleProfileAdmission, RfqProfileAdmission } from "@kynesyslabs/dacs/negotiate";
import { DACS_V06_PROFILE, canonicalIdentity } from "./channelSignature.js";

/**
 * The coordinated corrective candidate this package is built and tested
 * against: CORE v0.3, DACS-1 v0.8, DACS-2 v0.6, DACS-3 v0.6, DACS-4 v0.8,
 * DACS-5 v0.7, pinned by the canonical-channel-message-v0.6 corpus. One
 * constant for the whole package: the signature module's `DACS_V06_PROFILE`.
 */
export const DEPLOYMENT_CORRECTIVE_PROFILE: ChannelCorrectiveProfile = DACS_V06_PROFILE;

export interface ProfileAdmissionOptions {
  /** This role's own canonical claim; every admitted session includes it. */
  self: string;
  /** Live view of the claims this operator treats as members (configured counterpart + admitted registrations). */
  members: () => Iterable<string>;
  /** The exact profile this deployment is configured for. Default: the corpus pin. */
  profile?: ChannelCorrectiveProfile;
  /** Provenance label recorded on the authority (no authority by itself). */
  source?: string;
  log?: (event: Readonly<Record<string, unknown>>) => void;
}

/** Canonical identity of a claim (CF-3), or null when it is not a claim this deployment can place. */
function identityOf(claim: string): string | null {
  const identity = canonicalIdentity(claim);
  return /^[a-z][a-z0-9-]*:[^\s?]+$/i.test(identity) ? identity : null;
}

/**
 * Build the resolver `createDurableRfqLifecycleClient` consults on every
 * operation. It returns the admission with an authority bound to the exact
 * session and both participants, or `undefined` when this deployment holds no
 * authority for that session.
 */
export function createProfileAdmission(options: ProfileAdmissionOptions): RfqLifecycleProfileAdmission {
  const profile = options.profile ?? DEPLOYMENT_CORRECTIVE_PROFILE;
  const log = options.log ?? (() => {});
  const selfIdentity = identityOf(options.self);
  if (selfIdentity === null) throw new Error("self claim is not a canonical claim");
  return (request): RfqProfileAdmission | undefined => {
    const participants = request.participantIdentities;
    const members = new Set<string>();
    for (const claim of options.members()) { const id = identityOf(claim); if (id !== null) members.add(id); }
    members.add(selfIdentity);
    const identities = participants.map(identityOf);
    const refuse = (reason: string): undefined => {
      log({ event: "profile-admission-withheld", jobId: request.jobId, channelId: request.channelId, role: request.role, reason });
      return undefined;
    };
    if (participants.length !== 2 || identities.some((id) => id === null)) return refuse("participants are not two canonical claims");
    if (identities[0] === identities[1]) return refuse("participants are the same identity");
    if (!identities.includes(selfIdentity)) return refuse("this role is not a participant");
    const stranger = participants.find((claim, index) => !members.has(identities[index]!));
    if (stranger !== undefined) return refuse(`participant is not an admitted member: ${stranger}`);
    return {
      profile,
      authority: {
        authenticated: true,
        sessionId: request.channelId,
        participantIdentities: [participants[0]!, participants[1]!],
        releasePin: profile.releasePin,
        moduleVersions: profile.moduleVersions,
        source: options.source ?? "colony-rfq:operator-peer-table",
      },
    };
  };
}
