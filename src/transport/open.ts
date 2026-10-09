/**
 * Session announcement over the interim transport.
 *
 * The SDK's lifecycle requires both roles to `open()` the same session (same
 * jobId, channelId, verified Listing pin and party bundles) before the first
 * turn. The buyer therefore announces the session it is about to open; the
 * seller validates the announcement against its own Listing and opens its
 * side. The announcement is stored in the seller's inbox like any packet and
 * is acknowledged only after persistence, so it is replay- and restart-safe.
 */

import type { AttestationRef, IdentityBundle } from "@kynesyslabs/dacs/artifacts";
import type { ListingPin } from "@kynesyslabs/dacs/artifacts";

export interface RfqSessionAnnouncement {
  packetVersion: "1";
  kind: "open";
  packetId: string;
  jobId: string;
  channelId: string;
  sender: string;
  recipient: string;
  listingPin: ListingPin;
  buyer: { identityBundle: IdentityBundle; vetRecordRef: AttestationRef };
  /** The buyer's signed and anchored vet of the seller (seller.vetRecordRef for both sides). */
  sellerVetRef: AttestationRef;
  announcedAt: number;
}

export function announcementPacketId(jobId: string): string {
  return `open:${jobId}`;
}

export function isSessionAnnouncement(value: unknown): value is RfqSessionAnnouncement {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const v = value as Record<string, unknown>;
  return v["packetVersion"] === "1" && v["kind"] === "open" &&
    typeof v["packetId"] === "string" && typeof v["jobId"] === "string" && v["packetId"] === announcementPacketId(v["jobId"] as string) &&
    typeof v["channelId"] === "string" && typeof v["sender"] === "string" && typeof v["recipient"] === "string" &&
    typeof v["listingPin"] === "object" && v["listingPin"] !== null &&
    typeof v["buyer"] === "object" && v["buyer"] !== null &&
    typeof v["sellerVetRef"] === "object" && v["sellerVetRef"] !== null && typeof v["announcedAt"] === "number";
}
