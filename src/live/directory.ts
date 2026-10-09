/**
 * Buyer-side catalog backed by the DACS Directory (the community front end,
 * `Community/reference-implementations/dacs-directory`; hosted instance at
 * `https://community-production-9ab1.up.railway.app`).
 *
 * The directory is treated as discovery only, never as truth: every hit is
 * re-read from chain at the anchor the directory names and run through the
 * SDK's own listing validation before it can be offered to the model. Hits
 * that fail stay out of the catalog and are logged with the failing step.
 */

import { canonicalDemosAgentPublicKey } from "@kynesyslabs/dacs/identity";
import type { AttestationRef } from "@kynesyslabs/dacs/artifacts";
import type { ListingCatalogEntry } from "../buyer/service.js";
import { discoverVerifiedListing } from "./listing.js";

export const DACS_DIRECTORY_URL = "https://community-production-9ab1.up.railway.app" as const;

export interface DirectoryListingSummary {
  listingId: string;
  version: number;
  contentHash: string;
  anchor: { kind: string; locator: string };
  seller: { primaryClaim: string; displayName?: string };
  artifactProfile: string;
  status: string;
  offering: { title: string; category: string; negotiation?: string[] };
  pricing: { kind?: string };
}

export interface DirectoryCatalogOptions {
  directoryUrl?: string;
  /** Only listings from these sellers are offered (the showcase seller). Omit for all. */
  sellers?: readonly string[];
  /** Only listings whose pipeline negotiates by RFQ. Default true. */
  rfqOnly?: boolean;
  readAnchor: (ref: string) => Promise<Record<string, unknown> | null>;
  /** Vet record ref to use for a seller when none is exchanged live (tests). */
  sellerVetRecordRef?: (sellerClaim: string) => AttestationRef;
  fetch?: typeof fetch;
  nowMs?: () => number;
  limit?: number;
  log?: (event: Readonly<Record<string, unknown>>) => void;
}

const PLACEHOLDER_VET: AttestationRef = { anchor: { kind: "storage-program", locator: "pending" }, contentHash: "0".repeat(64) };

export async function fetchDirectoryListings(options: Pick<DirectoryCatalogOptions, "directoryUrl" | "sellers" | "fetch" | "limit">): Promise<DirectoryListingSummary[]> {
  const base = (options.directoryUrl ?? DACS_DIRECTORY_URL).replace(/\/$/, "");
  const doFetch = options.fetch ?? fetch;
  const sellers = options.sellers === undefined ? [undefined] : options.sellers;
  const out: DirectoryListingSummary[] = [];
  for (const seller of sellers) {
    const params = new URLSearchParams({ limit: String(options.limit ?? 50), profile: "dacs-v0.1" });
    if (seller !== undefined) params.set("primaryClaim", seller);
    const response = await doFetch(`${base}/api/dacs/listings?${params.toString()}`, { headers: { accept: "application/json" } });
    if (!response.ok) throw new Error(`directory returned HTTP ${response.status}`);
    const body = await response.json() as { listings?: DirectoryListingSummary[] };
    for (const item of body.listings ?? []) out.push(item);
  }
  return out;
}

/** A `catalog()` for `createBuyerNegotiationService` that reads the directory and verifies from chain. */
export function createDirectoryCatalog(options: DirectoryCatalogOptions): () => Promise<ListingCatalogEntry[]> {
  const log = options.log ?? (() => {});
  const nowMs = options.nowMs ?? Date.now;
  return async () => {
    const summaries = await fetchDirectoryListings(options);
    const entries: ListingCatalogEntry[] = [];
    for (const summary of summaries) {
      if (summary.status !== "active") continue;
      if ((options.rfqOnly ?? true) && !(summary.offering.negotiation ?? []).includes("negotiate-rfq")) continue;
      const sellerPublicKey = canonicalDemosAgentPublicKey(summary.seller.primaryClaim);
      if (sellerPublicKey === null) {
        log({ event: "directory-skip", listingId: summary.listingId, reason: "seller claim is not a canonical Demos agent" });
        continue;
      }
      try {
        const verifiedListing = await discoverVerifiedListing({
          readAnchor: options.readAnchor, listingRef: summary.anchor.locator,
          sellerClaim: summary.seller.primaryClaim, sellerPublicKey, nowMs,
        });
        if (verifiedListing.pin.contentHash !== summary.contentHash) {
          log({ event: "directory-skip", listingId: summary.listingId, reason: "directory contentHash differs from chain bytes" });
          continue;
        }
        entries.push({
          verifiedListing,
          sellerClaim: summary.seller.primaryClaim,
          sellerVetRecordRef: options.sellerVetRecordRef?.(summary.seller.primaryClaim) ?? PLACEHOLDER_VET,
        });
      } catch (cause) {
        log({ event: "directory-skip", listingId: summary.listingId, version: summary.version, reason: cause instanceof Error ? cause.message : String(cause) });
      }
    }
    log({ event: "directory-catalog", offered: entries.length, seen: summaries.length });
    return entries;
  };
}
