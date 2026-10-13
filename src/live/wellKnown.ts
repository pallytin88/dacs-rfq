/**
 * DACS-1 §6.3.5 discovery surface for the seller: an A2A `agent.json` with a
 * `dacs` block pointing at a hash-bound `listings.json`. The DACS Directory's
 * federation crawler reads exactly these two files from a public HTTPS domain,
 * verifies `indexHash` over the raw bytes of `listings.json`, and then reads
 * every listed anchor from chain itself. Shapes follow the Directory's own
 * generator (`app/api/dacs/wellknown-files/route.ts`, Community, MIT).
 */

import { contentHash, sha256Hex, stripSignature } from "@kynesyslabs/dacs/canonical";
import type { Listing } from "@kynesyslabs/dacs/artifacts";

export interface WellKnownListing {
  listing: Listing;
  /** Native storage-program locator, `stor-` + 40 hex. */
  locator: string;
  status: "active" | "revoked";
}

export interface WellKnownInput {
  sellerClaim: string;
  displayName: string;
  description?: string;
  /** Public HTTPS hostname the files will be served from (no scheme). */
  domain: string;
  listings: readonly WellKnownListing[];
  generatedAt?: number;
  identityClaims?: readonly string[];
}

export interface WellKnownFiles {
  "/.well-known/agent.json": string;
  "/.well-known/dacs/listings.json": string;
  indexHash: string;
  /** Lets the object be served as a static-document map. */
  [path: string]: string;
}

const LOCATOR = /^stor-[0-9a-f]{40}$/;

export function buildWellKnownFiles(input: WellKnownInput): WellKnownFiles {
  if (!/^did:demos:agent:[0-9a-f]{64}$/.test(input.sellerClaim)) throw new Error("seller claim must be a canonical Demos agent claim");
  const domain = input.domain.replace(/^https?:\/\//, "").replace(/\/$/, "");
  if (domain.length === 0 || /[/\s]/.test(domain)) throw new Error("domain must be a bare hostname");
  const entries = input.listings.map(({ listing, locator, status }) => {
    if (!LOCATOR.test(locator)) throw new Error(`locator ${locator} is not stor-<40 hex>`);
    const pricing = listing.pricing as { kind: string; price?: { amount: string; currency: string }; bandCenter?: { amount: string; currency: string } };
    const priceHint = pricing.kind === "fixed" && pricing.price ? `${pricing.price.amount} ${pricing.price.currency}`
      : pricing.kind === "negotiable" && pricing.bandCenter ? `~${pricing.bandCenter.amount} ${pricing.bandCenter.currency} (negotiable)` : undefined;
    return {
      listingId: listing.listingId,
      version: listing.listingVersion,
      contentHash: contentHash(stripSignature(listing as unknown as Record<string, unknown>) as Record<string, unknown>),
      anchor: { kind: "storage-program", locator },
      summary: {
        title: listing.offering.title, category: listing.offering.category, tags: listing.offering.tags,
        ...(priceHint === undefined ? {} : { priceHint }),
      },
      status,
    };
  });
  const listingsJson = JSON.stringify({ indexVersion: "1", generatedAt: input.generatedAt ?? Date.now(), seller: input.sellerClaim, listings: entries }, null, 2);
  const indexHash = sha256Hex(listingsJson);
  const active = input.listings.filter((l) => l.status === "active");
  const agentJson = JSON.stringify({
    name: input.displayName,
    description: input.description ?? active[0]?.listing.offering.description ?? "DACS seller",
    url: `https://${domain}`,
    version: "1.0.0",
    protocolVersion: "0.3.0",
    preferredTransport: "HTTP+JSON",
    capabilities: { streaming: false, pushNotifications: false, stateTransitionHistory: false },
    defaultInputModes: ["application/json", "text/plain"],
    defaultOutputModes: ["application/json"],
    skills: active.map(({ listing }) => ({
      id: listing.listingId, name: listing.offering.title, description: listing.offering.description ?? "DACS service", tags: listing.offering.tags,
    })),
    dacs: {
      dacsVersion: "1",
      listings: { indexUrl: `https://${domain}/.well-known/dacs/listings.json`, indexHash: `sha256-${indexHash}` },
      identityClaims: input.identityClaims ?? [input.sellerClaim],
    },
  }, null, 2);
  return { "/.well-known/agent.json": agentJson, "/.well-known/dacs/listings.json": listingsJson, indexHash };
}
