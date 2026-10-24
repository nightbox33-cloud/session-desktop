#!/usr/bin/env node
/**
 * PoC #3 — Stale/replayed call OFFERs are accepted (`Math.max` used where `Math.abs` was meant).
 *
 * ts/receiver/callMessage.ts:
 *
 *     if (Math.max(envelope.sentAtMs - NetworkTime.now()) > TTL_DEFAULT.CALL_MESSAGE) { drop }
 *
 * `Math.max()` with a single argument is the identity function, so this only rejects offers whose
 * timestamp is more than TTL (5 minutes) *in the future*. An OFFER of any age is accepted, and the
 * check that was meant to bound the freshness of the offer does nothing.
 *
 * A caller can therefore replay an old OFFER (or re-inject one that was withheld by a malicious
 * swarm node) and make the victim's device ring with an obsolete call, repeatedly, with no rate
 * limit on incoming call messages.
 *
 * Run: node security-poc/03_call_offer_replay.mjs
 */
const TTL_DEFAULT_CALL_MESSAGE = 5 * 60 * 1000; // 5 minutes
const now = Date.now();

const offers = [
  { label: 'fresh offer (now - 10s)', sentAtMs: now - 10_000 },
  { label: 'stale offer (now - 6h)', sentAtMs: now - 6 * 60 * 60 * 1000 },
  { label: 'stale offer (now - 30d)', sentAtMs: now - 30 * 24 * 60 * 60 * 1000 },
  { label: 'future offer (now + 1h)', sentAtMs: now + 60 * 60 * 1000 },
];

const vulnAccepts = sentAtMs => Math.max(sentAtMs - now) <= TTL_DEFAULT_CALL_MESSAGE;
const fixedAccepts = sentAtMs => Math.abs(sentAtMs - now) <= TTL_DEFAULT_CALL_MESSAGE;

console.log('offer                              | v1.18.3  | fixed');
console.log('-----------------------------------+----------+-------');
let exploited = false;
for (const offer of offers) {
  const vuln = vulnAccepts(offer.sentAtMs);
  const fixed = fixedAccepts(offer.sentAtMs);
  if (vuln && !fixed) {
    exploited = true;
  }
  console.log(
    `${offer.label.padEnd(34)} | ${(vuln ? 'RINGS' : 'drop').padEnd(8)} | ${fixed ? 'RINGS' : 'drop'}`
  );
}
console.log(
  exploited
    ? '\n-> stale offers ring the victim in v1.18.3 and are dropped after the fix.'
    : '\n-> PoC did not reproduce the bug.'
);
process.exitCode = exploited ? 0 : 1;
