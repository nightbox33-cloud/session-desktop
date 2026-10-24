#!/usr/bin/env node
/**
 * PoC #2 — Persistent conversation pinning with a forged `sent_at` (remote DoS, zero interaction).
 *
 * `shouldProcessContentMessage()` (ts/receiver/common.ts) validated the *content* timestamp against
 * the envelope timestamp but never bounded the envelope timestamp itself. On top of that, the
 * `sigTimestamp` check is skipped entirely for "legacy" messages (`if (!sigTimestampMs) return true`),
 * and any sender controls both fields anyway.
 *
 * The receiver then does, for every incoming message:
 *     conversation.setActiveAt(Math.max(activeAt, message.sent_at))
 *     if (message.sent_at > activeAt) conversation.setLastMessage(...)
 * and `active_at` is persisted in the database.
 *
 * So a single message dated in 2077 makes the conversation:
 *   - stay at the top of the left pane forever,
 *   - stop updating its last-message preview for every real message that follows,
 *   - and it survives app restarts (it is in `conversations.active_at`).
 * The only user-level recovery is deleting the whole conversation.
 *
 * Run: node security-poc/02_future_timestamp_pin.mjs
 */
import { DatabaseSync } from 'node:sqlite';

const NOW = Date.now();
const ATTACKER_SENT_AT = NOW + 50 * 365 * 24 * 60 * 60 * 1000; // ~50 years ahead
const MAX_FUTURE_MESSAGE_SKEW_MS = 24 * 60 * 60 * 1000; // the fix: 1 day

const db = new DatabaseSync(':memory:');
db.exec(`CREATE TABLE conversations (id TEXT PRIMARY KEY, active_at INTEGER, lastMessage TEXT);`);
db.exec(`CREATE TABLE messages (conversationId TEXT, sent_at INTEGER, body TEXT);`);
db.prepare(`INSERT INTO conversations VALUES ('05attacker', 0, NULL)`).run();

// What the receiver does today (ts/receiver/queuedJob.ts + dataMessage.ts):
function acceptMessage({ sent_at, body }, { boundFuture }) {
  const conv = db.prepare(`SELECT * FROM conversations WHERE id = '05attacker'`).get();
  // shouldProcessContentMessage() with the fix
  if (boundFuture && sent_at > Date.now() + MAX_FUTURE_MESSAGE_SKEW_MS) {
    return 'dropped (sent_at too far in the future)';
  }
  const newActiveAt = Math.max(conv.active_at || 0, sent_at);
  const updatesLastMessage = !conv.active_at || sent_at > conv.active_at;
  db.prepare(`UPDATE conversations SET active_at = ?, lastMessage = ? WHERE id = '05attacker'`).run(
    newActiveAt,
    updatesLastMessage ? body : conv.lastMessage
  );
  db.prepare(`INSERT INTO messages VALUES ('05attacker', ?, ?)`).run(sent_at, body);
  return updatesLastMessage ? 'stored, last message updated' : 'stored, last message NOT updated';
}

console.log('=== VULNERABLE (v1.18.3) ===');
console.log('1) attacker message dated +50y:', acceptMessage({ sent_at: ATTACKER_SENT_AT, body: 'hi' }, { boundFuture: false }));
console.log('2) real message from the same contact, 1 min later:',
  acceptMessage({ sent_at: NOW + 60000, body: 'are you there?' }, { boundFuture: false }));
const poisoned = db.prepare(`SELECT * FROM conversations`).get();
console.log('   conversation active_at now:', new Date(poisoned.active_at).toISOString());
console.log('   last message shown to the victim:', JSON.stringify(poisoned.lastMessage));
console.log('   -> the chat is pinned to the top until 2077 and its preview never updates again\n');

// Fresh DB for the fixed run
db.exec(`DELETE FROM conversations; DELETE FROM messages;`);
db.prepare(`INSERT INTO conversations VALUES ('05attacker', 0, NULL)`).run();

console.log('=== FIXED ===');
console.log('1) attacker message dated +50y:', acceptMessage({ sent_at: ATTACKER_SENT_AT, body: 'hi' }, { boundFuture: true }));
console.log('2) real message from the same contact, 1 min later:',
  acceptMessage({ sent_at: NOW + 60000, body: 'are you there?' }, { boundFuture: true }));
const healthy = db.prepare(`SELECT * FROM conversations`).get();
console.log('   last message shown to the victim:', JSON.stringify(healthy.lastMessage));
process.exitCode = poisoned.lastMessage === 'hi' && healthy.lastMessage === 'are you there?' ? 0 : 1;
