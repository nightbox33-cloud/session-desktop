import { type BaseDecodedEnvelope } from './types';
import { DURATION } from '../session/constants';
import { longOrNumberToNumber } from '../types/long/longOrNumberToNumber';
import { NetworkTime } from '../util/NetworkTime';

/**
 * How far in the future a message timestamp is allowed to be.
 *
 * `sentAt` is chosen by the sender and is *not* bounded by the network. Without a bound, anybody
 * can date a message years ahead: the conversation gets `active_at` in the far future, it is
 * pinned to the top of the left pane, and every later message of that conversation stops updating
 * the last message (and disappears-messages timers are computed from it). The poisoning survives
 * restarts because `active_at` is stored in the DB. A day is loose enough for any clock skew.
 */
export const MAX_FUTURE_MESSAGE_SKEW_MS = DURATION.DAYS;

export function getEnvelopeId(envelope: BaseDecodedEnvelope) {
  if (envelope.source) {
    return `${envelope.source} ${longOrNumberToNumber(envelope.sentAtMs)} (${envelope.id})`;
  }

  return envelope.id;
}

export function shouldProcessContentMessage({
  sentAtMs,
  isCommunity,
  sigTimestampMs = 0,
}: {
  sentAtMs: number;
  sigTimestampMs: number | undefined;
  isCommunity: boolean;
}) {
  const maybeEnvelopeTimestamp = longOrNumberToNumber(sentAtMs);
  if (maybeEnvelopeTimestamp && maybeEnvelopeTimestamp > NetworkTime.now() + MAX_FUTURE_MESSAGE_SKEW_MS) {
    window?.log?.warn(
      `shouldProcessContentMessage: dropping a message dated too far in the future: ${maybeEnvelopeTimestamp} (now ${NetworkTime.now()})`
    );
    return false;
  }

  // FIXME: drop this case once the change has been out in the wild long enough
  if (!sentAtMs || !longOrNumberToNumber(sigTimestampMs)) {
    // legacy client
    return true;
  }
  const envelopeTimestamp = longOrNumberToNumber(sentAtMs);
  const contentTimestamp = longOrNumberToNumber(sigTimestampMs);
  if (!isCommunity) {
    return envelopeTimestamp === contentTimestamp;
  }
  // we want to process a community message and allow a window of 6 hours
  return Math.abs(envelopeTimestamp - contentTimestamp) <= 6 * DURATION.HOURS;
}
