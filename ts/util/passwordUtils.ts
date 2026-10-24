import * as crypto from 'crypto';
import { isString } from 'lodash';
import { PASSWORD_LENGTH } from '../session/constants';
import { tr } from '../localization/localeTools';

const sha512 = (text: string) => {
  const hash = crypto.createHash('sha512');
  hash.update(text, 'utf8');
  return hash.digest('hex');
};

export const generateHash = (phrase: string) => phrase && sha512(phrase);

/**
 * Compares the provided phrase with the stored hash in constant time.
 *
 * NOTE: the hash is only used to confirm that the user knows the current passphrase before
 * changing/removing it. The database itself is encrypted with the passphrase through SQLCipher,
 * which is what actually protects the data. We still avoid a plain `===` comparison, because
 * that leaks the length of the matching prefix through timing.
 */
export const matchesHash = (phrase: string | null, hash: string | null | undefined) => {
  if (!phrase || !hash || !isString(hash)) {
    return false;
  }

  const a = Buffer.from(sha512(phrase), 'utf8');
  const b = Buffer.from(hash, 'utf8');
  if (a.length !== b.length) {
    return false;
  }

  return crypto.timingSafeEqual(a, b);
};

const passwordArgs = {
  min: PASSWORD_LENGTH.MIN_PASSWORD_LEN.toString(),
  max: PASSWORD_LENGTH.MAX_PASSWORD_LEN.toString(),
};

// Letters, numbers and a conservative set of symbols.
// `'`, `"`, `\`, control characters and newlines are intentionally rejected: this passphrase is
// interpolated into the SQLCipher `rekey = ...` pragma statement, which has no bind parameters.
const ALLOWED_PASSWORD_REGEX = /^[a-zA-Z0-9\-!?/()._`~@#$%^&*+=[\]{}|<>,;: ]+$/;

export const validatePassword = (phrase: string) => {
  if (!isString(phrase)) {
    return tr('passwordError');
  }

  if (phrase.length === 0) {
    return tr('passwordErrorLength', passwordArgs);
  }

  if (
    phrase.length < PASSWORD_LENGTH.MIN_PASSWORD_LEN ||
    phrase.length > PASSWORD_LENGTH.MAX_PASSWORD_LEN
  ) {
    return tr('passwordErrorLength', passwordArgs);
  }

  if (!ALLOWED_PASSWORD_REGEX.test(phrase)) {
    return tr('passwordError');
  }

  return null;
};
