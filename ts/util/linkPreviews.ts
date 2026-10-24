/* global URL */
import nodeUrl from 'url';
import { compact, isEmpty, isNumber, range } from 'lodash';
import LinkifyIt from 'linkify-it';

const linkifyIt = new LinkifyIt();

function maybeParseHref(href: string) {
  try {
    return new URL(href);
  } catch (err) {
    return null;
  }
}

const LOCAL_HOST_SUFFIXES = [
  '.localhost',
  '.local',
  '.localdomain',
  '.internal',
  '.intranet',
  '.lan',
  '.home',
  '.home.arpa',
  '.arpa',
  '.onion',
];

/**
 * Returns true for hostnames/IPs which only make sense locally (loopback, link-local, RFC1918,
 * CGNAT, multicast, ULA...). Fetching link previews for those lets a remote contact use our
 * client to probe services running on the machine or on the local network (SSRF / port scan),
 * and `169.254.169.254` is a well known cloud metadata endpoint.
 */
export function isLocalOrPrivateHostname(hostname: string) {
  const host = (hostname || '').trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (!host) {
    return true;
  }

  if (host === 'localhost' || LOCAL_HOST_SUFFIXES.some(suffix => host.endsWith(suffix))) {
    return true;
  }

  // IPv4 (WHATWG URL already normalises odd notations such as 2130706433 or 0x7f.1)
  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (ipv4) {
    const first = Number(ipv4[1]);
    const second = Number(ipv4[2]);
    if (first === 0 || first === 10 || first === 127) {
      return true;
    }
    if (first === 169 && second === 254) {
      return true;
    }
    if (first === 172 && second >= 16 && second <= 31) {
      return true;
    }
    if (first === 192 && second === 168) {
      return true;
    }
    if (first === 100 && second >= 64 && second <= 127) {
      return true;
    }
    // multicast / reserved / broadcast
    return first >= 224;
  }

  if (host.includes(':')) {
    // IPv6
    if (host === '::' || host === '::1') {
      return true;
    }
    // unique local addresses fc00::/7
    if (/^f[cd][0-9a-f]{2}:/.test(host)) {
      return true;
    }
    // link local fe80::/10
    if (/^fe[89ab][0-9a-f]:/.test(host)) {
      return true;
    }
    // IPv4 mapped addresses
    if (host.startsWith('::ffff:')) {
      return true;
    }
    return false;
  }

  // bare single-label hostnames (resolved through search domains) are not public
  return !host.includes('.');
}

function isLinkSafeToPreview(href: string) {
  const url = maybeParseHref(href);
  return Boolean(
    url &&
      url.protocol === 'https:' &&
      !isLinkSneaky(href) &&
      !isLocalOrPrivateHostname(url.hostname)
  );
}

function findLinks(text: string, caretLocation?: number) {
  const haveCaretLocation = isNumber(caretLocation);
  const textLength = text ? text.length : 0;

  const matches = linkifyIt.match(text || '') || [];
  return compact(
    matches.map(match => {
      if (!haveCaretLocation) {
        return match.text;
      }

      if (match.lastIndex === textLength && caretLocation === textLength) {
        return match.text;
      }

      if (match.index > caretLocation || match.lastIndex < caretLocation) {
        return match.text;
      }

      return null;
    })
  );
}

function getDomain(href: string) {
  const url = maybeParseHref(href);
  return url ? url.hostname : null;
}

// See <https://tools.ietf.org/html/rfc3986>.
const VALID_URI_CHARACTERS = new Set([
  '%',
  // "gen-delims"
  ':',
  '/',
  '?',
  '#',
  '[',
  ']',
  '@',
  // "sub-delims"
  '!',
  '$',
  '&',
  "'",
  '(',
  ')',
  '*',
  '+',
  ',',
  ';',
  '=',
  // unreserved
  ...String.fromCharCode(...range(65, 91), ...range(97, 123)),
  ...range(10).map(String),
  '-',
  '.',
  '_',
  '~',
]);
// eslint-disable-next-line prefer-regex-literals
const ASCII_PATTERN = new RegExp('[\\u0020-\\u007F]', 'g');
const MAX_HREF_LENGTH = 2 ** 12;

function isLinkSneaky(href: string) {
  // This helps users avoid extremely long links (which could be hiding something
  //   sketchy) and also sidesteps the performance implications of extremely long hrefs.
  if (href.length > MAX_HREF_LENGTH) {
    return true;
  }

  const url = maybeParseHref(href);

  // If we can't parse it, it's sneaky.
  if (!url) {
    return true;
  }

  // Any links which contain auth are considered sneaky
  if (url.username) {
    return true;
  }

  // If the domain is falsy, something fishy is going on
  if (!url.hostname) {
    return true;
  }

  // To quote [RFC 1034][0]: "the total number of octets that represent a
  //   domain name [...] is limited to 255." To be extra careful, we set a
  //   maximum of 2048. (This also uses the string's `.length` property,
  //   which isn't exactly the same thing as the number of octets.)
  // [0]: https://tools.ietf.org/html/rfc1034
  if (url.hostname.length > 2048) {
    return true;
  }

  // Domains cannot contain encoded characters
  if (url.hostname.includes('%')) {
    return true;
  }

  // There must be at least 2 domain labels, and none of them can be empty.
  const labels = url.hostname.split('.');
  if (labels.length < 2 || labels.some(isEmpty)) {
    return true;
  }

  // This is necessary because getDomain returns domains in punycode form.
  const unicodeDomain = nodeUrl.domainToUnicode
    ? nodeUrl.domainToUnicode(url.hostname)
    : url.hostname;

  const withoutPeriods = unicodeDomain.replace(/\./g, '');

  const hasASCII = ASCII_PATTERN.test(withoutPeriods);
  const withoutASCII = withoutPeriods.replace(ASCII_PATTERN, '');

  const isMixed = hasASCII && withoutASCII.length > 0;
  if (isMixed) {
    return true;
  }

  // We can't use `url.pathname` (and so on) because it automatically encodes strings.
  //   For example, it turns `/aquí` into `/aqu%C3%AD`.
  const startOfPathAndHash = href.indexOf('/', url.protocol.length + 4);
  const pathAndHash = startOfPathAndHash === -1 ? '' : href.substr(startOfPathAndHash);
  return [...pathAndHash].some(character => !VALID_URI_CHARACTERS.has(character));
}

export const LinkPreviews = { isLinkSneaky, getDomain, findLinks, isLinkSafeToPreview };
