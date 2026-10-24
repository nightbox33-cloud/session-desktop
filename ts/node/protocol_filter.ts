import path from 'path';
import fs from 'fs';
import { Protocol, ProtocolRequest } from 'electron';

function eliminateAllAfterCharacter(str: string, character: string) {
  const index = str.indexOf(character);
  if (index < 0) {
    return str;
  }

  return str.slice(0, index);
}

/**
 * Converts a `file://` url into a filesystem path.
 *
 * `decodeURIComponent` throws on malformed input (e.g. a lone `%`), so we must never let that
 * exception escape: this runs inside the protocol handler of the main process, where a throw
 * becomes an unhandled exception.
 */
function urlToPath(targetUrl: string, options: { isWindows?: boolean }) {
  const { isWindows } = options;

  let decoded: string;
  try {
    decoded = decodeURIComponent(targetUrl);
  } catch (e) {
    return null;
  }

  // Only ever accept the `file:` scheme. Slicing a fixed amount of characters would happily
  // "convert" any other scheme into a path (e.g. `http://host/x` -> `//host/x`).
  const scheme = 'file://';
  if (!decoded.toLowerCase().startsWith(scheme)) {
    return null;
  }

  let withoutScheme = decoded.slice(scheme.length);
  if (isWindows) {
    // `file:///C:/app/index.html` and `file://C:/app/index.html` are both valid on windows.
    while (withoutScheme.startsWith('/') || withoutScheme.startsWith('\\')) {
      withoutScheme = withoutScheme.slice(1);
    }
  }
  // On non-windows the path is already absolute (`/home/user/...`), on windows the leading
  // slashes belong to the url and not to the path, so they were stripped above.
  const withRoot = withoutScheme;
  const withoutQuerystring = eliminateAllAfterCharacter(withRoot, '?');
  const withoutHash = eliminateAllAfterCharacter(withoutQuerystring, '#');

  return withoutHash;
}

/**
 * Returns true if `candidate` is `root` itself or is inside `root`.
 * A plain `startsWith` check is not enough: `/home/u/Session-evil` starts with `/home/u/Session`.
 */
function isPathInside(candidate: string, root: string, isWindows: boolean) {
  const normalizedRoot = isWindows ? root.toLowerCase() : root;
  const withSeparator = normalizedRoot.endsWith(path.sep)
    ? normalizedRoot
    : `${normalizedRoot}${path.sep}`;
  const normalizedCandidate = isWindows ? candidate.toLowerCase() : candidate;

  return normalizedCandidate === normalizedRoot || normalizedCandidate.startsWith(withSeparator);
}

function createFileHandler({
  userDataPath,
  installPath,
  isWindows,
}: {
  isWindows: boolean;
  installPath: string;
  userDataPath: string;
}) {
  return (request: ProtocolRequest, callback: any) => {
    const targetPath = urlToPath(request.url, { isWindows });
    if (!targetPath) {
      console.log(`Warning: denying request to invalid file url '${request.url}'`);
      return callback();
    }

    // normalize() is primarily useful here for switching / to \ on windows
    const target = path.normalize(targetPath);
    // here we attempt to follow symlinks to the ultimate final path, reflective of what
    //   we do in main.js on userDataPath and installPath

    let realPath = target;
    try {
      realPath = fs.existsSync(target) ? fs.realpathSync(target) : target;
    } catch (e) {
      console.log(`Warning: denying request to unreadable path '${target}'`);
      return callback();
    }

    if (!path.isAbsolute(realPath)) {
      console.log(`Warning: denying request to non-absolute path '${realPath}'`);
      return callback();
    }

    if (!isPathInside(realPath, userDataPath, isWindows) && !isPathInside(realPath, installPath, isWindows)) {
      console.log(
        `Warning: denying request to path '${realPath}' (userDataPath: '${userDataPath}', installPath: '${installPath}')`
      );
      return callback();
    }

    return callback({
      path: realPath,
    });
  };
}

export function installFileHandler({
  protocol,
  userDataPath,
  installPath,
  isWindows,
}: {
  protocol: Protocol;
  userDataPath: string;
  installPath: string;
  isWindows: boolean;
}) {
  protocol.interceptFileProtocol(
    'file',
    createFileHandler({ userDataPath, installPath, isWindows })
  );
}

// Turn off browser URI scheme since we do all network requests via Node.js
function disabledHandler(_request: any, callback: any) {
  return callback();
}

export function installWebHandler({ protocol }: { protocol: Protocol }) {
  protocol.interceptFileProtocol('about', disabledHandler);
  protocol.interceptFileProtocol('content', disabledHandler);
  protocol.interceptFileProtocol('chrome', disabledHandler);
  protocol.interceptFileProtocol('cid', disabledHandler);
  protocol.interceptFileProtocol('data', disabledHandler);
  protocol.interceptFileProtocol('filesystem', disabledHandler);
  protocol.interceptFileProtocol('ftp', disabledHandler);
  protocol.interceptFileProtocol('gopher', disabledHandler);
  protocol.interceptFileProtocol('http', disabledHandler);
  protocol.interceptFileProtocol('https', disabledHandler);
  protocol.interceptFileProtocol('javascript', disabledHandler);
  protocol.interceptFileProtocol('mailto', disabledHandler);
  protocol.interceptFileProtocol('ws', disabledHandler);
  protocol.interceptFileProtocol('wss', disabledHandler);
}
