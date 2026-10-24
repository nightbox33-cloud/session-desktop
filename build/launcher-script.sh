#!/usr/bin/env bash

# do not set -x here because it will fail on non-debian  based distrib
# set -e

# Some distributions have unprivileged_userns_clone disabled.
# If that's the case, and we run an AppImage (deb is not impacted by this),
# the Chromium sandbox cannot be used and the app won't start unless we start it with
# --no-sandbox.
# This bash script is the launcher script for AppImage only, and will at runtime check
# if we need to add the --no-sandbox before running the AppImage itself.
#
# NOTE: --no-sandbox is a security downgrade (it disables the OS-level sandbox of the
# renderer). It is only ever added as a last resort, when the kernel tells us that
# unprivileged user namespaces are not available.

UNPRIVILEGED_USERNS_ENABLED=$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

SANDBOX_ARGS=()
if [ "$UNPRIVILEGED_USERNS_ENABLED" = "0" ]; then
  SANDBOX_ARGS+=(--no-sandbox)
fi

# Note: the previous version of this script always passed one extra (possibly empty)
# argument to the binary. Using an array keeps the argv exactly as intended.
exec "$SCRIPT_DIR/session-desktop-bin" "${SANDBOX_ARGS[@]+"${SANDBOX_ARGS[@]}"}" "$@"
