#!/usr/bin/env sh
# dsh-rea-toolkit bootstrap entry (Linux / macOS).
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"

if command -v node >/dev/null 2>&1; then
  exec node "$DIR/install-tools.mjs" "$@"
fi

for candidate in "$HOME/.dsh/dsh-runtimes/dsh-primary-runtime/dependencies/node/bin/node" /usr/local/bin/node; do
  if [ -x "$candidate" ]; then exec "$candidate" "$DIR/install-tools.mjs" "$@"; fi
done

echo "Node.js 22.19+/24.11+/26+ is required but was not found." >&2
echo "Install Node.js (https://nodejs.org), then re-run this script." >&2
exit 1
