#!/bin/sh
# nmaptui installer.
#
#   curl -fsSL https://raw.githubusercontent.com/profullstack/nmaptui/main/install.sh | sh
#
# Installs the published @profullstack/nmaptui package under ~/.local and puts
# `nmaptui` on ~/.local/bin. POSIX sh, never asks for root, safe to re-run:
# a second run upgrades in place, and `nmaptui update` runs the same steps.
#
# Environment:
#   NMAPTUI_PREFIX    install prefix (default ~/.local; the command lands in $PREFIX/bin)
#   NMAPTUI_VERSION   version or dist-tag to install (default latest)
#   NMAPTUI_SKIP_NMAP set to 1 to skip the nmap check

set -eu

PREFIX="${NMAPTUI_PREFIX:-$HOME/.local}"
VERSION="${NMAPTUI_VERSION:-latest}"
PKG="@profullstack/nmaptui@$VERSION"

say() { printf '%s\n' "$*"; }
die() { printf 'nmaptui: %s\n' "$*" >&2; exit 1; }

# Node 22.6 is the floor: the package ships plain ES modules and the bin runs
# under `node`. Bun works too, so a box with only bun is not turned away.
runtime=""
if command -v node >/dev/null 2>&1; then
	# `node -p` colourises its output on a TTY, so read `node -v` instead.
	nodev="$(node -v 2>/dev/null | sed 's/^v//')"
	major="${nodev%%.*}"; rest="${nodev#*.}"; minor="${rest%%.*}"
	case "$major$minor" in *[!0-9]*|"") major=0; minor=0 ;; esac
	if [ "$major" -gt 22 ] || { [ "$major" -eq 22 ] && [ "$minor" -ge 6 ]; }; then
		runtime="node"
	else
		say "node $(node -v) is too old for nmaptui (needs 22.6 or newer)."
	fi
fi
if [ -z "$runtime" ] && command -v bun >/dev/null 2>&1; then
	runtime="bun"
fi
[ -n "$runtime" ] || die "Node 22.6+ or Bun is required. Install one (https://nodejs.org, https://bun.sh, or \`mise use -g node@lts\`) and re-run this installer."

if [ "$runtime" = "node" ]; then
	command -v npm >/dev/null 2>&1 || die "npm is required alongside node."
	say "Installing $PKG into $PREFIX with npm"
	mkdir -p "$PREFIX"
	npm install -g --prefix "$PREFIX" --no-audit --no-fund --silent "$PKG" \
		|| die "npm install failed. If this is a brand-new release, the registry can take a few minutes to serve it; try again shortly."
	BIN="$PREFIX/bin/nmaptui"
else
	say "Installing $PKG with bun"
	bun add -g "$PKG" >/dev/null || die "bun add -g failed."
	BIN="$(command -v nmaptui 2>/dev/null || printf '%s/.bun/bin/nmaptui' "$HOME")"
fi

[ -x "$BIN" ] || die "installed, but $BIN is not executable. Check the install output above."
say "Installed $("$BIN" --version)"

# nmap itself is a system package, and this script never uses sudo, so the
# most it does is name the command. nmaptui still opens and diffs XML files
# without it.
if [ "${NMAPTUI_SKIP_NMAP:-0}" != "1" ] && ! command -v nmap >/dev/null 2>&1; then
	say ""
	say "nmap is not installed. Scans need it; opening and diffing saved XML does not."
	if command -v apt-get >/dev/null 2>&1; then say "  sudo apt-get install -y nmap";
	elif command -v dnf >/dev/null 2>&1; then say "  sudo dnf install -y nmap";
	elif command -v pacman >/dev/null 2>&1; then say "  sudo pacman -S nmap";
	elif command -v brew >/dev/null 2>&1; then say "  brew install nmap";
	elif command -v zypper >/dev/null 2>&1; then say "  sudo zypper install nmap";
	else say "  see https://nmap.org/download"; fi
fi

BIN_DIR="$(dirname "$BIN")"
case ":$PATH:" in
	*":$BIN_DIR:"*) ;;
	*)
		say ""
		say "$BIN_DIR is not on your PATH. Add this to your shell profile:"
		say "  export PATH=\"$BIN_DIR:\$PATH\""
		;;
esac

say ""
say "Run: nmaptui                      open the console"
say "     nmaptui 10.0.0.0/24 --start  scan a network right away"
say "     nmaptui --help               everything else"
