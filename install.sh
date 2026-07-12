#!/bin/sh
# reaper installer (macOS + Linux) — latest GitHub release, on your PATH.
#   curl -fsSL https://raw.githubusercontent.com/benelser/reaper/main/install.sh | sh
#
# Env overrides: REAPER_INSTALL_DIR (default ~/.local/bin),
#                REAPER_ARTIFACT (local .tar.gz — used by CI to validate
#                this script without a network release).
set -eu

REPO="benelser/reaper"
INSTALL_DIR="${REAPER_INSTALL_DIR:-$HOME/.local/bin}"

case "$(uname -s)" in
  Darwin) os="apple-darwin" ;;
  Linux)  os="unknown-linux-musl" ;;
  *) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  arm64|aarch64) arch="aarch64" ;;
  x86_64|amd64)  arch="x86_64" ;;
  *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;;
esac
if [ "$os" = "unknown-linux-musl" ] && [ "$arch" = "aarch64" ]; then
  echo "no prebuilt aarch64-linux binary yet — build from source:" >&2
  echo "  cargo install --git https://github.com/$REPO reaper" >&2
  exit 1
fi

target="$arch-$os"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

if [ -n "${REAPER_ARTIFACT:-}" ]; then
  cp "$REAPER_ARTIFACT" "$tmp/reaper.tar.gz"
else
  url="https://github.com/$REPO/releases/latest/download/reaper-$target.tar.gz"
  echo "downloading reaper ($target)…"
  curl -fsSL "$url" -o "$tmp/reaper.tar.gz"
fi

tar xzf "$tmp/reaper.tar.gz" -C "$tmp"
mkdir -p "$INSTALL_DIR"
install -m 755 "$tmp/reaper" "$INSTALL_DIR/reaper"
echo "installed: $("$INSTALL_DIR/reaper" --version) → $INSTALL_DIR/reaper"

# Put it on the PATH — persistently, in the right rc for the user's shell.
on_path() { case ":$PATH:" in *":$INSTALL_DIR:"*) true ;; *) false ;; esac; }
if on_path; then
  :
else
  line="export PATH=\"$INSTALL_DIR:\$PATH\"  # added by reaper installer"
  shell_name="$(basename "${SHELL:-sh}")"
  case "$shell_name" in
    zsh)  rc="$HOME/.zshrc" ;;
    bash) rc="$HOME/.bashrc" ;;
    fish) rc="" ;;
    *)    rc="$HOME/.profile" ;;
  esac
  if [ "$shell_name" = "fish" ]; then
    mkdir -p "$HOME/.config/fish/conf.d"
    echo "fish_add_path $INSTALL_DIR  # added by reaper installer" \
      > "$HOME/.config/fish/conf.d/reaper.fish"
    echo "PATH: added via ~/.config/fish/conf.d/reaper.fish"
  else
    if ! grep -qs "added by reaper installer" "$rc" 2>/dev/null; then
      printf '\n%s\n' "$line" >> "$rc"
    fi
    echo "PATH: added $INSTALL_DIR via $rc (open a new terminal, or: source $rc)"
  fi
fi

echo
echo "  reaper              # TUI on the current directory — nothing is deleted until you confirm"
echo "  reaper scan ~       # classify your home dir, zero mutation"
echo "  reaper update       # stay current — updates itself in place"
