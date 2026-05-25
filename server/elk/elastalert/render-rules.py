#!/usr/bin/env python3
"""
ElastAlert rule renderer.

ElastAlert 2 doesn't natively expand ${ENV_VAR} placeholders inside rule
files, but rules need to embed the server's API_KEY in webhook headers.
This script runs at container startup, copies every rule file in
/opt/elastalert/rules into /opt/elastalert/rules-rendered with all
${VAR} placeholders substituted from the container's environment.

Placeholders that reference undefined variables are left untouched (so
operators get a loud failure rather than silent posts with empty keys).
"""
from __future__ import annotations

import glob
import os
import re
import sys

SRC = "/opt/elastalert/rules"
# Render into /tmp so we don't need to mount a writeable volume — the
# rendered files are regenerated on every container start anyway.
DST = "/tmp/rules-rendered"

PLACEHOLDER_RE = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)\}")


def render(content: str) -> tuple[str, list[str]]:
    """Substitute ${VAR} placeholders; return (rendered, missing_vars)."""
    missing: list[str] = []

    def repl(match: re.Match) -> str:
        name = match.group(1)
        value = os.environ.get(name)
        if value is None:
            missing.append(name)
            return match.group(0)
        return value

    return PLACEHOLDER_RE.sub(repl, content), missing


def main() -> int:
    os.makedirs(DST, exist_ok=True)

    # Clear stale rendered files first so deletions in the source dir
    # actually propagate.
    for stale in glob.glob(os.path.join(DST, "*")):
        try:
            os.remove(stale)
        except OSError:
            pass

    sources = sorted(
        glob.glob(os.path.join(SRC, "*.yaml"))
        + glob.glob(os.path.join(SRC, "*.yml"))
    )

    if not sources:
        print(f"[render-rules] No rule files in {SRC}", file=sys.stderr)
        return 0

    total_missing: set[str] = set()
    for src_path in sources:
        with open(src_path, "r", encoding="utf-8") as fh:
            content = fh.read()
        rendered, missing = render(content)
        total_missing.update(missing)
        dst_path = os.path.join(DST, os.path.basename(src_path))
        with open(dst_path, "w", encoding="utf-8") as fh:
            fh.write(rendered)
        print(f"[render-rules] {os.path.basename(src_path)} -> {dst_path}")

    if total_missing:
        print(
            f"[render-rules] WARNING: undefined env vars in rules: "
            f"{', '.join(sorted(total_missing))}",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
