"""Fetch every artifact a release run built, BY NAME, from the package index.

Not through a resolver. `pip download` takes the wheel and leaves the sdist —
correct pip behaviour, and no proof at all about the sdist's bytes. That gap is
exactly what made `0.1.0a3` unprovable: the sdist sat on the index the whole
time and nothing had ever compared it.

So the enumeration comes from the RELEASE RUN's own hash manifest, and each
filename in it is requested individually. A file the run built and the index
will not serve is reported and left absent, so the verdict function sees a
missing artifact rather than a quietly shorter list.

Reads its credential from the environment. Nothing here builds a URL containing
one — the token goes in the `Authorization`/basic-auth header, because a URL
carrying `user:token@host` leaks the moment anything echoes it.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def parse_manifest(text: str) -> list[str]:
    """`sha256sum` output -> the filenames, in order."""
    names: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        _, _, name = line.partition(" ")
        names.append(name.strip().lstrip("*"))
    return names


def find_href(html: str, filename: str) -> str | None:
    """The index page's link for exactly this filename."""
    for href in re.findall(r'href="([^"]+)"', html):
        path = urllib.parse.urlparse(href).path
        if path.rsplit("/", 1)[-1].split("#")[0] == filename:
            return href
    return None


def _open(url: str, user: str, token: str) -> bytes:
    request = urllib.request.Request(url)  # noqa: S310 - https, built from config
    credential = base64.b64encode(f"{user}:{token}".encode()).decode()
    request.add_header("Authorization", f"Basic {credential}")
    with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310
        return response.read()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", required=True)
    parser.add_argument("--distribution", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--dest", required=True)
    parser.add_argument("--user", default="ci-reader")
    args = parser.parse_args(argv)

    token = os.environ.get("INDEX_TOKEN", "")
    if not token:
        print("::error::INDEX_TOKEN is empty; cannot fetch artifacts", file=sys.stderr)
        return 1

    manifest = Path(args.manifest)
    if not manifest.is_file():
        print(f"::warning::{manifest} is absent; nothing to enumerate")
        return 0

    listing = f"{args.index.rstrip('/')}/{args.distribution}/"
    html = _open(listing, args.user, token).decode("utf-8", "replace")

    dest = Path(args.dest)
    dest.mkdir(parents=True, exist_ok=True)

    failures = 0
    for name in parse_manifest(manifest.read_text(encoding="utf-8")):
        href = find_href(html, name)
        if href is None:
            print(f"::warning::{name} is not linked on the index")
            failures += 1
            continue
        url = urllib.parse.urljoin(listing, href)
        try:
            body = _open(url, args.user, token)
        except urllib.error.HTTPError as exc:
            print(f"::warning::{name} -> HTTP {exc.code}")
            failures += 1
            continue
        (dest / name).write_bytes(body)
        digest = hashlib.sha256(body).hexdigest()
        print(f"  fetched {name} ({len(body)} bytes) sha256 {digest}")

    # Deliberately 0 even with failures: an artifact the index will not serve is
    # an OBSERVATION for the verdict function, which reports it as unproven.
    # Failing here would turn a finding into a step error and lose the report.
    if failures:
        print(f"::warning::{failures} artifact(s) could not be fetched")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
