#!/usr/bin/env python3
"""
Dump every Flutter release as `version,Engine_commit,Snapshot_Hash` CSV rows.

The original version of this script hung because all of its network calls
(urlretrieve / requests.get) ran without a timeout, so one stalled connection
blocked the run forever. It also re-cloned the whole flutter/flutter repo and
re-downloaded every engine artifact on each run, and extracted the hash with
a character-by-character scan that takes minutes per binary.

This version:
  - resumes: rows already present in the output (or seed files) are reused,
    so a re-run only fetches what is missing
  - times out and retries every network call - no infinite blocking
  - resolves engine commits via raw.githubusercontent.com - no git clone
  - downloads one artifact per unique engine commit (versions share engines)
  - fetches in parallel and writes the CSV atomically at checkpoints

Row order matches the Flutter releases manifest (newest release first),
exactly like the original script's output.
"""

import argparse
import concurrent.futures
import json
import os
import re
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
import zipfile

import requests

sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/../reflutter")
from utils import elff as ELFF

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RELEASES_URL = (
    "https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json"
)
ENGINE_VERSION_URL = (
    "https://raw.githubusercontent.com/flutter/flutter/{revision}/bin/internal/engine.version"
)
SNAPSHOT_URL = (
    "https://storage.googleapis.com/flutter_infra_release/flutter/{engine}/android-arm64-release/linux-x64.zip"
)
CSV_HEADER = "version,Engine_commit,Snapshot_Hash"

# Shorebird engine artifacts live in a public GCS bucket that mirrors the
# vanilla flutter_infra_release layout; the bucket listing is the
# authoritative enumeration of available engine revisions (the fork's release
# tags lag the rolled engines).
SHOREBIRD = {
    "snapshot_url": (
        "https://storage.googleapis.com/download.shorebird.dev/flutter_infra_release/flutter/{engine}/android-arm64-release/linux-x64.zip"
    ),
    "out": os.path.join(os.path.dirname(SCRIPT_DIR), "enginehash_sb.csv"),
}

CONNECT_TIMEOUT = 15  # seconds to establish a connection before failing
READ_TIMEOUT = 180  # seconds without receiving data before failing
MAX_RETRIES = 4
CHECKPOINT_EVERY = 25  # engine artifacts resolved between CSV checkpoints

ENGINE_COMMIT_RE = re.compile(r"[0-9a-f]{40}")
SNAPSHOT_HASH_RE = re.compile(r"[a-f\d]{32}")


class NotFoundError(Exception):
    """The requested artifact does not exist (e.g. engines without arm64 builds)."""


def sleep_backoff(attempt):
    time.sleep(min(2**attempt, 30))


def fetch_text(url, session):
    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = session.get(url, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT))
            if response.status_code in (404, 410):
                raise NotFoundError(url)
            response.raise_for_status()
            return response.text
        except NotFoundError:
            raise
        except requests.RequestException as error:
            last_error = error
            if attempt < MAX_RETRIES:
                sleep_backoff(attempt)
    raise last_error


def download_file(url, dest_path, session):
    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with session.get(
                url, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT), stream=True
            ) as response:
                if response.status_code in (404, 410):
                    raise NotFoundError(url)
                response.raise_for_status()
                with open(dest_path, "wb") as out:
                    for chunk in response.iter_content(chunk_size=1 << 20):
                        out.write(chunk)
            return
        except NotFoundError:
            raise
        except requests.RequestException as error:
            last_error = error
            if attempt < MAX_RETRIES:
                sleep_backoff(attempt)
    raise last_error


def load_seed_rows(seed_paths):
    """Read previous outputs as version -> (engine_commit, snapshot_hash)."""
    rows = {}
    for path in seed_paths:
        if not os.path.isfile(path):
            continue
        with open(path, "r", errors="replace") as seed:
            for line in seed:
                parts = [part.strip() for part in line.strip().split(",")]
                if len(parts) != 3 or parts[0] == "version":
                    continue
                version, engine_commit, snapshot_hash = parts
                if ENGINE_COMMIT_RE.fullmatch(engine_commit) and SNAPSHOT_HASH_RE.fullmatch(
                    snapshot_hash
                ):
                    rows[version] = (engine_commit, snapshot_hash)
    return rows


def engine_commit_of(revision, session):
    """Framework revision -> engine commit recorded in bin/internal/engine.version."""
    try:
        return fetch_text(
            ENGINE_VERSION_URL.format(revision=revision), session
        ).strip()
    except NotFoundError:
        return ""


def snapshot_hash_of(engine_commit, session, url_template=None):
    """Download the engine's gen_snapshot artifact and extract its snapshot hash."""
    if url_template is None:
        url_template = SNAPSHOT_URL
    with tempfile.TemporaryDirectory(prefix="gen_enginehash-") as tmp_dir:
        zip_path = os.path.join(tmp_dir, "engine.zip")
        try:
            download_file(url_template.format(engine=engine_commit), zip_path, session)
        except NotFoundError:
            return None
        try:
            with zipfile.ZipFile(zip_path) as archive:
                member = next(
                    (name for name in archive.namelist() if name.endswith("gen_snapshot")),
                    None,
                )
                if member is None:
                    return None
                archive.extract(member, tmp_dir)
                return ELFF(os.path.join(tmp_dir, member)) or None
        except zipfile.BadZipFile:
            return None


def write_rows(out_path, releases, row_of_version):
    """Write the CSV in releases-manifest order, atomically (crash-safe resume)."""
    partial_path = out_path + ".part"
    written = 0
    with open(partial_path, "w") as out:
        out.write(CSV_HEADER + "\n")
        seen_versions = set()
        for release in releases:
            version = release["version"]
            if version in seen_versions:
                continue
            seen_versions.add(version)
            row = row_of_version.get(version)
            if row:
                out.write("{},{},{}\n".format(version, row[0], row[1]))
                written += 1
        # retain rows for versions outside the current manifest (e.g. a
        # --limit run) so partial runs never shrink the resume seed
        for version in sorted(row_of_version):
            if version not in seen_versions:
                row = row_of_version[version]
                out.write("{},{},{}\n".format(version, row[0], row[1]))
                written += 1
    os.replace(partial_path, out_path)
    return written


def shorebird_engine_revisions(session):
    """Engine revisions available in Shorebird's public artifact bucket.

    The bucket mirrors the vanilla flutter_infra_release layout; the release
    tags of the shorebirdtech/flutter fork lag the rolled engines, so the
    bucket listing itself is the authoritative enumeration.
    """
    revisions = []
    marker = ""
    while True:
        url = (
            "https://storage.googleapis.com/download.shorebird.dev"
            "?prefix=flutter_infra_release/flutter/&delimiter=/&max-keys=1000"
            + marker
        )
        root = ET.fromstring(session.get(url, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT)).text)
        for child in root.findall(".//{*}Prefix"):
            name = (child.text or "").strip().rstrip("/")
            rev = name.rsplit("/", 1)[-1]
            if ENGINE_COMMIT_RE.fullmatch(rev):
                revisions.append(rev)
        page = root.find("{*}NextMarker")
        if page is None:
            break
        marker = "&marker=" + page.text.strip()
    return sorted(set(revisions))


def main_shorebird(args):
    started = time.time()
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_maxsize=max(args.workers, 10))
    session.mount("https://", adapter)

    out_path = args.out if args.out != os.path.join(SCRIPT_DIR, "enginehash.tmp.csv") else SHOREBIRD["out"]
    revisions = shorebird_engine_revisions(session)
    if args.limit:
        revisions = revisions[: args.limit]
    print("[i] {} shorebird engine revisions in bucket".format(len(revisions)), flush=True)

    row_of_version = load_seed_rows([out_path])
    known_hashes = {snapshot_hash for _, snapshot_hash in row_of_version.values()}

    # rows are keyed sb-<rev> (the hash column is what lookups match on)
    engine_of_row = {row[0]: rev for rev, row in ((v[0], v) for v in row_of_version.values())}
    todo = [rev for rev in revisions if "sb-" + rev not in row_of_version]

    misses = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(snapshot_hash_of, rev, session, SHOREBIRD["snapshot_url"]): rev
            for rev in todo
        }
        for done, future in enumerate(concurrent.futures.as_completed(futures), 1):
            rev = futures[future]
            try:
                snapshot_hash = future.result()
            except requests.RequestException as error:
                snapshot_hash = None
                print("[!] download failed for engine {}: {}".format(rev, error), flush=True)
            if snapshot_hash and snapshot_hash not in known_hashes:
                known_hashes.add(snapshot_hash)
                row_of_version["sb-" + rev] = (rev, snapshot_hash)
            elif not snapshot_hash:
                misses.append(rev)
            print(
                "[fetch] {}/{} engine {}... -> {}".format(
                    done, len(todo), rev[:12], snapshot_hash
                ),
                flush=True,
            )

    partial_path = out_path + ".part"
    written = 0
    with open(partial_path, "w") as out:
        out.write(CSV_HEADER + "\n")
        for version in sorted(row_of_version, reverse=True):
            row = row_of_version[version]
            out.write("{},{},{}\n".format(version, row[0], row[1]))
            written += 1
    os.replace(partial_path, out_path)
    print(
        "[done] {} rows written to {} in {:.0f}s, {} unresolved".format(
            written, out_path, time.time() - started, len(misses)
        ),
        flush=True,
    )
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        default=os.path.join(SCRIPT_DIR, "enginehash.tmp.csv"),
        help="output CSV path (also used as a resume seed)",
    )
    parser.add_argument(
        "--seed",
        action="append",
        default=None,
        help="extra CSV to resume from (repeatable); defaults to --out and "
        "enginehash.tmp next to this script",
    )
    parser.add_argument("--workers", type=int, default=4, help="parallel downloads")
    parser.add_argument(
        "--limit", type=int, default=None, help="only process the N newest releases"
    )
    parser.add_argument(
        "--shorebird",
        action="store_true",
        help="collect Shorebird engine hashes from the shorebirdtech/flutter "
        "release tags and Shorebird's public artifact bucket "
        "(writes enginehash_sb.csv)",
    )
    args = parser.parse_args()

    if args.shorebird:
        return main_shorebird(args)

    started = time.time()
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_maxsize=max(args.workers, 10))
    session.mount("https://", adapter)

    releases = json.loads(fetch_text(RELEASES_URL, session))["releases"]
    if args.limit:
        releases = releases[: args.limit]

    seed_paths = list(args.seed or []) + [
        args.out,
        os.path.join(SCRIPT_DIR, "enginehash.tmp"),
    ]
    row_of_version = load_seed_rows(seed_paths)
    engine_snapshot = {
        engine_commit: snapshot_hash
        for engine_commit, snapshot_hash in row_of_version.values()
    }
    print(
        "[i] {} releases in manifest, {} rows resumed from seeds".format(
            len(releases), len(row_of_version)
        ),
        flush=True,
    )

    # Pass 1: framework revision -> engine commit for every release.
    revisions = sorted({release["hash"] for release in releases})
    engine_by_revision = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(engine_commit_of, revision, session): revision
            for revision in revisions
        }
        for done, future in enumerate(concurrent.futures.as_completed(futures), 1):
            revision = futures[future]
            try:
                engine_by_revision[revision] = future.result()
            except requests.RequestException as error:
                engine_by_revision[revision] = ""
                print("[!] engine.version failed for {}: {}".format(revision, error), flush=True)
            if done % 100 == 0 or done == len(futures):
                print("[engine] {}/{} revisions resolved".format(done, len(futures)), flush=True)

    # Pass 2: collect versions that still need a snapshot hash.
    pending_by_engine = {}
    seen_versions = set()
    for release in releases:
        version = release["version"]
        if version in row_of_version or version in seen_versions:
            continue
        seen_versions.add(version)
        engine_commit = engine_by_revision.get(release["hash"], "")
        if not engine_commit:
            print("[!] no engine commit for {} (skipped)".format(version), flush=True)
            continue
        pending_by_engine.setdefault(engine_commit, []).append(version)

    engines_to_fetch = [
        engine for engine in pending_by_engine if engine not in engine_snapshot
    ]
    print(
        "[i] {} versions to resolve, {} engine artifacts to download".format(
            len(sum(pending_by_engine.values(), [])), len(engines_to_fetch)
        ),
        flush=True,
    )

    # Pass 3: download each missing engine artifact once, extract its hash.
    misses = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(snapshot_hash_of, engine, session): engine
            for engine in engines_to_fetch
        }
        for done, future in enumerate(concurrent.futures.as_completed(futures), 1):
            engine = futures[future]
            try:
                snapshot_hash = future.result()
            except requests.RequestException as error:
                snapshot_hash = None
                print("[!] download failed for engine {}: {}".format(engine, error), flush=True)
            engine_snapshot[engine] = snapshot_hash
            if snapshot_hash:
                for version in pending_by_engine[engine]:
                    row_of_version[version] = (engine, snapshot_hash)
            else:
                misses.extend(pending_by_engine[engine])
            print(
                "[fetch] {}/{} engine {}... -> {}".format(
                    done, len(engines_to_fetch), engine[:12], snapshot_hash
                ),
                flush=True,
            )
            if done % CHECKPOINT_EVERY == 0:
                write_rows(args.out, releases, row_of_version)

    written = write_rows(args.out, releases, row_of_version)
    print(
        "[done] {} rows written to {} in {:.0f}s, {} unresolved: {}".format(
            written,
            args.out,
            time.time() - started,
            len(misses),
            ", ".join(misses[:20]) or "none",
        ),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
