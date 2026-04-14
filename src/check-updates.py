#!/usr/bin/env python3
#
# Checks whether any assets on SC4E and/or STEX are newer than stated in our yaml files.
#
# Usage: check-updates.py --api [sc4e|stex] [--mode id|updated] <yaml files or directories>
#
# The STEX_API_KEY environment variable must be set for STEX queries. (API key is issued by ST admins)

import yaml
import sys
import os
import re
import argparse
from dateutil.parser import isoparse
from datetime import timezone, timedelta, datetime
import urllib.request
import json
from dataclasses import dataclass
import copy
from collections import defaultdict
import tempfile
import subprocess
import hashlib
import shutil


def nonempty_docs(dirs_or_files):
    # Generate all the paths with non-empty documents contained in the yaml files.
    # Yield (path, None) in case of parse error.
    for d in dirs_or_files:
        paths = [d] if not os.path.isdir(d) else \
            (os.path.join(root, fname) for (root, dirs, files) in os.walk(d) for fname in files)
        for path in paths:
            if not path.endswith(".yaml"):
                continue
            with open(path, encoding='utf-8') as f:
                text = f.read()
                try:
                    yield path, [doc for doc in yaml.safe_load_all(text) if doc is not None]  # ignore empty documents
                except yaml.parser.ParserError:
                    yield path, None


class ExchangeApi:
    def fetch_upstream_state(self, file_ids=None, load_reports_dir=None, save_reports_dir=None):
        raise NotImplementedError

    def extract_id(self, url):
        raise NotImplementedError

    def upstream_last_modified(self, upstream_entry):
        raise NotImplementedError

    def upstream_version(self, upstream_entry):
        raise NotImplementedError

    def upstream_website_link(self, upstream_entry):
        raise NotImplementedError

    def get_subfile_candidates(self, upstream_entry, subfile_id):
        # For APIs that support subfiles (STEX), override this.
        return {}

    def update_subfile_in_url(self, url, old_subfile_id, new_subfile_id):
        # Default: no-op
        return url


def _fetch_with_retry(req):
    import time
    from urllib.error import HTTPError
    retried = False
    while True:
        try:
            with urllib.request.urlopen(req) as data:
                report = json.load(data)
                return report
        except HTTPError as e:
            if e.code == 403 and not retried:
                print("Received 403 Forbidden, retrying after 5 seconds...")
                retried = True
                time.sleep(5)
                continue
            else:
                print(f"::error file=check-updates.py,line={e.__traceback__.tb_lineno}::HTTP error {e.code} for URL {req.full_url.split('?', 1)[0]}")
                raise


def _fetch_with_cache(req, load_reports_file=None, save_reports_file=None):
    report = None
    if load_reports_file:
        try:
            with open(load_reports_file, "r", encoding="utf-8") as f:
                report = json.load(f)
                print(f"Loaded report from {load_reports_file}")
        except IOError:
            pass  # file does not exist
    if report is None:
        report = _fetch_with_retry(req)
    if save_reports_file:
        os.makedirs(os.path.dirname(save_reports_file), exist_ok=True)
        with open(save_reports_file, "w", encoding="utf-8") as f:
            json.dump(report, f)
            print(f"Saved report to {save_reports_file}")
    return report


class Sc4eApi(ExchangeApi):
    url_id_pattern = re.compile(r".*sc4evermore.com/.*[?&]id=(\d+).*")
    report_file = "sc4e-report.json"

    def fetch_upstream_state(self, file_ids=None, load_reports_dir=None, save_reports_dir=None):
        req = urllib.request.Request(
            "https://www.sc4evermore.com/latest-modified-downloads.php",
            headers={'User-Agent': 'Mozilla/5.0'})
        report = _fetch_with_cache(
                req,
                save_reports_file=os.path.join(save_reports_dir, self.report_file) if save_reports_dir else None,
                load_reports_file=os.path.join(load_reports_dir, self.report_file) if load_reports_dir else None)
        return {str(item['id']): item for item in report['files']}

    def extract_id(self, url):
        m = self.url_id_pattern.fullmatch(url)
        return (m.group(1), None) if m else (None, None)

    def upstream_last_modified(self, upstream_entry):
        dt = isoparse(upstream_entry['modified'])
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    def upstream_version(self, upstream_entry):
        return upstream_entry.get('release')

    def upstream_website_link(self, upstream_entry):
        file_id = upstream_entry['id']
        return f"https://www.sc4evermore.com/index.php/downloads/download/{file_id}"


class StexApi(ExchangeApi):
    url_id_pattern = re.compile(r".*simtropolis.com/files/file/(\d+)-.*?(?:$|[?&]r=(\d+).*$)")  # matches ID and optional subfile ID
    since_days = 180  # to keep the request small
    id_limit = 250  # to keep the request small
    report_file = "stex-report.json"

    def __init__(self, api_key, mode="updated"):
        self.api_key = api_key
        self.mode = mode

    def fetch_upstream_state(self, file_ids=None, load_reports_dir=None, save_reports_dir=None):
        if self.mode == "id":
            if not file_ids:
                return {}
            req_url = f"https://community.simtropolis.com/stex/files-api.php?key={self.api_key}&sort=desc&id=" + ",".join(file_ids[:self.id_limit])
        else:
            req_url = f"https://community.simtropolis.com/stex/files-api.php?key={self.api_key}&days={self.since_days}&mode=updated&sc4only=true&sort=desc"
        req = urllib.request.Request(req_url, headers={'User-Agent': 'Mozilla/5.0 Firefox/130.0'})
        report = _fetch_with_cache(
                req,
                save_reports_file=os.path.join(save_reports_dir, self.report_file) if save_reports_dir else None,
                load_reports_file=os.path.join(load_reports_dir, self.report_file) if load_reports_dir else None)
        return {str(item['id']): item for item in report}

    def extract_id(self, url):
        m = self.url_id_pattern.fullmatch(url)
        return (m.group(1), m.group(2)) if m else (None, None)

    def upstream_last_modified(self, upstream_entry):
        dt = isoparse(upstream_entry['updated'])
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    def upstream_version(self, upstream_entry):
        return upstream_entry.get('release')

    def upstream_website_link(self, upstream_entry):
        return upstream_entry.get('fileURL')

    def get_subfile_candidates(self, upstream_entry, subfile_id):
        subfiles = upstream_entry.get('files', [])
        name = next((r.get('name') for r in subfiles if str(r.get('id')) == subfile_id), None)
        if subfile_id is not None and name is not None:
            return {subfile_id: name}
        else:
            if len(subfiles) != 1:
                return {r.get('id'): r.get('name') for r in subfiles}
            else:
                return {}

    def update_subfile_in_url(self, url, old_subfile_id, new_subfile_id):
        # Replace or add/remove r=subfile_id in the url
        m = self.url_id_pattern.fullmatch(url)
        if not m:
            return url
        old_r = m.group(2)
        if new_subfile_id is None:
            # Remove r=... if present
            if "?r=" in url:
                return re.sub(r'[?]r=\d+&?', '?', url)
            else:
                return re.sub(r'[&]r=\d+', '', url)
        if old_r is None:
            # Add r=new_subfile_id
            sep = '&' if '?' in url else '?'
            return f"{url}{sep}r={new_subfile_id}"
        # Replace old r=... with new one
        return re.sub(r'\b(r=)\d+', f"r={new_subfile_id}", url)


@dataclass
class AssetUpdateInfo:
    asset_id: str
    version: str
    version_upstream: str
    last_modified: datetime
    last_modified_upstream: datetime
    file_id: str
    subfile_id: str | None
    subfile_candidates: dict[str, str]  # subfile_id -> subfile_name
    website_link: str
    yaml_path: str
    url: str
    new_url: str

    def __str__(self):
        s = (f"{self.asset_id}:"
             f"\n  version: {self.version} -> {self.version_upstream}"
             f"\n  lastModified: {self.last_modified.isoformat().replace('+00:00', 'Z')} -> {self.last_modified_upstream.isoformat().replace('+00:00', 'Z')}"
             f"\n  Website: {self.website_link}"
             f"\n  YAML: {self.yaml_path}")
        if len(self.subfile_candidates) > 1:
            s += "\n  Subfiles:"
            for sub_id, sub_name in self.subfile_candidates.items():
                s += f"\n    {sub_id}: {sub_name}"
        if self.subfile_id is not None and self.subfile_id not in self.subfile_candidates:
            s += f"\n  Note: subfile ID {self.subfile_id} not found among subfiles, so URL must be updated"
        return s


def check_updates(api, docs, upstream_state, file_to_updates=None, update_mode=False):
    errors = 0
    out_of_date = 0
    up_to_date = 0
    skipped = 0
    for p, doc_list in docs:
        asset_updates = []
        if doc_list is None:
            errors += 1
            continue
        for doc in doc_list:
            url = doc.get('nonPersistentUrl') or doc.get('url')
            if url is None:
                continue
            file_id, subfile_id = api.extract_id(url)
            if file_id is None or file_id not in upstream_state:
                skipped += 1
                continue
            upstream_entry = upstream_state[file_id]
            subfile_candidates = api.get_subfile_candidates(upstream_entry, subfile_id)
            if subfile_id is not None and subfile_id not in subfile_candidates or subfile_id is None and len(subfile_candidates) > 1:
                if not update_mode:
                    errors += 1
                    print(f"{doc.get('assetId')}:")
                    print(f"  url subfile ID {subfile_id} is not valid:" if subfile_id else f"file ID {file_id} has multiple subfiles, but no subfile ID specified in url:")
                    print(f"    subfiles: {subfile_candidates}")
                    print(f"  {api.upstream_website_link(upstream_entry)}")
            last_modified_upstream = api.upstream_last_modified(upstream_entry)
            if 'lastModified' not in doc:
                errors += 1  # TODO
                continue
            last_modified = isoparse(doc.get('lastModified'))
            # we ignore small timestamp differences
            if abs(last_modified_upstream - last_modified) <= timedelta(minutes=10):
                up_to_date += 1
            else:
                old_version = doc.get('version')
                version_upstream = api.upstream_version(upstream_entry)
                new_url = doc.get('url')
                if new_url and "github.com" in new_url:
                    new_url = update_version_in_url(new_url, old_version, version_upstream)
                update_info = AssetUpdateInfo(
                    asset_id=doc.get('assetId'),
                    version=old_version,
                    version_upstream=version_upstream,
                    last_modified=last_modified,
                    last_modified_upstream=last_modified_upstream,
                    file_id=file_id,
                    subfile_id=subfile_id,
                    subfile_candidates=subfile_candidates,
                    website_link=api.upstream_website_link(upstream_entry),
                    yaml_path=p,
                    url=doc.get('url'),
                    new_url=new_url,
                )
                if last_modified < last_modified_upstream:
                    out_of_date += 1
                    asset_updates.append(update_info)
                else:
                    errors += 1  # our assets should not be newer than upstream's assets TODO
                    print("error: ", end='')
                print(update_info)
        if asset_updates and file_to_updates is not None:
            if update_mode:
                # Compute new url with updated subfile_id if needed
                make_subfile_candidates_unique(asset_updates)  # for current yaml path
                for update_info in asset_updates:
                    new_subfile_id = next(iter(update_info.subfile_candidates), None)
                    if update_info.new_url:
                        update_info.new_url = api.update_subfile_in_url(update_info.new_url, update_info.subfile_id, new_subfile_id)
            if p in file_to_updates:
                file_to_updates[p].extend(asset_updates)
            else:
                file_to_updates[p] = asset_updates
    return out_of_date, up_to_date, skipped, errors


def sanitize_version(version):
    if not version:
        return version
    v = version.strip()
    v = re.sub(r'^(v|version)\s*', '', v, flags=re.IGNORECASE)
    v = v.replace(' ', '')
    v = re.sub(r'(\.0)+$', '', v)  # Remove trailing .0 groups (e.g. 1.0.0 -> 1, 1.2.0 -> 1.2)
    return v


def versions_equal(v1, v2):
    """Compare version strings, ignoring optional -release suffixes."""
    def base(v):
        v = re.sub(r'-\d+$', '', v or '')
        v = re.sub(r'(\.0)+$', '', v)  # Remove trailing .0 groups (e.g. 1.0.0 -> 1, 1.2.0 -> 1.2)
        return v
    return base(v1) == base(v2)


def update_version_in_url(url, old_version, new_version):
    """Replace old version with new version in URLs (e.g. for github URLs)."""
    # Find all version-like substrings in the URL
    # Accept 1.2.3, 1.2, 1, etc.
    pattern = re.compile(r'\d+(?:\.\d+){0,2}', re.IGNORECASE)
    def repl(m):
        s = m.group(0)
        # Compare sanitized version
        if sanitize_version(s) == sanitize_version(old_version):
            return new_version
        return s
    return pattern.sub(repl, url)


def compute_new_version(current_version, upstream_version):
    """Combine current and upstream version, incrementing release suffix if equal."""
    if not current_version:
        return sanitize_version(upstream_version)
    if versions_equal(current_version, sanitize_version(upstream_version)):
        m = re.match(r'^(.*?)-(\d+)$', current_version)
        if m:
            base, rel = m.group(1), m.group(2)
            return f"{base}-{int(rel)+1}"
        else:
            return f"{current_version}-1"
    else:
        return sanitize_version(upstream_version)


def drop_common_affixes(strings):
    """Drop common prefix and suffix from a list of strings."""
    if not strings:
        return strings, '', ''
    # Find common prefix
    prefix = os.path.commonprefix(strings)
    # Find common suffix
    rev = [s[::-1] for s in strings]
    suffix = os.path.commonprefix(rev)[::-1]
    # Strip prefix and suffix
    stripped = [s[len(prefix):len(s)-len(suffix) if len(suffix) > 0 else None] for s in strings]
    return stripped, prefix, suffix


def map_asset_ids_to_subfile_ids(asset_ids, subfile_candidates):
    """
    Map asset_ids to subfile_ids heuristically.
    asset_ids: list of assetId strings
    subfile_candidates: dict of subfile_id -> subfile_name
    Returns: dict of asset_id -> subfile_id
    """
    if not asset_ids or not subfile_candidates:
        return {}
    # Lowercase subfile names
    subfile_names = {k: v.lower() for k, v in subfile_candidates.items()}
    # Drop common prefix/suffix
    subfiles_stripped, subfile_prefix, subfile_suffix = drop_common_affixes(list(subfile_names.values()))
    assets_stripped, asset_prefix, asset_suffix = drop_common_affixes(asset_ids)
    # Build mapping of original asset_id to stripped
    asset_stripped_map = dict(zip(asset_ids, assets_stripped))
    subfile_stripped_map = dict(zip(subfile_candidates.keys(), subfiles_stripped))
    # Heuristic: unique first letter
    result = {}
    remaining_assets = set(asset_ids)
    remaining_subfiles = set(subfile_candidates.keys())
    letter_re = re.compile(r'[a-z]', re.IGNORECASE)
    while remaining_assets and remaining_subfiles:
        # Find unique first letters
        asset_letter1st = defaultdict(list)
        for a, s in asset_stripped_map.items():
            m = letter_re.search(s)
            if m:
                asset_letter1st[m.group(0)].append(a)
        subfile_letter1st = defaultdict(list)
        for sid, s in subfile_stripped_map.items():
            m = letter_re.search(s)
            if m:
                subfile_letter1st[m.group(0)].append(sid)
        matched = False
        for letter in set(asset_letter1st) & set(subfile_letter1st):
            if len(asset_letter1st[letter]) == 1 and len(subfile_letter1st[letter]) == 1:
                a = asset_letter1st[letter][0]
                sid = subfile_letter1st[letter][0]
                result[a] = sid
                remaining_assets.remove(a)
                remaining_subfiles.remove(sid)
                del asset_stripped_map[a]
                del subfile_stripped_map[sid]
                matched = True
        if not matched:
            break
    # If only one asset and one subfile remain, map them
    if len(remaining_assets) == 1 and len(remaining_subfiles) == 1:
        a = next(iter(remaining_assets))
        sid = next(iter(remaining_subfiles))
        result[a] = sid
        remaining_assets.remove(a)
        remaining_subfiles.remove(sid)
    if remaining_assets or remaining_subfiles:
        remaining_candidates = {sid: subfile_candidates[sid] for sid in remaining_subfiles}
        raise ValueError(f"Could not uniquely map asset IDs {remaining_assets} to subfile IDs {remaining_candidates}")
    return result


def make_subfile_candidates_unique(asset_updates):
    """
    For each file_id with non-unique subfile_candidates, map asset_ids to subfile_ids and update candidates.
    Modifies asset_updates in place.
    """
    # Group by file_id
    by_file = defaultdict(list)
    for a in asset_updates:
        by_file[a.file_id].append(a)
    for file_id, info_items in by_file.items():
        # Merge all candidates
        candidates = {}
        for a in info_items:
            candidates.update(a.subfile_candidates)
        if len(candidates) > 1:
            asset_ids = [a.asset_id for a in info_items]
            try:
                mapping = map_asset_ids_to_subfile_ids(asset_ids, candidates)
            except Exception as e:
                raise RuntimeError(f"Failed to map asset_ids to subfile_ids for file_id {file_id}: {e}")
            # Update each AssetUpdateInfo's subfile_candidates to only the mapped one
            for a in info_items:
                sid = mapping[a.asset_id]
                a.subfile_candidates = {sid: candidates[sid]}
                a.subfile_id = sid


class Downloader:
    def __init__(self, tmpdir, yes=False):
        self.tmpdir = tmpdir
        self.yes = yes
        self.cache = {}  # url to path
        self._denied = set()

    def _should_skip_download(self, url):
        # Only allow downloads from github.com for now
        return not (url and "github.com" in url)

    def download(self, url):
        if self._should_skip_download(url):
            raise ValueError(f"URL {url} is not allowed to be downloaded")
        if url in self.cache:
            return self.cache[url]
        fname = os.path.join(self.tmpdir, os.path.basename(url.split("?")[0]))  # TODO this does not work for non-github URLs
        # Use curl to download, fail if not 200
        try:
            print(f"Downloading {url} ...")
            subprocess.run(
                ["curl", "-L", "--fail", "--silent", "--show-error", "--output", fname, url],
                check=True,
                capture_output=True,
            )
            print("Download finished.")
            self.cache[url] = fname
            return fname
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to download {url}: {e.stderr.decode()}") from e

    def can_download(self, url):
        if self._should_skip_download(url):
            return False
        if url in self.cache:
            return True
        if url in self._denied:
            return False
        if not self.yes:
            resp = input(f"Download {url}? [y/N] ")
            if resp.strip().lower() not in ("y", "yes"):
                print("Skipped.")
                self._denied.add(url)
                return False
        return True


def sha256sum(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_file_from_archive(asset_path, tmpdir, asset_id, incl):
    outdir = os.path.join(tmpdir, "extract-" + asset_id + "-" + incl.replace("/", "_"))  # TODO this could fail for some incl
    os.makedirs(outdir, exist_ok=True)
    try:
        # Extract file
        subprocess.run(
            ["sc4pac", "extract", "--output", outdir, "--include", incl, "--exclude", "$__nothing__", asset_path],
            check=True,
            capture_output=True,
        )
        # Find the extracted file
        files = []
        for root, dirs, fnames in os.walk(outdir):
            for fname in fnames:
                files.append(os.path.join(root, fname))
    except Exception as e:
        raise RuntimeError(f"Failed to extract {asset_id!r} include {incl!r}: {e}")
    if len(files) == 1:
        return files[0]
    else:
        raise RuntimeError(f"Warning: expected one file matching include {incl!r}, found {len(files)}")


def update_yaml_file_in_place(yaml_path, asset_updates, downloader):
    """Update the yaml file in place using ruamel.yaml, preserving formatting."""
    from ruamel.yaml import YAML
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.width = 4096
    with open(yaml_path, encoding='utf-8') as f:
        text = f.read()
    docs = list(yaml.load_all(text))
    orig_docs = copy.deepcopy(docs)

    # Map assetId to AssetUpdateInfo
    update_map = {a.asset_id: a for a in asset_updates}

    def update_checksum(checksum, sha256):
        if checksum['sha256'].lower() != sha256.lower():
            checksum['sha256'] = sha256

    def update_asset(asset, info: AssetUpdateInfo):
        old_version = asset.get('version')
        new_version = compute_new_version(old_version, info.version_upstream)
        asset['version'] = new_version
        asset['lastModified'] = info.last_modified_upstream.isoformat().replace('+00:00', 'Z')
        if info.new_url != info.url:
            asset['url'] = info.new_url  # includes new subfile_id if necessary and updated github version
        url = asset.get('url')
        if 'checksum' in asset and downloader.can_download(url):
            update_checksum(asset['checksum'], sha256sum(downloader.download(url)))

    def update_package(package, update_map: dict[str, AssetUpdateInfo]):
        all_assets = package.get('assets', []) + [asset for variant in package.get('variants', []) for asset in variant.get('assets', [])]
        all_asset_ids = {asset.get('assetId') for asset in all_assets if 'assetId' in asset}
        updated_ids = all_asset_ids.intersection(update_map)
        for asset_id in updated_ids:
            info = update_map[asset_id]
            if versions_equal(package.get('version'), info.version):
                # If package version is the same as original asset version, we can update it to upstream version too
                package['version'] = compute_new_version(package.get('version'), info.version_upstream)
                break
        for asset in all_assets:
            # Update withChecksum sha256 if present
            asset_id = asset.get('assetId')
            if asset_id not in updated_ids:
                continue
            info = update_map[asset_id]
            url = info.new_url
            if not downloader.can_download(url):
                continue
            asset_path = downloader.download(url)
            for wc in asset.get('withChecksum', []):
                incl = wc.get('include')
                if not incl:
                    continue
                path = extract_file_from_archive(asset_path=asset_path, tmpdir=downloader.tmpdir, asset_id=asset_id, incl=incl)
                update_checksum(wc, sha256sum(path))

    # Update all docs
    for doc in docs:
        # Asset document
        if isinstance(doc, dict) and doc.get('assetId') in update_map:
            info = update_map[doc['assetId']]
            update_asset(doc, info)
        # Package document
        if isinstance(doc, dict) and doc.get('group') and doc.get('name'):
            update_package(doc, update_map)
        # Array document
        if isinstance(doc, dict) and 'packages' in doc:
            for pkg in doc['packages']:
                update_package(pkg, update_map)
            for asset in doc.get('assets', []):
                if asset.get('assetId') in update_map:
                    info = update_map[asset['assetId']]
                    update_asset(asset, info)

    # Only write if changed
    if docs != orig_docs:
        with open(yaml_path, 'w', encoding='utf-8') as f:
            yaml.dump_all(docs, f)


def main():
    parser = argparse.ArgumentParser(
            description="Check for outdated assets on SC4E and/or STEX.",
            epilog="The STEX_API_KEY environment variable must be set for STEX queries. (API key is issued by ST admins.)")
    parser.add_argument('--api', action="append", choices=('sc4e', 'stex'), help="Which exchange API to check (default: both)")
    parser.add_argument('--mode', choices=['id', 'updated'], default='updated', help="STEX: query mode (default: updated); query all IDs from given yaml files, or query recently updated STEX entries")
    parser.add_argument('--update', action='store_true', help="Update YAML files in place with upstream asset info")
    parser.add_argument('-y', '--yes', action='store_true', help="Download assets without confirmation if --update is set")
    parser.add_argument('--save-reports', type=str, help="Directory to save fetched reports (for caching)")
    parser.add_argument('--load-reports', type=str, help="Directory to load cached reports (for offline/cached use)")
    parser.add_argument('--no-exit-status', action='store_true', help="Always exit with status 0 unless there is an unhandled exception")
    parser.add_argument('paths', nargs='*', help="YAML files or directories to check")
    args = parser.parse_args()
    if not args.api:
        args.api = ['sc4e', 'stex']

    apis = []
    if 'sc4e' in args.api:
        apis.append(('SC4E', Sc4eApi()))
    if 'stex' in args.api:
        stex_api_key = os.environ.get('STEX_API_KEY')
        if not stex_api_key:
            print("The STEX_API_KEY environment variable must be set for STEX queries.")
            return 1
        apis.append(('STEX', StexApi(stex_api_key, mode=args.mode)))

    result = 0
    if not args.paths:
        print("Found no yaml files to analyze.")
        return result
    docs = list(nonempty_docs(args.paths))
    total_errors = 0
    file_to_updates = {} if args.update else None
    for label, api in apis:
        if isinstance(api, StexApi) and api.mode == "id":
            # For STEX in id mode, collect file IDs first
            file_ids = []
            for path, doc_list in docs:
                if doc_list is None:  # TODO parse error
                    continue
                for doc in doc_list:
                    url = doc.get('nonPersistentUrl') or doc.get('url')
                    if url is None:
                        continue  # not an asset
                    file_id, _ = api.extract_id(url)
                    if file_id:
                        file_ids.append(file_id)
            if not file_ids:
                print("No STEX file IDs found in yaml files.")
                continue
        else:
            file_ids = None
        upstream_state = api.fetch_upstream_state(file_ids=file_ids, load_reports_dir=args.load_reports, save_reports_dir=args.save_reports)
        out_of_date, up_to_date, skipped, errors = check_updates(api, docs, upstream_state, file_to_updates, update_mode=args.update)
        total_errors += errors
        skipped_msg = (
            "" if not skipped else
            f" (skipped {skipped} assets not updated in the last {api.since_days} days)" if isinstance(api, StexApi) and api.mode != "id" else
            f" (skipped {skipped} assets)")
        if out_of_date == 0:
            print(f"All {up_to_date} {label} assets are up-to-date{skipped_msg}.")
        else:
            print(f"There are {out_of_date} outdated {label} assets, while {up_to_date} are up-to-date{skipped_msg}.")
            if not args.update:
                result |= 0x02
    if args.update:
        tmpdir = tempfile.mkdtemp(prefix="sc4pac-dl-")
        try:
            downloader = Downloader(tmpdir, yes=args.yes)
            for yaml_path, updates in file_to_updates.items():
                print(f"Updating {yaml_path} ...")
                update_yaml_file_in_place(yaml_path, updates, downloader=downloader)
        finally:
            if tmpdir:
                shutil.rmtree(tmpdir)
    if total_errors > 0:
        print(f"Finished with {total_errors} errors.")
        result |= 0x01
    return result if not args.no_exit_status else 0


if __name__ == '__main__':
    sys.exit(main())
