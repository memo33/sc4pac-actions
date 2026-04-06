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
from datetime import timezone, timedelta
import urllib.request
import json


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
                    for doc in yaml.safe_load_all(text):
                        if doc is None:  # empty yaml file or document
                            continue
                        yield path, doc
                except yaml.parser.ParserError:
                    yield path, None


class ExchangeApi:
    def fetch_upstream_state(self, file_ids=None):
        raise NotImplementedError

    def extract_id(self, url):
        raise NotImplementedError

    def upstream_last_modified(self, upstream_entry):
        raise NotImplementedError

    def upstream_version(self, upstream_entry):
        raise NotImplementedError

    def upstream_download_url(self, upstream_entry):
        raise NotImplementedError

    def check_subfile(self, upstream_entry, subfile_id):
        # For APIs that support subfiles (STEX), override this.
        return True, ""


class Sc4eApi(ExchangeApi):
    url_id_pattern = re.compile(r".*sc4evermore.com/.*[?&]id=(\d+).*")

    def fetch_upstream_state(self, file_ids=None):
        req = urllib.request.Request(
            "https://www.sc4evermore.com/latest-modified-downloads.php",
            headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as data:
            report = json.load(data)
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

    def upstream_download_url(self, upstream_entry):
        file_id = upstream_entry['id']
        return f"https://www.sc4evermore.com/index.php/downloads/download/{file_id}"


class StexApi(ExchangeApi):
    url_id_pattern = re.compile(r".*simtropolis.com/files/file/(\d+)-.*?(?:$|[?&]r=(\d+).*$)")  # matches ID and optional subfile ID
    since_days = 180  # to keep the request small
    id_limit = 250  # to keep the request small

    def __init__(self, api_key, mode="updated"):
        self.api_key = api_key
        self.mode = mode

    def fetch_upstream_state(self, file_ids=None):
        if self.mode == "id":
            if not file_ids:
                return {}
            req_url = f"https://community.simtropolis.com/stex/files-api.php?key={self.api_key}&sort=desc&id=" + ",".join(file_ids[:self.id_limit])
        else:
            req_url = f"https://community.simtropolis.com/stex/files-api.php?key={self.api_key}&days={self.since_days}&mode=updated&sc4only=true&sort=desc"
        req = urllib.request.Request(req_url, headers={'User-Agent': 'Mozilla/5.0 Firefox/130.0'})
        with urllib.request.urlopen(req) as data:
            report = json.load(data)
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

    def upstream_download_url(self, upstream_entry):
        return upstream_entry.get('fileURL')

    def check_subfile(self, upstream_entry, subfile_id):
        subfiles = upstream_entry.get('files', [])
        if subfile_id is None:
            if len(subfiles) != 1:
                msg = f"url must include subfile ID `r=#` as there are {len(subfiles)} subfiles:" + \
                      "\n    " + \
                      "\n    ".join(f"{r.get('id')}: {r.get('name')}" for r in subfiles)
                return False, msg
        else:
            if subfile_id not in [str(r.get('id')) for r in subfiles]:
                msg = f"url subfile ID {subfile_id} does not exist (anymore), so must be updated:" + \
                      "\n    " + \
                      "\n    ".join(f"{r.get('id')}: {r.get('name')}" for r in subfiles)
                return False, msg
        return True, ""


def check_updates(api, docs, upstream_state):
    errors = 0
    out_of_date = 0
    up_to_date = 0
    skipped = 0
    for p, doc in docs:
        if doc is None:
            errors += 1
            continue
        url = doc.get('nonPersistentUrl') or doc.get('url')
        if url is None:
            continue
        file_id, subfile_id = api.extract_id(url)
        if file_id is None or file_id not in upstream_state:
            skipped += 1
            continue
        upstream_entry = upstream_state[file_id]
        ok, msg = api.check_subfile(upstream_entry, subfile_id)
        if not ok:
            errors += 1
            print(f"{doc.get('assetId')}:")
            print(f"  {msg}")
            print(f"  {api.upstream_download_url(upstream_entry)}")
        last_modified_upstream = api.upstream_last_modified(upstream_entry)
        if 'lastModified' not in doc:
            errors += 1  # TODO
            continue
        last_modified = isoparse(doc.get('lastModified'))
        # we ignore small timestamp differences
        if abs(last_modified_upstream - last_modified) <= timedelta(minutes=10):
            up_to_date += 1
        else:
            if last_modified < last_modified_upstream:
                out_of_date += 1
            else:
                errors += 1  # our assets should not be newer than upstream's assets TODO
                print("error: ", end='')
            print(f"{doc.get('assetId')}:")
            print(f"  {doc.get('version')} -> {api.upstream_version(upstream_entry)}")
            print(f"  {last_modified.isoformat().replace('+00:00', 'Z')} -> {last_modified_upstream.isoformat().replace('+00:00', 'Z')}")
            print(f"  {api.upstream_download_url(upstream_entry)}")
            print(f"  {p}")
    return out_of_date, up_to_date, skipped, errors


def main():
    parser = argparse.ArgumentParser(
            description="Check for outdated assets on SC4E and/or STEX.",
            epilog="The STEX_API_KEY environment variable must be set for STEX queries. (API key is issued by ST admins.)")
    parser.add_argument('--api', action="append", choices=('sc4e', 'stex'), help="Which exchange API to check (default: both)")
    parser.add_argument('--mode', choices=['id', 'updated'], default='updated', help="STEX: query mode (default: updated); query all IDs from given yaml files, or query recently updated STEX entries")
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
    for label, api in apis:
        # For STEX in id mode, collect file IDs first
        file_ids = []
        if isinstance(api, StexApi) and api.mode == "id":
            for _, doc in docs:
                if doc is None:  # TODO parse error
                    continue
                url = doc.get('nonPersistentUrl') or doc.get('url')
                if url is None:
                    continue  # not an asset
                file_id, _ = api.extract_id(url)
                if file_id:
                    file_ids.append(file_id)
            if not file_ids:
                print("No STEX file IDs found in yaml files.")
                continue
            upstream_state = api.fetch_upstream_state(file_ids=file_ids)
        else:
            upstream_state = api.fetch_upstream_state()
        out_of_date, up_to_date, skipped, errors = check_updates(api, docs, upstream_state)
        total_errors += errors
        skipped_msg = (
            "" if not skipped else
            f" (skipped {skipped} assets not updated in the last {api.since_days} days)" if isinstance(api, StexApi) and api.mode != "id" else
            f" (skipped {skipped} assets)")
        if out_of_date == 0:
            print(f"All {up_to_date} {label} assets are up-to-date{skipped_msg}.")
        else:
            print(f"There are {out_of_date} outdated {label} assets, while {up_to_date} are up-to-date{skipped_msg}.")
            result |= 0x02
    if total_errors > 0:
        print(f"Finished with {total_errors} errors.")
        result |= 0x01
    return result

if __name__ == '__main__':
    sys.exit(main())
