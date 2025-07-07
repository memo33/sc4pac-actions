#!/usr/bin/env python3
#
# Given some input yaml files, outputs the package identifiers
# (`<group>:<name>`) of packages defined in those files.
#
# Pass directories or yaml files as arguments.

import yaml
import sys
import os


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
                    path, None


def main() -> int:
    args = sys.argv[1:]
    if not args:
        return 0

    errors = 0
    pkgs = []
    for p, doc in nonempty_docs(args):
        if doc is None:  # parse error
            errors += 1
            print(f"parse error: {p}", file=sys.stderr)
            continue

        if 'packages' in doc:
            for obj in doc.get('packages', []):
                pkgs.append(f"{obj['group']}:{obj['name']}")
        elif 'group' in doc and 'name' in doc:
            pkgs.append(f"{doc['group']}:{doc['name']}")
        else:
            pass  # e.g. asset

    for pkg in pkgs:
        print(pkg)

    if errors > 0:
        print(f"Finished with {errors} errors.")
        return 1
    else:
        return 0


if __name__ == '__main__':
    sys.exit(main())
