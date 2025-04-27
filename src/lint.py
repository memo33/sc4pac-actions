#!/usr/bin/env python3
#
# Pass directories or yaml files as arguments to validate sc4pac yaml files.

import yaml
import sys
import os
import re
from urllib.parse import (urlparse, parse_qs)
import jsonschema
from jsonschema import ValidationError
import typing

# add subfolders as necessary
default_subfolders = r"""
### [subfolders-docsify]
050-load-first
100-props-textures
150-mods
170-terrain
180-flora
200-residential
300-commercial
360-landmark
400-industrial
410-agriculture
500-utilities
600-civics
610-safety
620-education
630-health
640-government
650-religion
660-parks
700-transit
710-automata
900-overrides
### [subfolders-docsify]
""".strip().splitlines()[1:-1]

# Add packages as necessary. These packages should only be used as dependencies
# from packages with a matching variant. For example, a package without a DN
# variant should never depend on simfox:day-and-nite-mod.
variant_specific_dependencies = {
    "simfox:day-and-nite-mod": ("nightmode", "dark"),
    "toroca:industry-quadrupler": ("toroca:industry-quadrupler:capacity", "quadrupled"),
    "cam:colossus-addon-mod": ("CAM", "yes"),
}


def create_schema(config):
    unique_strings = {
        "type": "array",
        "items": {"type": "string"},
        "uniqueItems": True,
    }

    map_of_strings = {
        "type": "object",
        # "patternProperties": {".*": {"type": "string"}},
        "additionalProperties": {"type": "string"},
    }

    asset_schema = {
        "title": "Asset",
        "type": "object",
        "additionalProperties": False,
        "required": ["assetId", "version", "lastModified", "url"],
        "properties": {
            "assetId": {"type": "string"},
            "version": {"type": "string"},
            "lastModified": {"type": "string"},
            "url": {"type": "string", "validate_query_params": True},
            "nonPersistentUrl": {"type": "string", "validate_query_params": True},
            "archiveType": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "format": {"enum": ["Clickteam"]},
                    "version": {"enum": ["20", "24", "30", "35", "40"]},
                },
            },
            "checksum": {
                "type": "object",
                "additionalProperties": False,
                "required": ["sha256"],
                "properties": {
                    "sha256": {"type": "string", "validate_sha256": True},
                },
            },
        },
    }

    assets = {
        "type": "array",
        "items": {
            "type": "object",
            "additionalProperties": False,
            "required": ["assetId"],
            "properties": {
                "assetId": {"type": "string"},
                "include": {**unique_strings, "validate_pattern": True},
                "exclude": {**unique_strings, "validate_pattern": True},
                "withChecksum": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["include", "sha256"],
                        "properties": {
                            "include": {"type": "string", "validate_pattern": True},
                            "sha256": {"type": "string", "validate_sha256": True},
                        },
                    },
                    "uniqueItems": True,
                },
            },
        },
    }

    package_schema = {
        "title": "Package",
        "type": "object",
        "additionalProperties": False,
        "required": ["group", "name", "version", "subfolder"],
        "properties": {
            "group": {"type": "string"},
            "name": {"type": "string", "validate_name": True},
            "version": {"type": "string"},
            "subfolder": {"enum": sorted(set(default_subfolders + config['subfolders']))},
            "dependencies": unique_strings,
            "conflicting": unique_strings,
            "assets": assets,
            "variants": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["variant"],
                    "properties": {
                        "variant": map_of_strings,
                        "dependencies": unique_strings,
                        "conflicting": unique_strings,
                        "assets": assets,
                    },
                },
            },
            "variantDescriptions": {
                "type": "object",
                "patternProperties": {".*": map_of_strings},
            },
            "variantInfo": {
                "type": "array",
                "unique_by": "variantId",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["variantId"],
                    "properties": {
                        "variantId": {"type": "string"},
                        "description": {"type": "string", "validate_text_field": "description"},
                        "values": {
                            "type": "array",
                            "unique_by": "value",
                            "items": {
                                "type": "object",
                                "additionalProperties": False,
                                "required": ["value"],
                                "properties": {
                                    "value": {"type": "string"},
                                    "description": {"type": "string", "validate_text_field": "description"},
                                    "default": {"type": "boolean"},
                                },
                            },
                        },
                    },
                },
            },
            "info": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "summary": {"type": "string"},
                    "warning": {"type": "string", "validate_text_field": "warning"},
                    "conflicts": {"type": "string", "validate_text_field": "conflicts"},
                    "description": {"type": "string", "validate_text_field": "description"},
                    "author": {"type": "string"},
                    "images": unique_strings,
                    "website": {"type": "string", "validate_query_params": True},
                    "websites": {**unique_strings, "validate_query_params": True},
                },
            },
        },
    }

    # Using this combined schema would lead to unhelpful error messages in case neither schema fully matches.
    # schema = {
    #     "oneOf": [package_schema, asset_schema]
    # }
    return package_schema, asset_schema


class DependencyChecker:

    naming_convention = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
    naming_convention_variants_value = re.compile(r"[a-z0-9]+([-\.][a-z0-9]+)*", re.IGNORECASE)
    naming_convention_variants = re.compile(  # group:package:variant (regex groups: \1:\2:\3)
            rf"(?:({naming_convention.pattern}):)?(?:({naming_convention.pattern}):)?([a-zA-Z0-9]+(?:[-\.][a-zA-Z0-9]+)*)")
    naming_convention_files = re.compile(r"[a-z0-9]+([-\./\\][a-z0-9]+)*", re.IGNORECASE)
    version_rel_pattern = re.compile(r"(.*?)(-\d+)?")
    pronouns_pattern = re.compile(r"\b[Mm][ey]\b|(?:\bI\b(?!-|\.| [A-Z]))")
    desc_invalid_chars_pattern = re.compile(r'\\n|\\"')
    sha256_pattern = re.compile(r"[a-f0-9]*", re.IGNORECASE)
    gh_url_pattern = re.compile(r"^https://github\.com/([^/]+)/(?:[^/]+)/releases/download/.*")
    unescaped_paren_open  = re.compile(r"(?<!\\)\((?!\?)")  # a `(` not preceded by `\` or followed by `?`
    unescaped_paren_close = re.compile(r"(?<!\\)\)(?!\?)")  # a `)` not preceded by `\` or followed by `?`
    unescaped_dollar = re.compile(r"(?<!\\)\$(?!$|[|])")  # a `$` not preceded by `\` and not at the end and not followed by `|`

    def __init__(self, *, config):
        self.config = config
        self.known_packages = set()
        self.known_assets = set()
        self.referenced_packages = set()
        self.referenced_assets = set()
        self.self_dependencies = set()
        self.bad_conflicts = set()
        self.duplicate_packages = set()
        self.duplicate_assets = set()
        self.asset_urls = {}  # asset -> url
        self.asset_versions = {}  # asset -> version
        self.overlapping_variants = set()
        self.known_variant_values = {}
        self.unexpected_variants = []
        self.invalid_asset_names = set()
        self.invalid_group_names = set()
        self.invalid_package_names = set()
        self.invalid_variant_names = set()
        self.packages_with_single_assets = {}  # pkg -> (version, set of assets from variants)
        self.packages_using_asset = {}  # asset -> set of packages
        self.dlls_without_checksum = set()
        self.assets_http_without_checksum = set()
        self.packages_with_checksum = []  # (pkg, group, assetId)
        self.unexpected_variant_specific_dependencies = []  # (pkg, dependency)
        self.duplicate_website_fields = set()
        self.deprecated_variant_descs = set()
        self.invalid_variant_info_ids = []
        self.invalid_variant_info_values = []
        self.duplicate_default_variants = []

    def aggregate_identifiers(self, doc):
        if 'assetId' in doc:
            asset = doc['assetId']
            if asset not in self.known_assets:
                self.known_assets.add(asset)
            else:
                self.duplicate_assets.add(asset)
            url = doc.get('url')
            self.asset_urls[asset] = url
            self.asset_versions[asset] = doc.get('version')
            if not self.naming_convention.fullmatch(asset):
                self.invalid_asset_names.add(asset)
            if urlparse(url).scheme not in ['https', 'file'] and 'checksum' not in doc:
                self.assets_http_without_checksum.add(asset)
        if 'group' in doc and 'name' in doc:
            pkg = f"{doc['group']}:{doc['name']}"
            if pkg not in self.known_packages:
                self.known_packages.add(pkg)
            else:
                self.duplicate_packages.add(pkg)
            if not self.naming_convention.fullmatch(doc['group']):
                self.invalid_group_names.add(doc['group'])
            if not self.naming_convention.fullmatch(doc['name']):
                self.invalid_package_names.add(doc['name'])

            def asset_ids(obj):
                return (a['assetId'] for a in obj.get('assets', []) if 'assetId' in a)

            variants0 = doc.get('variants', [])
            def iterate_doc_and_variants():
                yield doc
                yield from variants0

            for obj in iterate_doc_and_variants():
                local_deps = obj.get('dependencies', [])
                self.referenced_packages.update(local_deps)
                for dep in local_deps:
                    if dep == pkg:
                        self.self_dependencies.add(pkg)
                    if dep in variant_specific_dependencies:
                        expected_variant, expected_value = variant_specific_dependencies[dep]
                        if obj.get('variant', {}).get(expected_variant) != expected_value:
                            self.unexpected_variant_specific_dependencies.append((pkg, dep))

                local_conflicts = set(obj.get('conflicting', []))
                self.referenced_packages.update(local_conflicts)
                if local_conflicts and (
                        pkg in local_conflicts or
                        any(dep in local_conflicts for dep in local_deps) or
                        any(dep in local_conflicts for dep in doc.get('dependencies', []))):
                    self.bad_conflicts.add(pkg)

                local_assets = list(asset_ids(obj))
                self.referenced_assets.update(local_assets)
                for a in local_assets:
                    if a in self.packages_using_asset:
                        self.packages_using_asset[a].add(pkg)
                    else:
                        self.packages_using_asset[a] = set([pkg])

            num_doc_assets = len(doc.get('assets', []))
            if num_doc_assets <= 1:
                single_assets = set(asset_ids(doc))
                if all(len(v.get('assets', [])) <= 1 for v in variants0):
                    for v in variants0:
                        single_assets.update(asset_ids(v))
                    self.packages_with_single_assets[pkg] = (doc.get('version'), single_assets)

            variants = [v.get('variant', {}) for v in variants0]
            if len(variants) != len(set(tuple(sorted(v.items())) for v in variants)):
                # the same variant should not be defined twice
                self.overlapping_variants.add(pkg)

            variant_keys = set(key for v in variants for key, value in v.items())
            for key in variant_keys:
                variant_values = set(v[key] for v in variants if key in v)
                if key not in self.known_variant_values:
                    self.known_variant_values[key] = variant_values
                elif self.known_variant_values[key] != variant_values:
                    self.unexpected_variants.append((pkg, key, sorted(variant_values), sorted(self.known_variant_values[key])))
                else:
                    pass
                if not self.naming_convention_variants.fullmatch(str(key)):
                    self.invalid_variant_names.add(key)
                for value in variant_values:
                    if not self.naming_convention_variants_value.fullmatch(value):
                        self.invalid_variant_names.add(value)

            info = doc.get('info', {})
            if 'website' in info and 'websites' in info:
                self.duplicate_website_fields.add(pkg)

            is_dll = ("DLL" in info.get('summary', "")) or ("dll" in doc['name'].split('-'))
            has_asset = False
            has_checksum = False
            for obj in iterate_doc_and_variants():
                for asset in obj.get('assets', []):
                    has_asset = True
                    if "withChecksum" in asset:
                        has_checksum = True
                        self.packages_with_checksum.append((pkg, doc['group'], asset.get('assetId')))
            if is_dll and has_asset and not has_checksum:
                self.dlls_without_checksum.add(pkg)

            variant_info = doc.get('variantInfo', [])
            if variant_info and 'variantDescriptions' in doc:
                self.deprecated_variant_descs.add(pkg)
            for vinfo in variant_info:
                variant_id = vinfo.get('variantId')
                if variant_id not in variant_keys:
                    self.invalid_variant_info_ids.append((pkg, variant_id))
                else:
                    expected_variant_values = self.known_variant_values[variant_id]
                    unexpected_variant_values = [v for vitem in vinfo.get('values', [])
                                                 if (v := vitem.get('value')) not in expected_variant_values]
                    if unexpected_variant_values:
                        self.invalid_variant_info_values.append((pkg, variant_id, unexpected_variant_values))
                num_defaults = len([v for v in vinfo.get('values', []) if v.get('default')])
                if num_defaults > 1:
                    self.duplicate_default_variants.append((pkg, variant_id))


    def _get_channel_contents(self, channel_url):
        import urllib.request
        import json
        if channel_url.endswith("/"):  # otherwise it should be a .yaml file
            channel_url = f"{channel_url}sc4pac-channel-contents.json"
        req = urllib.request.Request(channel_url)
        with urllib.request.urlopen(req) as data:
            channel_contents = json.load(data)
        return channel_contents

    def unknowns(self):
        packages = self.referenced_packages.difference(self.known_packages)
        assets = self.referenced_assets.difference(self.known_assets)
        if packages or assets:
            # some dependencies are not known, so check other channels
            channels = [self._get_channel_contents(channel_url) for channel_url in self.config['extra-channels']]
            remote_assets = [pkg['name'] for c in channels for pkg in c['assets']]
            remote_packages = [f"{pkg['group']}:{pkg['name']}" for c in channels for pkg in c['packages']]
            packages = packages.difference(remote_packages)
            assets = assets.difference(remote_assets)
        return {'packages': sorted(packages), 'assets': sorted(assets)}

    def duplicates(self):
        return {'packages': sorted(self.duplicate_packages),
                'assets': sorted(self.duplicate_assets)}

    def assets_with_same_url(self):
        url_assets = {u: a for a, u in self.asset_urls.items()}
        non_unique_assets = [(a1, a2) for a1, u in self.asset_urls.items()
                             if (a2 := url_assets[u]) != a1]
        return non_unique_assets

    def unused_assets(self):
        return sorted(self.known_assets.difference(self.referenced_assets))

    # turns a patch version such as 1.0.0-2 into 1.0.0
    def _version_without_rel(self, version):
        return self.version_rel_pattern.fullmatch(version).group(1)

    def _should_expect_matching_version_for_asset(self, asset):
        # for assets used by more packages, we assume that the asset contains
        # multiple unrelated packages, so versions of packages do not need to match
        return len(self.packages_using_asset.get(asset, [])) <= 3

    def package_asset_version_mismatches(self):
        ignore_version_mismatches = set(self.config['ignore-version-mismatches'])
        for pkg, (version, assets) in self.packages_with_single_assets.items():
            if pkg in ignore_version_mismatches:
                continue
            v1 = self._version_without_rel(version)
            for asset in assets:
                if self._should_expect_matching_version_for_asset(asset):
                    v2 = self._version_without_rel(self.asset_versions.get(asset, 'None'))
                    if v1 != v2:
                        yield (pkg, v1, asset, v2)

    def dlls_without_github_messages(self):
        ignore_non_gh = set(self.config['ignore-non-github-urls'])
        grp2gh = {}  # group -> set()
        for d in self.config['group-to-github']:
            for group, gh_owner in d.items():
                if group in grp2gh:
                    grp2gh[group].add(gh_owner)
                else:
                    grp2gh[group] = {gh_owner}
        for pkg, group, asset in self.packages_with_checksum:
            m = self.gh_url_pattern.fullmatch(self.asset_urls[asset])
            if not m:
                if asset not in ignore_non_gh:
                    yield f"""Asset "{asset}" should use a GitHub download "url", as it appears to be a DLL used by "{pkg}"."""
            else:
                gh_owner = m.group(1)
                if gh_owner not in grp2gh.get(group, set()):
                    yield f"""GitHub account "{gh_owner}" for asset "{asset}" is not known to belong to group "{group}" """ \
                            "(a new mapping needs to be defined in lint-config.yaml)."


def validate_document_separators(text) -> None:
    needs_separator = False
    errors = 0
    for line in text.splitlines():
        if line.startswith("---"):
            needs_separator = False
        elif (line.startswith("group:") or line.startswith("\"group\":") or
              line.startswith("url:") or line.startswith("\"url\":")):
            if needs_separator:
                errors += 1
            else:
                needs_separator = True
        elif line.startswith("..."):
            break
    if errors > 0:
        raise yaml.parser.ParserError(
                "YAML file contains multiple package and asset definitions. They all need to be separated by `---`.")


def create_validators(config):

    def validate_pattern(validator, value, instance, schema):
        patterns = [instance] if isinstance(instance, str) else instance
        msgs = []
        bad_prefix = [p for p in patterns if p.startswith('.*')]
        if bad_prefix:
            msgs.append(f"include/exclude patterns should not start with '.*' in {bad_prefix}")
        bad_parens = [p for p in patterns if
                      DependencyChecker.unescaped_paren_open.search(p) and ")?" not in p or
                      DependencyChecker.unescaped_paren_close.search(p) and "(?" not in p]
        if bad_parens:
            msgs.append(rf"Parentheses in include/exclude patterns need to be escaped: use `\(...\)` for literals or `(?:...)` for regex-grouping in {bad_parens}. "
                        r"If the include/exclude pattern is enclosed in double quotes in YAML, then use double-backslashes: `\\(...\\)`.")
        bad_dollars = [p for p in patterns if DependencyChecker.unescaped_dollar.search(p)]
        if bad_dollars:
            msgs.append(rf"Dollar signs in include/exclude patterns need to be escaped: use `\$` instead of `$` in {bad_dollars}."
                        r" Otherwise, `$` means end-of-line."
                        r" If the include/exclude pattern is enclosed in double quotes in YAML, use double-backslashes: `\\$`.")
        bad_backslashes = [p for p in patterns if r"\\" in p]
        if bad_backslashes:
            msgs.append(f"Incorrect use of double backslashes in regex: {', '.join(bad_backslashes)}."
                        r" Use double backslashes `\\` only within double quotes,"
                        r" use single backslashes `\` in strings enclosed in single quotes or no quotes,"
                        r" use forward slashes `/` as path separator between folders and files.")
        if msgs:
            yield ValidationError('\n'.join(msgs))

    _irrelevant_query_parameters = [
        ("sc4evermore.com", ("catid",)),
        ("simtropolis.com", ("confirm", "t", "csrfKey")),
    ]

    def validate_query_params(validator, value, urls, schema):
        if isinstance(urls, str):
            urls = [urls]
        msgs = []
        for url in urls:
            if '/sc4evermore.com/' in url:
                msgs.append(f"Domain of URL {url} should be www.sc4evermore.com (add www.)")
            qs = parse_qs(urlparse(url).query)
            bad_params = [p for domain, params in _irrelevant_query_parameters
                          if domain in url for p in params if p in qs]
            if bad_params:
                msgs.append(f"Avoid these URL query parameters: {', '.join(bad_params)}")
        if msgs:
            yield ValidationError('\n'.join(msgs))

    def validate_name(validator, value, name, schema):
        if "-vol-" in str(name):
            yield ValidationError(f"Avoid the hyphen after 'vol' (for consistency with other packages): {name}")

    allow_ego_perspective = config['allow-ego-perspective']
    def validate_text_field(validator, field, text, schema):
        msgs = []
        if text is not None and text.strip().lower() == "none":
            msgs.append(f"""Text "{field}" should not be "{text.strip()}", but should be omitted instead.""")
        if text is not None and not allow_ego_perspective and DependencyChecker.pronouns_pattern.search(text):
            msgs.append(f"""The "{field}" should be written in a neutral perspective (avoid the words 'I', 'me', 'my').""")
        if text is not None and DependencyChecker.desc_invalid_chars_pattern.search(text):
            msgs.append("""The "{field}" seems to be malformed (avoid the characters '\\n', '\\"').""")
        if msgs:
            yield ValidationError('\n'.join(msgs))

    def validate_sha256(validator, value, text, schema):
        if not (len(text) == 64 and DependencyChecker.sha256_pattern.fullmatch(text)):
            yield ValidationError(f"value is not a sha256: {text}")

    def unique_by(validator, field, items, schema):
        seen = set()
        dupes = []
        for item in items:
            if field in item:
                v = item[field]
                if isinstance(v, typing.Hashable):  # else this is likely a type error that will be caught elsewhere
                    if v not in seen:
                        seen.add(v)
                    else:
                        dupes.append(v)
        if dupes:
            items_abbrev = [f"{{{repr(field)}: {repr(item.get(field))},...}}" for item in items]
            yield ValidationError(f"""Array contains ambiguous items with field {repr(field)} = {"/".join(map(repr, dupes))}:  [{", ".join(items_abbrev)}].""")

    return dict(
        validate_pattern=validate_pattern,
        validate_query_params=validate_query_params,
        validate_name=validate_name,
        validate_text_field=validate_text_field,
        validate_sha256=validate_sha256,
        unique_by=unique_by,
    )


def show_usage():
    print(
        "Usage: Pass at least one directory or yaml file to validate as argument.\n"
        "Options:\n"
        """--config <path>  path to lint-config.yaml file (defaults to "./lint-config.yaml")"""
    )
    return 1


def load_config(config_path):
    default_config = {
        'extra-channels': [],
        'subfolders': [],
        'ignore-version-mismatches': [],
        'allow-ego-perspective': False,
        'group-to-github': [],
        'ignore-non-github-urls': [],
    }
    try:
        with open(config_path, encoding='utf-8') as f:
            config = yaml.safe_load(f)
            return {**default_config, **config}
    except FileNotFoundError:
        print(f"Configuration file {config_path} not found, so using default configuration.")
        return default_config


def main() -> int:
    args = sys.argv[1:]
    config_path = "lint-config.yaml"
    while True:
        if not args:
            return show_usage()
        if args[0] == "--config":
            if len(args) < 2:
                return show_usage()
            config_path = args[1]
            args = args[2:]
            continue
        break
    config = load_config(config_path)

    def validator_from_schema(schema):
        validator = jsonschema.validators.extend(
                jsonschema.validators.Draft202012Validator,
                validators=create_validators(config),
            )(schema)
        validator.check_schema(schema)
        return validator
    package_validator, asset_validator = [validator_from_schema(s) for s in create_schema(config)]

    dependency_checker = DependencyChecker(config=config)
    validated = 0
    errors = 0

    def basic_report(identifiers, msg: str, stringify=None):
        if identifiers:
            nonlocal errors
            errors += len(identifiers)
            print(f"===> {msg}")
            for identifier in identifiers:
                print(identifier if stringify is None else stringify(identifier))

    for src_dir in args:
        for (parent, dirs, files) in os.walk(src_dir):
            for fname in files:
                if not fname.endswith(".yaml"):
                    continue
                msgs = []
                p = os.path.join(parent, fname)
                if not DependencyChecker.naming_convention_files.fullmatch(os.path.relpath(p, start=src_dir)):
                    msgs.append("File name should not contain spaces or other special characters.")
                with open(p, encoding='utf-8') as f:
                    validated += 1
                    text = f.read()
                    try:
                        validate_document_separators(text)
                        for doc in yaml.safe_load_all(text):
                            if doc is None:  # empty yaml file or document
                                continue
                            if "group" in doc:
                                err = jsonschema.exceptions.best_match(package_validator.iter_errors(doc))
                            elif "url" in doc:
                                err = jsonschema.exceptions.best_match(asset_validator.iter_errors(doc))
                            else:
                                err = ValidationError("""document does not look like a package or asset (found neither "group" nor "url")""")
                            if err is not None:
                                msgs.append(err.message)
                            else:
                                dependency_checker.aggregate_identifiers(doc)
                    except yaml.parser.ParserError as err:
                        msgs.append(str(err))
                if msgs:
                    errors += len(msgs)
                    print(f"===> {p}")
                    for msg in msgs:
                        print(msg)

    if not errors:
        # check that all dependencies exist
        # (this check only makes sense for the self-contained main channel)
        for label, unknown in dependency_checker.unknowns().items():
            basic_report(unknown, f"The following {label} are referenced, but not defined:")
        for label, dupes in dependency_checker.duplicates().items():
            basic_report(dupes, f"The following {label} are defined multiple times:")
        basic_report(dependency_checker.self_dependencies, "The following packages unnecessarily depend on themselves:")
        basic_report(dependency_checker.bad_conflicts, "The following packages conflict with their dependencies or themselves, which prevents them from getting installed at all:")  # this check is not exhaustive here, but only intended to catch obvious mistakes
        basic_report(dependency_checker.unexpected_variant_specific_dependencies, "The following packages have dependencies that should only be used with specific variants:",
                     lambda tup: "{0} depends on {1}, but this dependency should only be used with variant \"{2}={3}\"".format(*(tup + variant_specific_dependencies[tup[1]])))
        basic_report(dependency_checker.assets_with_same_url(),
                     "The following assets have the same URL (The same asset was defined twice with different asset IDs):",
                     lambda assets: ', '.join(assets))
        basic_report(dependency_checker.unused_assets(), "The following assets are not used:")
        basic_report(dependency_checker.overlapping_variants, "The following packages have duplicate variants:")
        basic_report(dependency_checker.unexpected_variants, "",
                     lambda tup: "{0} defines unexpected {1} variants {2} (expected: {3})".format(*tup))  # pkg, key, values, expected_values
        basic_report(dependency_checker.invalid_asset_names, "the following assetIds do not match the naming convention (lowercase alphanumeric hyphenated)")
        basic_report(dependency_checker.invalid_group_names, "the following group identifiers do not match the naming convention (lowercase alphanumeric hyphenated)")
        basic_report(dependency_checker.invalid_package_names, "the following package names do not match the naming convention (lowercase alphanumeric hyphenated)")
        basic_report(dependency_checker.invalid_variant_names, "the following variant labels or values do not match the naming convention (alphanumeric hyphenated or dots)")
        basic_report(list(dependency_checker.package_asset_version_mismatches()),
                     "The versions of the following packages do not match the version of the referenced assets (usually they should agree, but if the version mismatch is intentional, the packages can be added to the 'ignore-version-mismatches' list in lint-config.yaml):",
                     lambda tup: """{0} "{1}" (expected version "{3}" of asset {2})""".format(*tup))  # pkg, v1, asset, v2
        basic_report(dependency_checker.dlls_without_checksum, "The following packages appear to contain DLLs. A sha256 checksum is required for DLLs (add a `withChecksum` field).")
        basic_report(dependency_checker.assets_http_without_checksum, "The following assets use http instead of https. They should include a `checksum` field.")
        basic_report(list(dependency_checker.dlls_without_github_messages()), "DLLs should be downloaded from the author's GitHub releases to ensure authenticity.")
        basic_report(dependency_checker.duplicate_website_fields, """The following packages define both "website" and "websites" fields (use only one of them):""")
        basic_report(dependency_checker.deprecated_variant_descs, """The following packages define both "variantDescriptions" and "variantInfo" fields (use only "variantInfo"):""")
        basic_report(dependency_checker.invalid_variant_info_ids, "",
                     lambda tup: """The "variantInfo" field defines a variantId "{1}" which does not exist in package "{0}".""".format(*tup))
        basic_report(dependency_checker.invalid_variant_info_values, "",
                     lambda tup: """The "variantInfo" field for "{1}" in package "{0}" defines unknown values: {2}.""".format(*tup))
        basic_report(dependency_checker.duplicate_default_variants, "",
                     lambda tup: """The "variantInfo" field for "{1}" in package "{0}" defines too many (>1) "default" values.""".format(*tup))

    if errors > 0:
        print(f"Finished with {errors} errors.")
        return 1
    else:
        print(f"Successfully validated {validated} files.")
        return 0


if __name__ == '__main__':
    sys.exit(main())
