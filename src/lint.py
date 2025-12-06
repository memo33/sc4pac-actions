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
from dataclasses import dataclass

# add subfolders as necessary
default_subfolders = r"""
### [subfolders-docsify]
050-load-first
060-config
100-props-textures
110-resources
140-ordinances
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

default_global_variants = ["nightmode", "driveside", "roadstyle", "CAM"]  # extensible by `global-variants` lint-config


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

    include_exclude_checksum = {
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
    }

    assets = {
        "type": "array",
        "items": {
            "type": "object",
            "additionalProperties": False,
            "required": ["assetId"],
            "properties": {
                "assetId": {"type": "string"},
                **include_exclude_checksum,
                "withConditions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["ifVariant"],
                        "properties": {
                            "ifVariant": map_of_strings,
                            **include_exclude_checksum,
                        },
                    },
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
                    "summary": {"type": "string", "validate_text_field": "summary"},
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

    package_array_schema = {
        "title": "PackageArray",
        "type": "object",
        "additionalProperties": False,
        "required": ["packages"],
        "properties": {
            "packages": {
                "type": "array",
                "items": package_schema,

            },
            "assets": {
                "type": "array",
                "items": asset_schema,
            },
        },
    }

    # Using this combined schema would lead to unhelpful error messages in case neither schema fully matches.
    # schema = {
    #     "oneOf": [package_schema, asset_schema]
    # }
    return package_schema, asset_schema, package_array_schema


@dataclass(eq=True, frozen=True)
class Stanza:
    # A definition of file includes/excludes from a particular asset.
    # Usually, each Stanza in a yaml file should be unique for each variant or package.
    # This is a simplification, as verifying all variants and packages in a channel
    # are _functionally different_ would be complex (i.e. not just different in variant or package names).
    asset_ids: frozenset[str]
    dependencies: frozenset[str]
    include: frozenset[str]
    exclude: frozenset[str]
    withChecksumInclude: frozenset[str]
    conditional_variant_ids: frozenset[str]


class DependencyChecker:

    naming_convention = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
    naming_convention_variants_value = re.compile(r"[a-z0-9]+([-\.][a-z0-9]+)*", re.IGNORECASE)
    naming_convention_variants = re.compile(  # group:package:variant (regex groups: \1:\2:\3)
            rf"(?:({naming_convention.pattern}):)?(?:({naming_convention.pattern}):)?([a-zA-Z0-9]+(?:[-\.][a-zA-Z0-9]+)*)")
    naming_convention_files = re.compile(r"[a-z0-9]+([-\./\\][a-z0-9]+)*", re.IGNORECASE)
    naming_convention_files_lowercase = re.compile(naming_convention_files.pattern)
    version_rel_pattern = re.compile(r"(.*?)(-\d+)?")
    pronouns_pattern = re.compile(r"(?:\b[Mm][ey]\b(?!-))|(?:\bI\b(?!-|\.| [A-Z]))")
    desc_invalid_chars_pattern = re.compile(r'\\n|\\"')
    sha256_pattern = re.compile(r"[a-f0-9]*", re.IGNORECASE)
    gh_url_pattern = re.compile(r"^https://github\.com/([^/]+)/(?:[^/]+)/releases/download/.*")
    unescaped_paren_open  = re.compile(r"(?<!\\)\((?!\?)")  # a `(` not preceded by `\` or followed by `?`
    unescaped_paren_close = re.compile(r"(?<!\\)\)(?!\?)")  # a `)` not preceded by `\` or followed by `?`
    unescaped_dollar = re.compile(r"(?<!\\)\$(?!$|[|])")  # a `$` not preceded by `\` and not at the end and not followed by `|`
    superseded_pattern = re.compile(r"superseded.*pkg", re.IGNORECASE)
    md_pkg_link_pattern = re.compile(r"`pkg\b[^`]+`", re.IGNORECASE)

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
        self.valid_singular_variants = set(config['single-choice-variants'])
        self.singular_variants = []
        self.invalid_asset_names = set()
        self.invalid_group_names = set()
        self.invalid_package_names = set()
        self.invalid_variant_names = set()
        self.verbose_variant_names = []  # (variantId, value)
        self.ignore_all_group_prefixes_in_names = config['ignore-group-prefixes-in-name'] == True
        self.allowed_group_prefixes_in_names = set() if type(config['ignore-group-prefixes-in-name']) is bool else set(config['ignore-group-prefixes-in-name'])
        self.invalid_group_prefixes_in_names = set()
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
        self.superseded_with_assets = set()
        self.valid_global_variants = set(default_global_variants + config['global-variants'])
        self.unknown_global_variants = {}  # variantId -> pkg
        self.ignore_nonunique_includes = set(config['ignore-nonunique-includes'])
        self.duplicate_stanzas = []  # (pkg1, variant1, pkg2, variant2)

    def aggregate_identifiers(self, doc, stanzas: set[Stanza]):
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
            if not self.ignore_all_group_prefixes_in_names and pkg not in self.allowed_group_prefixes_in_names and doc['name'].startswith(f"{doc['group']}-"):
                self.invalid_group_prefixes_in_names.add(pkg)

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

                local_asset_ids = list(asset_ids(obj))
                self.referenced_assets.update(local_asset_ids)
                for a in local_asset_ids:
                    if a in self.packages_using_asset:
                        self.packages_using_asset[a].add(pkg)
                    else:
                        self.packages_using_asset[a] = set([pkg])

                # The following code makes an effort to extract stanzas that should be *unique*, but some edge cases will result in false-positives (e.g. when combining variants with conditional variants).
                if local_asset_ids and pkg not in self.ignore_nonunique_includes:
                    local_assets = [a for a in obj.get('assets', []) if 'assetId' in a and 'withConditions' not in a]
                    local_cond_assets = [a for a in obj.get('assets', []) if 'assetId' in a and 'withConditions' in a]
                    variant = obj.get('variant', {})
                    new_stanzas = []
                    if local_assets:
                        stanza = Stanza(
                                asset_ids=frozenset(a['assetId'] for a in local_assets),
                                dependencies=frozenset() if obj is doc else frozenset(local_deps),  # ignore dependencies for top-level stanzas, as different packages should not install same files, regardless of dependencies
                                include=frozenset(p for a in local_assets for p in a.get('include', [])),
                                exclude=frozenset(p for a in local_assets for p in a.get('exclude', [])),
                                withChecksumInclude=frozenset(w['include'] for a in local_assets for w in a.get('withChecksum', []) if 'include' in w),
                                conditional_variant_ids=frozenset())
                        new_stanzas.append((stanza, variant))
                    for a in local_cond_assets:
                        asset_ids_set = frozenset([a['assetId']])
                        local_deps_set = frozenset(local_deps)
                        for cond in a['withConditions']:
                            stanza = Stanza(
                                    asset_ids=asset_ids_set,
                                    dependencies=local_deps_set,
                                    include=frozenset(a.get('include', []) + cond.get('include', [])),
                                    exclude=frozenset(a.get('exclude', []) + cond.get('exclude', [])),
                                    withChecksumInclude=frozenset(w['include'] for w in cond.get('withChecksum', []) if 'include' in w),
                                    conditional_variant_ids=frozenset(cond.get('ifVariant', {}).keys()))
                            new_stanzas.append((stanza, variant | cond.get('ifVariant', {})))
                    for stanza, variant in new_stanzas:
                        p2v2 = stanzas.get(stanza)
                        if p2v2 is None:
                            stanzas[stanza] = pkg, variant
                        else:
                            self.duplicate_stanzas.append(p2v2 + (pkg, variant))

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

            def iterate_conditional_variants(obj):
                for asset in obj.get('assets', []):
                    for cond in asset.get('withConditions', []):
                        yield cond.get('ifVariant', {})

            conditional_variants = [v for obj in iterate_doc_and_variants() for v in iterate_conditional_variants(obj)]
            all_variants = variants + conditional_variants

            variant_keys = set(key for v in all_variants for key, value in v.items())
            for key in variant_keys:
                variant_values = set(v[key] for v in all_variants if key in v)
                if key not in self.known_variant_values:
                    self.known_variant_values[key] = variant_values
                elif self.known_variant_values[key] != variant_values:
                    self.unexpected_variants.append((pkg, key, sorted(variant_values), sorted(self.known_variant_values[key])))
                else:
                    pass
                if len(variant_values) == 1 and key not in self.valid_singular_variants:
                    self.singular_variants.append((pkg, key, variant_values))
                if not self.naming_convention_variants.fullmatch(str(key)):
                    self.invalid_variant_names.add(key)
                key0 = key.split(":")[-1]
                key0_pattern = re.compile(rf"\b{re.escape(key0)}\b")
                for value in variant_values:
                    if not self.naming_convention_variants_value.fullmatch(value):
                        self.invalid_variant_names.add(value)
                    if key0_pattern.search(value):
                        self.verbose_variant_names.append((key0, value))
                if ":" not in key and key not in self.valid_global_variants:
                    self.unknown_global_variants[key] = pkg

            info = doc.get('info', {})
            if 'website' in info and 'websites' in info:
                self.duplicate_website_fields.add(pkg)

            summary = info.get('summary', "")
            is_dll = ("DLL" in summary) or ("dll" in doc['name'].split('-'))
            has_asset = False
            has_checksum = False
            for obj in iterate_doc_and_variants():
                for asset in obj.get('assets', []):
                    has_asset = True
                    if "withChecksum" in asset or any(("withChecksum" in cond) for cond in asset.get('withConditions', [])):
                        has_checksum = True
                        self.packages_with_checksum.append((pkg, doc['group'], asset.get('assetId')))
            if is_dll and has_asset and not has_checksum:
                self.dlls_without_checksum.add(pkg)
            is_superseded = bool(self.superseded_pattern.search(summary))
            if is_superseded and has_asset and any(dep in summary for dep in doc.get('dependencies', [])):
                self.superseded_with_assets.add(pkg)

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


def create_validators(config, dependency_checker):

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
        if text is not None and not allow_ego_perspective and field != "summary" and DependencyChecker.pronouns_pattern.search(text):
            msgs.append(f"""The "{field}" should be written in a neutral perspective (avoid the words 'I', 'me', 'my').""")
        if text is not None and DependencyChecker.desc_invalid_chars_pattern.search(text):
            msgs.append(f"""The "{field}" seems to be malformed (avoid the characters '\\n', '\\"').""")
        if text is not None:
            for md_pkg_link in DependencyChecker.md_pkg_link_pattern.findall(text):
                if not md_pkg_link.startswith("`pkg="):
                    msgs.append(f"""The "{field}" contains a package hyperlink with incorrect syntax: {md_pkg_link} (use format `pkg=group:name` instead).""")
                else:
                    dependency_checker.referenced_packages.add(md_pkg_link[5:-1])
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


# Raise an error if a YAML file has duplicate keys, instead of silently ignoring it.
# See https://gist.github.com/pypt/94d747fe5180851196eb?permalink_comment_id=4653474#gistcomment-4653474
class UniqueKeyLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        mapping = set()
        for key_node, value_node in node.value:
            if ':merge' in key_node.tag:
                continue
            key = self.construct_object(key_node, deep=deep)
            if key in mapping:
                raise yaml.constructor.ConstructorError(f"Duplicate {key!r} key found in YAML")
            mapping.add(key)
        return super().construct_mapping(node, deep)
# # test cases
# import yaml
# yaml_data = r"""
# dependencies: []
# dependencies: []
# """
# yaml.load(yaml_data, Loader=UniqueKeyLoader)  # raises error
#
# yaml_data = r"""
# data:
#     1:
#         <<: &common
#             a: a
#             b: b
#         a: override
#     2:
#         <<: *common
#         b: override
# """
# yaml.load(yaml_data, Loader=UniqueKeyLoader) == {'data': {1: {'a': 'override', 'b': 'b'}, 2: {'a': 'a', 'b': 'override'}}}


def load_config(config_path):
    default_config = {
        'extra-channels': [],
        'subfolders': [],
        'ignore-version-mismatches': [],
        'allow-ego-perspective': False,
        'group-to-github': [],
        'ignore-non-github-urls': [],
        'lowercase-file-names': False,
        'global-variants': [],
        'single-choice-variants': [],
        'ignore-group-prefixes-in-name': True,
        'ignore-nonunique-includes': [],
    }
    try:
        with open(config_path, encoding='utf-8') as f:
            config = yaml.load(f, Loader=UniqueKeyLoader)  # yaml.safe_load(f)
            return {**default_config, **config}
    except FileNotFoundError:
        print(f"Configuration file {config_path} not found, so using default configuration.")
        return default_config
    except (yaml.parser.ParserError, yaml.constructor.ConstructorError) as err:
        raise ValueError(f"YAML error in {config_path}: {err}")


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
    dependency_checker = DependencyChecker(config=config)
    validated = 0
    errors = 0

    def validator_from_schema(schema):
        validator = jsonschema.validators.extend(
                jsonschema.validators.Draft202012Validator,
                validators=create_validators(config, dependency_checker),
            )(schema)
        validator.check_schema(schema)
        return validator
    package_validator, asset_validator, package_arr_validator = [validator_from_schema(s) for s in create_schema(config)]

    def basic_report(identifiers, msg: str, stringify=None):
        if identifiers:
            nonlocal errors
            errors += len(identifiers)
            print(f"===> {msg}")
            for identifier in identifiers:
                print(identifier if stringify is None else stringify(identifier))

    enforce_lowercase_filenames = config['lowercase-file-names']
    for src_dir in args:
        for (parent, dirs, files) in os.walk(src_dir):
            for fname in files:
                if not fname.endswith(".yaml"):
                    continue
                msgs = []
                p = os.path.join(parent, fname)
                if not (DependencyChecker.naming_convention_files_lowercase if
                        enforce_lowercase_filenames else
                        DependencyChecker.naming_convention_files
                        ).fullmatch(os.path.relpath(p, start=src_dir)):
                    msgs.append(f"""File name should not contain spaces{", uppercase letters" if enforce_lowercase_filenames else ""} or other special characters.""")
                with open(p, encoding='utf-8') as f:
                    validated += 1
                    text = f.read()
                    try:
                        validate_document_separators(text)
                        stanzas = {}  # stanza -> (pkg, variant)  # We only verify uniqueness of stanzas within a single yaml file to avoid storing the entire channel data in memory. Duplicate stanzas across more than one yaml file are less likely.
                        for doc in yaml.load_all(text, Loader=UniqueKeyLoader):  # yaml.safe_load_all(text):
                            if doc is None:  # empty yaml file or document
                                continue
                            if "group" in doc:
                                err = jsonschema.exceptions.best_match(package_validator.iter_errors(doc))
                            elif "url" in doc:
                                err = jsonschema.exceptions.best_match(asset_validator.iter_errors(doc))
                            elif "packages" in doc:
                                err = jsonschema.exceptions.best_match(package_arr_validator.iter_errors(doc))
                            else:
                                err = ValidationError("""document does not look like a package or asset (found neither "group" nor "url" nor "packages")""")
                            if err is not None:
                                msgs.append(err.message)
                            elif "packages" in doc:
                                for subDoc in doc.get("packages", []):
                                    dependency_checker.aggregate_identifiers(subDoc, stanzas)
                                for subDoc in doc.get("assets", []):
                                    dependency_checker.aggregate_identifiers(subDoc, stanzas)
                            else:
                                dependency_checker.aggregate_identifiers(doc, stanzas)
                    except (yaml.parser.ParserError, yaml.constructor.ConstructorError) as err:
                        msgs.append(str(err))
                if msgs:
                    errors += len(msgs)
                    print(f"::error file={p}::===> {p}")
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
        basic_report(dependency_checker.singular_variants, "",
                     lambda tup: """{0} defines a "{1}" variant with only a single choice: {2}""".format(*tup))  # pkg, variantId, values
        basic_report(dependency_checker.invalid_asset_names, "the following assetIds do not match the naming convention (lowercase alphanumeric hyphenated)")
        basic_report(dependency_checker.invalid_group_names, "the following group identifiers do not match the naming convention (lowercase alphanumeric hyphenated)")
        basic_report(dependency_checker.invalid_package_names, "the following package names do not match the naming convention (lowercase alphanumeric hyphenated)")
        basic_report(dependency_checker.invalid_variant_names, "the following variant labels or values do not match the naming convention (alphanumeric hyphenated or dots)")
        basic_report(sorted(set(dependency_checker.verbose_variant_names)), "",
                     lambda tup: "Naming issue: Avoid repeating the variant ID {0!r} in the variant's value name {1!r}.".format(*tup))
        basic_report(dependency_checker.invalid_group_prefixes_in_names, "The following package identifiers are of the form `group:group-name`. Prefer `group:name` instead. (Or edit `lint-config.yaml` to disable the check for specific packages.)")
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
        basic_report(dependency_checker.superseded_with_assets, "The following packages are superseded, so they usually should not reference an asset, but should only refer to the new dependency instead.")
        basic_report(dependency_checker.unknown_global_variants.items(), "",
                     lambda tup: f"""Variant IDs should use the package namespace by prefixing them with the package identifier, so replace "{tup[0]}" by "{tup[1]}:{str(tup[0]).lower()}" for example.""")
        basic_report(dependency_checker.duplicate_stanzas, "(If the following warnings cannot be resolved (using e.g. `withConditions` or by dropping redundant variants), then edit `lint-config.yaml` to add the packages to `ignore-nonunique-includes`.)",
                     lambda tup: (
                         "Two different variants of the package {0!r} seem to install the _same_ files, unintentionally. Consider removing them if they are the same.\n  {1}\n  vs\n  {3}"
                         if tup[0] == tup[2] else
                         "The packages {0!r} and {2!r} seem to install the _same_ files, unintentionally. Variants:\n  {1}\n  vs\n  {3}"
                         if tup[1] or tup[3] else
                         "The packages {0!r} and {2!r} seem to install the _same_ files, unintentionally."
                     ).format(*tup))

    if errors > 0:
        print(f"::error::Finished with {errors} errors.")
        return 1
    else:
        print(f"Successfully validated {validated} files.")
        return 0


if __name__ == '__main__':
    sys.exit(main())
