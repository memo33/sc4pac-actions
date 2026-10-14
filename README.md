# sc4pac-actions

GitHub actions and reusable workflows for building a metadata channel for [sc4pac](https://github.com/memo33/sc4pac-tools).

These are used to build the [Main channel](https://github.com/memo33/sc4pac) as well as other supplementary channels.

## Configuration

Create a file `.github/workflows/sc4pac.yaml` in your repository:
```yaml
name: sc4pac CI

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

jobs:
  channel:
    uses: memo33/sc4pac-actions/.github/workflows/sc4pac-channel.yaml@v2
    with:
      path: src                      # path to yaml source files, e.g. src/yaml
      channel-label: Owner           # your name or other suitable label
      deploy-repository: OWNER/REPO  # your GitHub repository
      skip-test: false               # optionally skip the test job
      skip-url-check: false          # optionally skip the url-check
      skip-deploy: false             # optionally skip deployment
    permissions:
      pages: write                   # to deploy to GitHub Pages
      id-token: write                # to verify the deployment originates from an appropriate source
      checks: write                  # to create placeholder checks for the subsequent sc4pac-test workflow
```
(For more detailed input and output arguments, see `.github/workflows/sc4pac-channel.yaml`.)

Additionally, unless `skip-test` and `skip-url-check` are true, create a second workflow `.github/workflows/sc4pac-test.yaml` in your repository:
```yaml
name: sc4pac-test

on:
  workflow_run:
    workflows: ["sc4pac CI"]
    types:
      - completed

jobs:
  channel-proxy:
    uses: memo33/sc4pac-actions/.github/workflows/sc4pac-privileged.yaml@v2
    with:
      workflow-run-id: ${{ github.event.workflow_run.id }}
      skip-test: false               # optionally skip the test job
      skip-url-check: false          # optionally skip the url-check
    #secrets:
    #  # The secrets are needed if the channel contains STEX files.
    #  # Configure them under: Settings > Secrets and variables > Actions > Repository secrets.
    #  # The `SC4PAC_SIMTROPOLIS_TOKEN` is used by `test`, the `STEX_API_KEY` by `url-check`.
    #  sc4pac-simtropolis-token: ${{ secrets.SC4PAC_SIMTROPOLIS_TOKEN }}
    #  stex-api-key: ${{ secrets.STEX_API_KEY }}
    permissions:
      contents: read                 # to access previous workflow run
      checks: write                  # to show the test results on the original commit
```

Also create a `lint-config.yaml` in the top-level directory of your repository:
```yaml
# Additional channel URLs the packages in your channel depend on (default: [])
extra-channels:
- https://memo33.github.io/sc4pac/channel/

# Additional subfolders (if not already used by the Main channel)
subfolders: []

# Package names for which the check for asset version mismatches should be skipped.
# Only needed when the linter tells you so.
ignore-version-mismatches: []

# Set this to true to allow writing descriptions from a first-person perspective.
allow-ego-perspective: false

# Set this to true to enforce lowercase file names:
lowercase-file-names: false

# For downloading DLLs from GitHub, define a mapping between groups and GH accounts.
# group-to-github:
# - null-45: "0xC0000054"
# - simmaster07: nsgomez

# Additional global variant IDs that are not used by the Main channel
global-variants: []

# Variant IDs which intentionally have just a single choice
single-choice-variants: []

# Set this to false to guard against package identifiers of the form `group:group-name`, but prefer `group:name` instead.
ignore-group-prefixes-in-name: true
# Or add an explicit list of packages for which the check is skipped. This implies false for all other packages.
# ignore-group-prefixes-in-name: []

# Some checks detect e.g. if two variants of a package unintentionally install the same files (i.e. the include patterns of the two variants are not unique).
# In case of unresolvable false positives, add their package names here.
ignore-nonunique-includes: []
```

To run the linter locally, clone this repository and run the linter from the root of the metadata repository.
For example:
```sh
python ../sc4pac-actions/src/lint.py src/yaml
```

## Auto-update workflow

Optionally, add another workflow `.github/workflows/auto-update.yaml` which automatically creates pull requests to update version numbers:
```yaml
name: auto-update

on:
  #schedule:  # uncomment and adjust for periodic runs (stops after 2 months of inactivity)
  #  - cron: '15 16 * * 0'  # 4:15 pm UTC on Sundays
  workflow_dispatch:  # trigger the workflow manually from the Actions tab

jobs:
  auto-update:
    uses: memo33/sc4pac-actions/.github/workflows/sc4pac-channel-updates.yaml@v2
    with:
      path: src/yaml
      api: sc4e  # sc4e,stex
      deploy-repository: OWNER/REPO  # your GitHub repository
    secrets:
      stex-api-key: ${{ secrets.STEX_API_KEY }}  # remove this unless using the stex api
      pat: ${{ secrets.SC4PAC_CHECK_UPDATES_TOKEN }}
    permissions:
      pull-requests: write
```
The personal access token `SC4PAC_CHECK_UPDATES_TOKEN` must be created for your profile under *Settings* → *Developer Settings* → *Personal Access Tokens* → *Fine-grained tokens* with correct permissions (Contents, Pull Requests).
Afterwards, add the token to the repository: *Settings* → *Secrets and Variables* → *Actions* → *Repository secrets*.
