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
  pull_request_target:
    branches: [ "main" ]

jobs:
  channel:
    uses: memo33/sc4pac-actions/.github/workflows/sc4pac-channel.yaml@main
    with:
      path: src                      # path to yaml source files, e.g. src/yaml
      channel-label: Owner           # your name or other suitable label
      deploy-repository: OWNER/REPO  # your GitHub repository
      use-stex-api: false            # optionally enable the STEX API calls if you have a private key
      skip-test: true                # optionally skip the `test` step
    #secrets:
    #  stex-api-key: ${{ secrets.STEX_API_KEY }}  # set the STEX_API_KEY under: Settings > Secrets and variables > Actions > Repository secrets
    #  sc4pac-simtropolis-token: ${{ secrets.SC4PAC_SIMTROPOLIS_TOKEN }}  # set the SC4PAC_SIMTROPOLIS_TOKEN for downloading files during `test`
    permissions:
      pages: write                   # to deploy to GitHub Pages
      id-token: write                # to verify the deployment originates from an appropriate source
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
```
