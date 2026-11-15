# Packaging

Recipes for package managers that need a submission outside this repo. Each one is updated per release
(the checksums come from the published PyPI sdist and GitHub release assets).

| Channel | File | How it ships |
|---|---|---|
| Homebrew | [homebrew-leakscan](https://github.com/Vasishta03/homebrew-leakscan) | Tap, updated by the release workflow (`scripts/update_homebrew.py`) |
| Scoop | [`bucket/leakscan.json`](../bucket/leakscan.json) | This repo is the bucket: `scoop bucket add leakscan https://github.com/Vasishta03/leakscan` |
| Nix | [`flake.nix`](../flake.nix) | `nix run github:Vasishta03/leakscan` |
| AUR | `aur/PKGBUILD` | Push to `ssh://aur@aur.archlinux.org/python-leakscan.git` |
| conda-forge | `conda-forge/meta.yaml` | PR to `conda-forge/staged-recipes` |
| winget | `winget/` | PR to `microsoft/winget-pkgs` under `manifests/v/Vasishta03/leakscan/<version>/` |
