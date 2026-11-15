# Install

leakscan needs Python 3.10 or newer, or you can use the Docker image or a standalone binary.

| Method | Command |
|---|---|
| pipx (recommended) | `pipx install leakscan` |
| uv | `uv tool install leakscan` or run once with `uvx leakscan scan .` |
| pip | `pip install leakscan` |
| Homebrew | `brew install vasishta03/leakscan/leakscan` |
| Docker | `docker run --rm -v "$PWD:/src" ghcr.io/vasishta03/leakscan scan .` |
| Binary | Download `leakscan-linux-x86_64`, `leakscan-macos-arm64` or `leakscan-windows-x86_64.exe` from [Releases](https://github.com/Vasishta03/leakscan/releases) |
| Script | `curl -fsSL https://raw.githubusercontent.com/Vasishta03/leakscan/main/install.sh \| sh` |
| Nix | `nix run github:Vasishta03/leakscan -- scan .` |
| Scoop | `scoop bucket add leakscan https://github.com/Vasishta03/leakscan` then `scoop install leakscan` |

Arch Linux (AUR), conda-forge and winget recipes are kept in
[`packaging/`](https://github.com/Vasishta03/leakscan/tree/main/packaging) until they're accepted upstream.

## Verify a release

Every release is built in GitHub Actions and comes with build provenance, Sigstore signatures and an SBOM.

```bash
gh attestation verify leakscan-0.5.0-py3-none-any.whl --repo Vasishta03/leakscan
```

## Shell completion

```bash
leakscan completion bash > ~/.local/share/bash-completion/completions/leakscan
leakscan completion zsh  > "${fpath[1]}/_leakscan"
leakscan completion fish > ~/.config/fish/completions/leakscan.fish
```

A man page (`leakscan.1`) is attached to each GitHub release.
