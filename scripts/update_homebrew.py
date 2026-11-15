"""Regenerate the Homebrew formula for a released version.

usage: python scripts/update_homebrew.py 0.5.0 path/to/Formula/leakscan.rb

Installs leakscan==VERSION into a throwaway venv to get the exact dependency
set, then pins every dependency's sdist URL and sha256 from PyPI.
"""
import json
import subprocess
import sys
import tempfile
import urllib.request
import venv
from pathlib import Path

version, out = sys.argv[1], Path(sys.argv[2])


def pypi(name: str, ver: str) -> dict:
    with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{ver}/json", timeout=30) as r:
        data = json.load(r)
    sdist = next(u for u in data["urls"] if u["packagetype"] == "sdist")
    return {"url": sdist["url"], "sha256": sdist["digests"]["sha256"]}


with tempfile.TemporaryDirectory() as d:
    venv.create(d, with_pip=True)
    py = str(Path(d) / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python"))
    subprocess.run([py, "-m", "pip", "install", "--quiet", f"leakscan=={version}"], check=True)
    frozen = subprocess.run([py, "-m", "pip", "freeze"], check=True, capture_output=True, text=True).stdout

deps = sorted((line.split("==") for line in frozen.splitlines() if "==" in line and not line.lower().startswith("leakscan")),
              key=lambda x: x[0].lower())
main = pypi("leakscan", version)
resources = "\n".join(
    f'  resource "{name.lower()}" do\n    url "{info["url"]}"\n    sha256 "{info["sha256"]}"\n  end\n'
    for name, ver in deps for info in [pypi(name, ver)]
)
out.write_text(f'''class Leakscan < Formula
  include Language::Python::Virtualenv

  desc "Find leaked API keys and secrets in code, git history, images and packages"
  homepage "https://github.com/Vasishta03/leakscan"
  url "{main['url']}"
  sha256 "{main['sha256']}"
  license "MIT"

  depends_on "python@3.12"

{resources}
  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match version.to_s, shell_output("#{{bin}}/leakscan --version")
    (testpath/"leak.py").write "key = 'sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc" + "'"
    assert_match "LS-STRIPE-001", shell_output("#{{bin}}/leakscan scan #{{testpath}}/leak.py --format json --no-progress", 1)
  end
end
''', encoding="utf-8")
print(f"wrote {out} for leakscan {version} with {len(deps)} resources")
