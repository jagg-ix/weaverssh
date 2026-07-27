#!/usr/bin/env python3
from __future__ import annotations

"""Generate distro-maintainer source recipes for a WeaverSSH source archive."""

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parents[2]
FAMILIES = ("debian", "redhat", "suse", "archlinux", "freebsd", "homebrew")


@dataclass(frozen=True)
class RecipePlan:
    schema: str
    version: str
    release: str
    source_url: str
    source_sha256: str
    source_size: int
    source_date_epoch: int
    output_dir: str
    families: list[str]


def clean_token(value: str, field: str) -> str:
    value = value.strip().lstrip("v") if field == "version" else value.strip()
    if not value or not re.fullmatch(r"[A-Za-z0-9._-]+", value):
        raise ValueError(f"invalid {field}: {value!r}")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_sha(value: str) -> str:
    value = value.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("source sha256 must be 64 lowercase hexadecimal characters")
    return value


def make_plan(
    version: str,
    release: str,
    source_url: str,
    source_sha256: str,
    source_archive: Path | None,
    output_dir: Path,
    families: list[str],
    source_size: int = 0,
    source_date_epoch: int | None = None,
) -> RecipePlan:
    version = clean_token(version, "version")
    release = clean_token(release, "release")
    if source_archive is not None:
        source_archive = source_archive.resolve()
        if not source_archive.is_file():
            raise FileNotFoundError(source_archive)
        source_sha256 = source_sha256 or sha256(source_archive)
        source_size = source_archive.stat().st_size
        source_url = source_url or source_archive.as_uri()
    parsed = urlparse(source_url)
    if parsed.scheme not in {"https", "http", "file"}:
        raise ValueError("source URL must use https, http, or file")
    source_sha256 = validate_sha(source_sha256)
    source_size = int(source_size)
    if source_size < 0:
        raise ValueError("source size must be non-negative")
    if source_date_epoch is None:
        source_date_epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0") or "0")
    if source_date_epoch < 0:
        raise ValueError("source date epoch must be non-negative")
    selected = families or list(FAMILIES)
    unknown = sorted(set(selected) - set(FAMILIES))
    if unknown:
        raise ValueError(f"unknown recipe families: {', '.join(unknown)}")
    return RecipePlan(
        schema="weaverssh.source-recipes.v1",
        version=version,
        release=release,
        source_url=source_url,
        source_sha256=source_sha256,
        source_size=source_size,
        source_date_epoch=source_date_epoch,
        output_dir=str(output_dir),
        families=selected,
    )


def write(path: Path, text: str, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")
    path.chmod(0o755 if executable else 0o644)


def debian_recipe(root: Path, plan: RecipePlan) -> None:
    debian = root / "debian"
    write(debian / "source" / "format", "3.0 (quilt)")
    write(
        debian / "control",
        """Source: weaverssh
Section: net
Priority: optional
Maintainer: WeaverSSH maintainers <noreply@example.invalid>
Build-Depends: debhelper-compat (= 13), golang-any (>= 1.24), make, ca-certificates
Standards-Version: 4.7.0
Homepage: https://github.com/jagg-ix/weaverssh
Rules-Requires-Root: no

Package: weaverssh
Architecture: any
Depends: ${shlibs:Depends}, ${misc:Depends}, ca-certificates, openssh-client, xauth, python3
Description: user-space data bus over SSH
 WeaverSSH provides routed filesystem, network, event, and policy-named
 execution services over an authenticated SSH session.
""",
    )
    date = datetime.fromtimestamp(plan.source_date_epoch, timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
    write(
        debian / "changelog",
        f"weaverssh ({plan.version}-{plan.release}) unstable; urgency=medium\n\n  * Source recipe generated from verified release archive.\n\n -- WeaverSSH maintainers <noreply@example.invalid>  {date}",
    )
    rules = """#!/usr/bin/make -f
%:
\tdh $@

override_dh_auto_build:
\tgo build -mod=vendor -trimpath -buildvcs=false -ldflags='-s -w' -o build/wv ./cmd/wv

override_dh_auto_install:
\tinstall -Dm755 build/wv debian/weaverssh/usr/bin/wv
"""
    write(debian / "rules", rules, executable=True)
    write(debian / "copyright", "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\nUpstream-Name: weaverssh\nSource: https://github.com/jagg-ix/weaverssh\nLicense: LicenseRef-WeaverSSH\n See the upstream repository for licensing terms.")


def rpm_recipe(root: Path, plan: RecipePlan, family: str) -> None:
    runtime = {
        "redhat": ("openssh-clients", "xorg-x11-xauth"),
        "suse": ("openssh", "xauth"),
    }[family]
    requires = "\n".join(f"Requires: {item}" for item in ("ca-certificates", *runtime, "python3"))
    spec = f"""Name: weaverssh
Version: {plan.version}
Release: {plan.release}%{{?dist}}
Summary: User-space data bus over SSH
License: LicenseRef-WeaverSSH
URL: https://github.com/jagg-ix/weaverssh
Source0: {plan.source_url}
BuildRequires: golang >= 1.24
BuildRequires: make
{requires}

%description
WeaverSSH provides routed filesystem, network, event, and policy-named execution
services over authenticated SSH sessions.

%prep
%autosetup -n weaverssh-%{{version}}

%build
export GOFLAGS=-mod=vendor
go build -trimpath -buildvcs=false -ldflags='-s -w' -o wv ./cmd/wv

%install
install -Dm755 wv %{{buildroot}}%{{_bindir}}/wv

%files
%{{_bindir}}/wv

%changelog
* Thu Jan 01 1970 WeaverSSH maintainers <noreply@example.invalid> - {plan.version}-{plan.release}
- Generated source-build recipe
"""
    write(root / family / "weaverssh.spec", spec)


def arch_recipe(root: Path, plan: RecipePlan) -> None:
    text = f"""pkgname=weaverssh
pkgver={plan.version}
pkgrel={plan.release}
pkgdesc='User-space data bus over SSH'
arch=('x86_64' 'aarch64' 'i686' 'armv7h')
url='https://github.com/jagg-ix/weaverssh'
license=('custom:LicenseRef-WeaverSSH')
depends=('ca-certificates' 'openssh' 'xorg-xauth' 'python')
makedepends=('go>=1.24' 'make')
source=('weaverssh-source::{plan.source_url}')
sha256sums=('{plan.source_sha256}')

build() {{
  cd "$srcdir/weaverssh-$pkgver"
  export GOFLAGS='-mod=vendor'
  go build -trimpath -buildvcs=false -ldflags='-s -w' -o wv ./cmd/wv
}}

package() {{
  cd "$srcdir/weaverssh-$pkgver"
  install -Dm755 wv "$pkgdir/usr/bin/wv"
}}
"""
    write(root / "archlinux" / "PKGBUILD", text)


def freebsd_recipe(root: Path, plan: RecipePlan) -> None:
    if plan.source_size <= 0:
        raise ValueError("FreeBSD recipe generation requires a local source archive or --source-size")
    filename = Path(urlparse(plan.source_url).path).name
    makefile = f"""PORTNAME=\tweaverssh
DISTVERSION=\t{plan.version}
CATEGORIES=\tnet
MASTER_SITES=\t{plan.source_url.rsplit('/', 1)[0]}/
DISTFILES=\t{filename}

MAINTAINER=\tnoreply@example.invalid
COMMENT=\tUser-space data bus over SSH
WWW=\t\thttps://github.com/jagg-ix/weaverssh

LICENSE=\tNONE
USES=\t\tgo:1.24,modules

PLIST_FILES=\tbin/wv

GO_BUILDFLAGS=\t-mod=vendor -trimpath -buildvcs=false -ldflags='-s -w'

do-build:
\tcd ${{WRKSRC}} && ${{SETENV}} ${{MAKE_ENV}} ${{GO_ENV}} ${{GO_CMD}} build ${{GO_BUILDFLAGS}} -o wv ./cmd/wv

do-install:
\t${{INSTALL_PROGRAM}} ${{WRKSRC}}/wv ${{STAGEDIR}}${{PREFIX}}/bin/wv

.include <bsd.port.mk>
"""
    write(root / "freebsd" / "Makefile", makefile)
    write(root / "freebsd" / "distinfo", f"TIMESTAMP = {plan.source_date_epoch}\nSHA256 ({filename}) = {plan.source_sha256}\nSIZE ({filename}) = {plan.source_size}")
    write(root / "freebsd" / "pkg-descr", "WeaverSSH is a user-space data bus over authenticated SSH sessions.\n\nWWW: https://github.com/jagg-ix/weaverssh")


def homebrew_recipe(root: Path, plan: RecipePlan) -> None:
    formula = f'''class Weaverssh < Formula
  desc "User-space data bus over SSH"
  homepage "https://github.com/jagg-ix/weaverssh"
  url "{plan.source_url}"
  sha256 "{plan.source_sha256}"
  version "{plan.version}"
  license :cannot_represent

  depends_on "go" => :build

  def install
    system "go", "build", "-mod=vendor", "-trimpath", "-buildvcs=false", "-ldflags=-s -w", "-o", bin/"wv", "./cmd/wv"
  end

  test do
    assert_match "weaverssh", shell_output("#{bin}/wv version")
  end
end
'''
    write(root / "homebrew" / "weaverssh.rb", formula)


def build(plan: RecipePlan) -> list[Path]:
    root = Path(plan.output_dir) / f"weaverssh-{plan.version}-{plan.release}"
    if root.exists():
        shutil.rmtree(root)
    builders = {
        "debian": lambda: debian_recipe(root, plan),
        "redhat": lambda: rpm_recipe(root, plan, "redhat"),
        "suse": lambda: rpm_recipe(root, plan, "suse"),
        "archlinux": lambda: arch_recipe(root, plan),
        "freebsd": lambda: freebsd_recipe(root, plan),
        "homebrew": lambda: homebrew_recipe(root, plan),
    }
    for family in plan.families:
        builders[family]()
    manifest = root / "RECIPE-MANIFEST.json"
    files = sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file())
    manifest.write_text(json.dumps({**asdict(plan), "files": files}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return [root / item for item in files] + [manifest]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "build"), nargs="?", default="plan")
    parser.add_argument("--version", default=os.environ.get("WEAVERSSH_VERSION", "0.1.0"))
    parser.add_argument("--release", default=os.environ.get("WEAVERSSH_RELEASE", "1"))
    parser.add_argument("--source-url", default="")
    parser.add_argument("--source-sha256", default="")
    parser.add_argument("--source-archive", type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, default=REPO_ROOT / "dist" / "source-recipes")
    parser.add_argument("--source-size", type=int, default=0)
    parser.add_argument("--source-date-epoch", type=int, default=None)
    parser.add_argument("--family", action="append", choices=FAMILIES, default=[])
    args = parser.parse_args()
    plan = make_plan(args.version, args.release, args.source_url, args.source_sha256, args.source_archive, args.output_dir, args.family, args.source_size, args.source_date_epoch)
    if args.command == "plan":
        print(json.dumps(asdict(plan), indent=2, sort_keys=True))
        return 0
    outputs = build(plan)
    print(json.dumps({"ok": True, "outputs": [str(path) for path in outputs]}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
