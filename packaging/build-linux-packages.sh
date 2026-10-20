#!/usr/bin/env bash
# Package already qualified binaries. Never start a service while packaging.
set -euo pipefail
dist=$(realpath "${1:?release payload directory}")
version=${2#v}
out=$(realpath -m "${3:?output directory}")
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'stable numeric version required' >&2; exit 2; }
root=$(cd "$(dirname "$0")/.." && pwd)
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$root" show -s --format=%ct HEAD)}
work=$(mktemp -d "${TMPDIR:-/tmp}/heraclitus-packages.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$out" "$work/payload/usr/bin" "$work/payload/usr/lib/systemd/system" \
  "$work/payload/usr/share/doc/heraclitusdb" "$work/payload/etc/heraclitusdb" "$work/debian"
for binary in heraclitus-server heraclitus-qualifier; do
  install -m 0755 "$dist/bin/$binary" "$work/payload/usr/bin/$binary"
done
install -m 0644 "$root/packaging/systemd/heraclitusdb.service" "$work/payload/usr/lib/systemd/system/"
install -m 0644 "$root/packaging/heraclitus.toml" "$work/payload/etc/heraclitusdb/"
install -m 0644 "$root/LICENSE" "$work/payload/usr/share/doc/heraclitusdb/copyright"
install -m 0644 "$dist/RELEASE_NOTES.md" "$dist/build-manifest.json" "$work/payload/usr/share/doc/heraclitusdb/"
install -m 0644 "$root/packaging/README.md" "$work/payload/usr/share/doc/heraclitusdb/"
cat > "$work/debian/control" <<EOF
Source: heraclitusdb
Section: database
Priority: optional
Maintainer: HeraclitusDB contributors <noreply@github.com>

Package: heraclitusdb
Architecture: amd64
Description: Append-only temporal event database
EOF
dependencies=$(cd "$work" && dpkg-shlibdeps --ignore-missing-info -O \
  -e"$work/payload/usr/bin/heraclitus-server" -e"$work/payload/usr/bin/heraclitus-qualifier" | sed -n 's/^shlibs:Depends=//p')
test -n "$dependencies"
mkdir -p "$work/payload/DEBIAN"
cat > "$work/payload/DEBIAN/control" <<EOF
Package: heraclitusdb
Version: $version
Section: database
Priority: optional
Architecture: amd64
Maintainer: HeraclitusDB contributors <noreply@github.com>
Depends: $dependencies, passwd
Homepage: https://github.com/JoseRFJuniorLLMs/HeraclitusDB
Description: Append-only temporal event database
 Event-sourced database with historical queries and cryptographic evidence.
 Service installation is stopped by default; configure authentication before use.
EOF
echo /etc/heraclitusdb/heraclitus.toml > "$work/payload/DEBIAN/conffiles"
cat > "$work/payload/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = configure ]; then
  getent group heraclitus >/dev/null || groupadd --system heraclitus
  getent passwd heraclitus >/dev/null || useradd --system --gid heraclitus --home-dir /var/lib/heraclitusdb --shell /usr/sbin/nologin heraclitus
  if command -v systemctl >/dev/null; then systemctl daemon-reload || true; fi
fi
EOF
chmod 0755 "$work/payload/DEBIAN/postinst"
find "$work/payload" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
dpkg-deb --root-owner-group --build "$work/payload" "$out/heraclitusdb_${version}_amd64.deb"
# DEBIAN is metadata for dpkg, never a file in the RPM filesystem payload.
rm -r -- "$work/payload/DEBIAN"
mkdir -p "$work/rpm/BUILD" "$work/rpm/BUILDROOT" "$work/rpm/RPMS" "$work/rpm/SOURCES" "$work/rpm/SPECS" "$work/rpm/SRPMS"
cat > "$work/rpm/SPECS/heraclitusdb.spec" <<EOF
%global debug_package %{nil}
%global __os_install_post %{nil}
%global _build_id_links none
Name: heraclitusdb
Version: $version
Release: 1
Summary: Append-only temporal event database
License: GPL-2.0-only
URL: https://github.com/JoseRFJuniorLLMs/HeraclitusDB
BuildArch: x86_64
Requires(pre): shadow-utils
%description
Event-sourced database with historical queries and cryptographic evidence.
Service installation is stopped by default; configure authentication before use.
%install
mkdir -p %{buildroot}
cp -a "$work/payload/." %{buildroot}/
%pre
getent group heraclitus >/dev/null || groupadd --system heraclitus
getent passwd heraclitus >/dev/null || useradd --system --gid heraclitus --home-dir /var/lib/heraclitusdb --shell /usr/sbin/nologin heraclitus
%post
if command -v systemctl >/dev/null; then systemctl daemon-reload || :; fi
%files
%defattr(-,root,root,-)
/usr/bin/heraclitus-server
/usr/bin/heraclitus-qualifier
/usr/lib/systemd/system/heraclitusdb.service
%dir /etc/heraclitusdb
%config(noreplace) /etc/heraclitusdb/heraclitus.toml
%doc /usr/share/doc/heraclitusdb
EOF
rpmbuild -bb --define "_topdir $work/rpm" --define '_buildhost reproducible' \
  --define 'use_source_date_epoch_as_buildtime 1' --define 'clamp_mtime_to_source_date_epoch 1' \
  "$work/rpm/SPECS/heraclitusdb.spec"
cp "$work/rpm/RPMS/x86_64/heraclitusdb-$version-1.x86_64.rpm" "$out/"
(cd "$out" && sha256sum -- *.deb *.rpm > SHA256SUMS)
