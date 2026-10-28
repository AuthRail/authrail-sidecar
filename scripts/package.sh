#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  printf 'usage: package.sh VERSION OUTPUT_DIRECTORY\n' >&2
  exit 2
fi
version=$1
output=$2
case "$version" in
  *[!A-Za-z0-9._-]*|'') printf 'version must be a safe label\n' >&2; exit 2 ;;
esac

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
platform_os=$(go env GOOS)
platform_arch=$(go env GOARCH)
name="authrail-sidecar-${version}-${platform_os}-${platform_arch}"
mkdir -p "$output"
mkdir "$output/$name"

(cd "$repository" && go build -trimpath -o "$output/$name/authrail-sidecar" ./cmd/authrail-sidecar)
cp "$repository/README.md" "$repository/PROTOCOL.md" "$repository/COMPATIBILITY.md" \
  "$repository/LICENSE" "$output/$name/"
cp -R "$repository/conformance" "$output/$name/"
mkdir "$output/$name/docker"
cp "$repository/docker/README.md" "$output/$name/docker/README.md"
mkdir -p "$output/$name/integrations/openshell"
for guide_asset in README.md executor.mjs containment.mjs start.mjs example-config.mjs \
  operator-settings.example.json package.json package-lock.json policy.yaml; do
  cp "$repository/integrations/openshell/$guide_asset" "$output/$name/integrations/openshell/$guide_asset"
done
printf '{"version":"%s","os":"%s","arch":"%s","bundleFormat":1,"localProtocolFormat":1,"stateFormat":1}\n' \
  "$version" "$platform_os" "$platform_arch" > "$output/$name/manifest.json"
(cd "$output" && tar -czf "$name.tar.gz" "$name")
(cd "$output" && shasum -a 256 "$name.tar.gz" > "$name.tar.gz.sha256")
printf '%s\n' "$output/$name.tar.gz"
