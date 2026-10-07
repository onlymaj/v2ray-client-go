#!/bin/sh
# Fails when the image tarball is larger than the limit (bytes).
set -eu
tar_file=$1
limit=$2
size=$(stat -c %s "$tar_file")
printf '%s: %d bytes (%.2f MiB), limit %.2f MiB\n' "$tar_file" "$size" \
  "$(echo "$size / 1048576" | bc -l)" "$(echo "$limit / 1048576" | bc -l)"
if [ "$size" -gt "$limit" ]; then
  echo "FAIL: image exceeds size limit" >&2
  exit 1
fi
