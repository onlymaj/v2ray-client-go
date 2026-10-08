#!/bin/sh
# Fails when the image tarball is larger than the limit (bytes).
set -eu
tar_file=$1
limit=$2
size=$(stat -c %s "$tar_file")
awk -v f="$tar_file" -v s="$size" -v l="$limit" \
  'BEGIN { printf "%s: %d bytes (%.2f MiB), limit %.2f MiB\n", f, s, s/1048576, l/1048576 }'
if [ "$size" -gt "$limit" ]; then
  echo "FAIL: image exceeds size limit" >&2
  exit 1
fi
