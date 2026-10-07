// Command mkimage writes a single-layer `docker save` tarball for a scratch
// image without needing Docker. RouterOS imports it with
// `/container add file=<tar>`.
//
// Usage:
//
//	mkimage -out image.tar -tag v2ray-client-go:latest -arch arm64 \
//	  -file dist/v2ray-client-go:/v2ray-client-go:0755 -dir /data \
//	  -entrypoint /v2ray-client-go -env GOMEMLIMIT=32MiB
package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

// Fixed timestamp so identical inputs give identical tarballs.
var epoch = time.Unix(0, 0).UTC()

func main() {
	var files, dirs, envs, entry multi
	out := flag.String("out", "image.tar", "output tarball")
	tag := flag.String("tag", "", "repo:tag")
	arch := flag.String("arch", "arm64", "image architecture")
	flag.Var(&files, "file", "src:dst:mode (repeatable)")
	flag.Var(&dirs, "dir", "empty directory to create (repeatable)")
	flag.Var(&envs, "env", "KEY=VALUE (repeatable)")
	flag.Var(&entry, "entrypoint", "entrypoint argv element (repeatable)")
	flag.Parse()
	if *tag == "" || len(entry) == 0 {
		log.Fatal("-tag and -entrypoint are required")
	}

	layer, err := buildLayer(files, dirs)
	if err != nil {
		log.Fatal(err)
	}
	layerSum := sha256.Sum256(layer)
	layerID := hex.EncodeToString(layerSum[:])

	config, _ := json.Marshal(map[string]any{
		"architecture": *arch,
		"os":           "linux",
		"created":      epoch.Format(time.RFC3339),
		"config": map[string]any{
			"Entrypoint": []string(entry),
			"Env":        []string(envs),
			"WorkingDir": "/",
		},
		"rootfs":  map[string]any{"type": "layers", "diff_ids": []string{"sha256:" + layerID}},
		"history": []map[string]string{{"created": epoch.Format(time.RFC3339), "created_by": "mkimage"}},
	})
	configSum := sha256.Sum256(config)
	configName := hex.EncodeToString(configSum[:]) + ".json"

	repo, ver, _ := strings.Cut(*tag, ":")
	if ver == "" {
		ver = "latest"
	}
	manifest, _ := json.Marshal([]map[string]any{{
		"Config":   configName,
		"RepoTags": []string{repo + ":" + ver},
		"Layers":   []string{layerID + "/layer.tar"},
	}})
	repositories, _ := json.Marshal(map[string]map[string]string{repo: {ver: layerID}})
	legacyJSON, _ := json.Marshal(map[string]any{"id": layerID, "created": epoch.Format(time.RFC3339), "os": "linux", "architecture": *arch})

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	add := func(name string, mode int64, data []byte) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(data)), ModTime: epoch, Typeflag: tar.TypeReg}); err != nil {
			log.Fatal(err)
		}
		tw.Write(data)
	}
	if err := tw.WriteHeader(&tar.Header{Name: layerID + "/", Mode: 0o755, ModTime: epoch, Typeflag: tar.TypeDir}); err != nil {
		log.Fatal(err)
	}
	add(layerID+"/VERSION", 0o644, []byte("1.0"))
	add(layerID+"/json", 0o644, legacyJSON)
	add(layerID+"/layer.tar", 0o644, layer)
	add(configName, 0o644, config)
	add("manifest.json", 0o644, manifest)
	add("repositories", 0o644, repositories)
	if err := tw.Close(); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, buf.Bytes(), 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s: %d bytes (layer %d bytes)\n", *out, buf.Len(), len(layer))
}

func buildLayer(files, dirs []string) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, d := range dirs {
		name := strings.Trim(d, "/") + "/"
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, ModTime: epoch, Typeflag: tar.TypeDir}); err != nil {
			return nil, err
		}
	}
	for _, f := range files {
		parts := strings.Split(f, ":")
		if len(parts) != 3 {
			return nil, fmt.Errorf("bad -file %q, want src:dst:mode", f)
		}
		data, err := os.ReadFile(parts[0])
		if err != nil {
			return nil, err
		}
		mode, err := strconv.ParseInt(parts[2], 8, 64)
		if err != nil {
			return nil, fmt.Errorf("bad mode in %q: %w", f, err)
		}
		hdr := &tar.Header{Name: strings.TrimPrefix(parts[1], "/"), Mode: mode, Size: int64(len(data)), ModTime: epoch, Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
