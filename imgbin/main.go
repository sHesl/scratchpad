package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/containers/image/v5/copy"
	"github.com/containers/image/v5/signature"
	"github.com/containers/image/v5/transports/alltransports"
	"github.com/containers/image/v5/types"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opencontainers/umoci"
	"github.com/opencontainers/umoci/oci/cas/dir"
	"github.com/opencontainers/umoci/oci/casext"
	"github.com/opencontainers/umoci/oci/layer"
	"github.com/tidwall/gjson"
)

var (
	osys string
	arch string
)

func init() {
	flag.StringVar(&osys, "os", runtime.GOOS, "override running operating system")
	flag.StringVar(&arch, "arch", runtime.GOARCH, "override running system architecture")
	flag.Parse()
}

func main() {
	ctx := context.Background()

	// if len(os.Args) < 2 {
	// 	errOut(74, "no img arg specified")
	// }

	osys = "linux"
	arch = "amd64"
	img := "docker-daemon:bitnami/kubectl:1.20" // os.Args[1]
	srcRef, err := alltransports.ParseImageName(img)
	if err != nil {
		errOut(74, "invalid source name %s: %v", img, err)
	}

	tmpDir := os.TempDir() + string(img) // tmpDir is a symlink, linked to /private/var/**
	destRef, err := alltransports.ParseImageName("oci:" + tmpDir)
	if err != nil {
		errOut(1, "an error has occurred producing an oci image from %s: %v", img, err)
	}
	destOnDisk := destRef.PolicyConfigurationIdentity() // absolute, fully resolved temp dir path

	pol := &signature.Policy{Default: signature.PolicyRequirements{signature.NewPRInsecureAcceptAnything()}}
	pc, err := signature.NewPolicyContext(pol)
	if err != nil {
		panic(err)
	}

	i, err := srcRef.NewImage(ctx, &types.SystemContext{OSChoice: osys, ArchitectureChoice: arch})
	if err != nil {
		panic(err)
	}

	cfgBlob, err := i.ConfigBlob(ctx)
	if err != nil {
		panic(err)
	}

	target := []string{}
	if r := gjson.GetBytes(cfgBlob, "config.Entrypoint"); r.Exists() {
		for _, p := range r.Array() {
			target = append(target, p.String())
		}
	}

	if len(target) == 0 {
		if r := gjson.GetBytes(cfgBlob, "config.Cmd"); r.Exists() {
			for _, p := range r.Array() {
				target = append(target, p.String())
			}
		}
	}

	entry := target[0]

	paths := []string{}
	if !strings.HasPrefix(entry, "/") {
		env := []string{}
		if r := gjson.GetBytes(cfgBlob, "config.Env"); r.Exists() {
			for _, p := range r.Array() {
				env = append(env, p.String())
			}
		}

		for _, p := range env {
			if len(p) < 5 || p[:5] != "PATH=" {
				continue
			}
			paths = append(paths, strings.Split(p[5:], string(os.PathListSeparator))...)
		}

		for i := range paths {
			paths[i] += "/" + entry
		}
	}

	if _, err := copy.Image(ctx, pc, destRef, srcRef, &copy.Options{}); err != nil {
		panic(err)
	}

	engine, err := dir.Open(destOnDisk)
	if err != nil {
		panic(err)
	}
	engineExt := casext.NewEngine(engine)
	defer engine.Close()

	opts := layer.UnpackOptions{MapOptions: layer.MapOptions{
		UIDMappings: []specs.LinuxIDMapping{{ContainerID: 0, HostID: uint32(os.Getuid()), Size: 1}},
		GIDMappings: []specs.LinuxIDMapping{{ContainerID: 0, HostID: uint32(os.Getgid()), Size: 1}},
		Rootless:    true,
	}}

	unpackDir := destOnDisk + "/unpacked"
	os.Mkdir(unpackDir, os.ModePerm)
	if err := umoci.Unpack(engineExt, "bitnami/kubectl:1.20", unpackDir, opts); err != nil {
		panic(err)
	}

	for _, path := range paths {
		f, err := os.ReadFile(unpackDir + "/rootfs" + path)
		if err != nil {
			continue
		}

		digest := sha256.Sum256(f)
		digestB64 := hex.EncodeToString(digest[:])
		fmt.Printf("%s = %s", path, digestB64)
	}

	// will also remove unpackDir
	if err := os.RemoveAll(destOnDisk); err != nil {
		panic(err)
	}
}

func errOut(code int, errStr string, a ...interface{}) {
	os.Stdout.WriteString("imgbin: " + fmt.Sprintf(errStr, a...))
	os.Exit(code)
}
