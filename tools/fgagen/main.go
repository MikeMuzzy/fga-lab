// Command authzgen generates the authorization catalog from the model DSL, so
// code and policy cannot disagree within a commit.
//
// It emits four catalogs:
//
//   - Permissions: checkable relations (can_*), used to build Checks.
//   - Roles: assignable relations, the only ones a grant may reference.
//   - Conditions: CEL conditions, with parameters split into the values frozen
//     at write time and the values supplied per Check.
//   - Grants: one constructor per type restriction, so a tuple cannot be
//     written with a condition the model does not require for that edge.
//
// The write/check split is declared in the DSL with directives above each
// condition, which the OpenFGA lexer discards but authzgen reads from source:
//
//	# fga:write allowed_pattern
//	# fga:check requested_path
//	condition path_match(allowed_pattern: string, requested_path: string) {
//	  requested_path.startsWith(allowed_pattern)
//	}
//
// Every parameter must be classified exactly once; unclassified or unknown
// parameters fail generation.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"example.com/authz/internal/authzgen"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("authzgen: ")
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	var (
		in     = flag.String("in", "model.fga", "path to the model DSL")
		out    = flag.String("out", "catalog.go", "path to the generated catalog")
		pkg    = flag.String("package", "authz", "package name of the generated file")
		prefix = flag.String("permission-prefix", authzgen.DefaultPermissionPrefix,
			"relation prefix marking checkable permissions")
		verify = flag.Bool("verify", false,
			"exit non-zero if the file on disk differs from the generated output")
	)
	flag.Parse()

	src, err := os.ReadFile(*in)
	if err != nil {
		return err
	}

	got, err := authzgen.Generate(*in, src, authzgen.Options{
		Package:          *pkg,
		PermissionPrefix: *prefix,
	})
	if err != nil {
		return err
	}

	if *verify {
		want, err := os.ReadFile(*out)
		if err != nil {
			return fmt.Errorf("verify: %w", err)
		}
		if !bytes.Equal(got, want) {
			return fmt.Errorf("%s is stale; re-run go generate", *out)
		}
		return nil
	}

	if err := writeFile(*out, got); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "authzgen: %s -> %s\n", *in, *out)
	return nil
}

// writeFile replaces path atomically, so an interrupted run cannot leave a
// half-written file that still compiles.
func writeFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(name)
	}()

	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o644); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return errors.Join(err, os.Remove(name))
	}
	return nil
}
