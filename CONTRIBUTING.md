# Contributing

Thanks for helping improve `sha256mb`. This guide covers the local workflow and
the checks that must pass before a change is merged.

## Prerequisites

- Go 1.22 or newer.
- `staticcheck` for linting:
  `go install honnef.co/go/tools/cmd/staticcheck@2024.1.1`.

## Everyday checks

Run these before opening a pull request:

```sh
gofmt -l .                              # must print nothing
go vet ./...
staticcheck ./...

go test ./...                           # native backend
GOSHA256MB_FORCE=scalar go test ./...   # scalar oracle
go test -race ./...                     # race detector
```

On arm64, also exercise the forced kernels so the SIMD and fused paths are
covered, not just whichever happens to be the default:

```sh
GOSHA256MB_FORCE=sha2x4   go test ./...
GOHASH160MB_FORCE=staged  go test ./hash160mb
GOHASH160MB_FORCE=fused   go test ./hash160mb
```

## Coverage

The importable library packages (root and `hash160mb`) are held to an 85%
statement-coverage floor:

```sh
go test -covermode=atomic -coverprofile=coverage.out ./ ./hash160mb
go tool cover -func=coverage.out | tail -1
go tool cover -html=coverage.out          # find uncovered lines
```

The floor is 85% rather than 100% because each architecture's vector kernel is
build-excluded on the other (so the amd64 CI coverage run cannot execute the
arm64 `sha2x4` / fused code), and the non-default forced kernels are exercised by
the test job rather than this single coverage run. The assembly generators
(`internal/shagen`, `hash160mb/internal/fusedgen`) are excluded from the gate;
they are validated by `go vet`, the cross-build job, and the `go generate`
clean-tree check instead.

## Fuzzing

Every fast path is differentially fuzzed against the standard-library oracles
(`crypto/sha256`, and `golang.org/x/crypto/ripemd160` for HASH160):

```sh
go test -run '^$' -fuzz '^FuzzHash33$'        -fuzztime=30s .
go test -run '^$' -fuzz '^FuzzFromPubkeys33$' -fuzztime=30s ./hash160mb
```

If fuzzing finds a failure it writes a reproducer under `testdata/fuzz/`. Commit
that file with your fix so the case becomes a permanent regression test.

## Benchmarks

See [PERFORMANCE.md](PERFORMANCE.md) for the full methodology. In short:

```sh
go test -run '^$' -bench '^BenchmarkHash33$' -benchmem ./
go test -run '^$' -bench '^BenchmarkFromPubkeys33$' -benchmem ./hash160mb
```

Validate performance claims with `benchstat`, not single runs, and measure A/B
pairs back-to-back on a quiet machine.

## Generated assembly — do not hand-edit

The arm64 kernels are generated:

- `block_arm64.s` (multi-buffer SHA-256) from [`internal/shagen/`](internal/shagen).
- `hash160mb/block_arm64.s` (fused HASH160) from
  [`hash160mb/internal/fusedgen/`](hash160mb/internal/fusedgen).

The `go:generate` directives live in [`generate.go`](generate.go) and
[`hash160mb/generate.go`](hash160mb/generate.go). Regenerate with:

```sh
go generate ./...
```

Do not edit `block_arm64.s` by hand — change the generator and rerun
`go generate`. CI runs `go generate ./...` followed by `git diff --exit-code`,
so any drift between a generator and its committed output fails the build.

Any new vector kernel (for example an amd64 AVX-512 / SHA-NI backend) must be
verified bit-for-bit against the scalar oracle by the differential and fuzz
tests before it is wired into dispatch. A backend must never report a SIMD name
via `Backend()` while actually running the scalar fallback.

## Pull request checklist

- [ ] `gofmt`, `go vet`, and `staticcheck` are clean.
- [ ] `go test ./...`, the forced-scalar run, and `go test -race ./...` pass.
- [ ] On arm64, the forced `sha2x4`, `staged`, and `fused` runs pass.
- [ ] `go generate ./...` produces no diff.
- [ ] New behavior has tests; new fast-path behavior is also fuzzed.
- [ ] Performance claims are backed by `benchstat` output.
- [ ] User-facing changes update the relevant docs and `CHANGELOG.md`.
