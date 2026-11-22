# Complete reanalysis dataset: boundary-r1

This dataset permits a third party to rerun the memory-to-TLS-to-CGO analysis
on the same acquired evidence used for the acquisition-boundary experiment. It
contains no third-party Tor traffic. The client, relays, destination, payload,
and keys were generated inside an isolated Chutney network for this experiment.

Unlike the earlier hash-only results, this dataset intentionally contains the
controlled core dump and PCAP. Consequently, it also contains throwaway TLS and
CGO secrets for this synthetic network. It must not be treated as a template
for publishing evidence acquired from a real endpoint.

## Contents

- `client.core.zst`: ELF core captured at the entry to
  `append_cell_to_circuit_queue`, after forward CGO processing and before the
  processed cell was inserted into the circuit queue.
- `entry-link.pcap.zst`: loopback capture of the isolated client--entry link.
- `tor-0.4.9.16-o2-arm64.zst`: the matching unstripped Linux arm64 ELF with
  DWARF. Its Build ID is
  `aa72f972c0bd8dabcfb349a62a4ae7dea0059fd6`.
- `tor-0.4.9.16-source.tar.zst`: corresponding C Tor source at commit
  `c51547ca15ea665950dd154e160051c57f5719db` (`tor-0.4.9.16`). The archive
  includes Tor's license notices and corresponding source for the distributed
  binary.
- `metadata/`: acquisition conditions, controlled circuit identifiers,
  stream-to-circuit attachments, traffic-generator result, GDB acquisition log,
  and the build configuration log.

The uncompressed SHA-256 values of the primary evidence are:

```text
e6dfdb26f755fb10c91b747a08712f40c25e074d3feead91c577030fcaf8c271  client.core
4ab715f3b6a328617047091c8901d40bebefeaaf47ad94f29bdc9fe0ed3b3a0d  entry-link.pcap
c725f66cc5c5089cf288820bc06ca1a748951094ec4f6127d0d73cf19c41b11f  tor-0.4.9.16-o2-arm64
```

## Verification and extraction

From this directory:

```sh
shasum -a 256 -c SHA256SUMS
zstd -d client.core.zst -o /tmp/cgo-boundary-r1.core
zstd -d entry-link.pcap.zst -o /tmp/cgo-boundary-r1.pcap
zstd -d tor-0.4.9.16-o2-arm64.zst -o /tmp/cgo-boundary-r1-tor
chmod +x /tmp/cgo-boundary-r1-tor
```

The repository's `forensics/verify_core_executable.py`, `forensics/gdb_scan.py`,
CGO/TLS extractors, `experiments/decrypt_tls13_sequence.py`, and CGO replay
tools accept these files without Control Protocol ground truth. The files in
`metadata/` are for post-hoc evaluation and must not be used to select a
circuit, TLS record, cell, or hop.

For a complete rerun, first build the repository's Docker image as
`tor-cgo-forensics:bookworm`, then run from the repository root:

```sh
experiments/reanalyze_boundary_dataset.sh
```

The script uses a new `/tmp/tor-cgo-boundary-reanalysis` directory and refuses
to overwrite an existing directory. Its final `correspondence.json` and
`summary.json` contain no plaintext or raw secret values.

The expected result is one stale captured candidate followed by one unique
CGO-authenticated anchor at sequence index 1. Starting at that anchor, all 929
available cells authenticate sequentially. These public expected values are
evaluation targets, not analyzer inputs.
