# Test data

Made with `ssh-keygen` (OpenSSH 10.2) on 2026-11-11. Everything here is a
throwaway: keys that guard nothing, made for the tests of `src/agent`.

- `ca_ed.pub`, `ca_rsa.pub`: two CAs.
- `host_ed-cert.pub`: a host certificate for an ed25519 key, principals
  `host.example.org` and `backup.example.org`, signed by `ca_ed`, valid
  2020-01-01 to 2099-12-31. Its fingerprint is
  `SHA256:1T2d+o1uviO6G2bFXBL66gkeZjLHNtJDENGwH+Q0A+w` (`ssh-keygen -l`).
- `host_p256-cert.pub`: a host certificate for a P-256 key, principal
  `host.example.org`, signed by `ca_rsa` (rsa-sha2-512). Fingerprint
  `SHA256:03BKZqwHOAF5ufeYfLIh1BVFHt18w+OQXlGlik1kMz8`.
- `host_p521.pub`: a P-521 host key (not supported; see `host_key.rs`).
- `host_rsa.pem`: the private half of a 2048-bit RSA key (PKCS#8), the only way
  the tests can sign with RSA. `host_rsa-cert.pub` is a *user* certificate for
  it, principal `alice`, signed by `ca_ed`.
