# Test fixtures (phase 001)

These files are **test-only** throwaway credentials, checked in so the
`tests/encrypt_roundtrip.rs` SSH Ed25519 round-trip test is self-contained.

- `test_ed25519` / `test_ed25519.pub` — an unencrypted OpenSSH Ed25519
  keypair generated with `ssh-keygen -t ed25519 -N ""`. It has no
  relationship to any real key and must never be used outside the test
  suite. It exists only to exercise `age`'s SSH recipient/identity path
  without requiring `ssh-keygen` at test time.

The X25519 age identity used by the tests is generated in-process via
`age::x25519::Identity::generate()` (no fixture file needed).
