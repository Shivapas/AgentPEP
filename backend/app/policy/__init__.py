"""AgentPEP trusted policy loader and AAPM consumer interface.

Sprint S-E03: Trusted Policy Loader + AAPM Consumer Interface
Features: FEATURE-02, FEATURE-09 (Part A)

Components:
  - trusted_key:      Pinned AAPM Ed25519 public key (compile-time constant)
  - events:           SECURITY_VIOLATION event emission
  - bundle_version:   Thread-safe bundle version tracking
  - loader:           Trusted policy loader with signature verification
  - registry_webhook: AAPM push notification receiver
  - registry_poll:    Pull polling fallback (60-second interval)
"""
