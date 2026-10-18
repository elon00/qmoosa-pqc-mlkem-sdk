# QMOOSA Post-Quantum Cryptography SDK (`qmoosa-pqc-mlkem-sdk`)

[![NIST FIPS 203](https://img.shields.io/badge/Standard-NIST%20FIPS%20203-blue.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![TypeScript](https://img.shields.io/badge/Language-TypeScript-blue.svg)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

`@qmoosa/pqc-mlkem-sdk` is the high-level developer toolkit and client abstraction layer for post-quantum key exchange in the QMOOSA-1000 portfolio (Domain 2: Post-Quantum Cryptography & Quantum Security, Batch 11, Repository 053).

---

## Features

- **`MlKemClient`**: Simple, intuitive API for pure ML-KEM and hybrid ML-KEM + X25519 key encapsulation.
- **`PqcSessionHandshake`**: Interactive 4-step authenticated key exchange protocol for quantum-safe peer-to-peer and client-server sessions.
- **Hex & Base64URL Serialization**: Zero-dependency string formatting with strict input validation.
- **Tamper Resistance**: Constant-time HMAC authentication tags preventing MITM and oracle attacks.

---

## License

MIT © 2026 elon00 / QMOOSA Mission
