# Performance Benchmarking of Cryptographic Mechanisms

## Overview

This project implements *Assignment #1* from the **Security and Privacy** course, which focuses on evaluating the performance of message digests, symmetric encryption, and asymmetric cryptographic mechanisms.

It performs performance benchmarking of:
- **AES-256** in Counter (CTR) mode (encryption + decryption)
- **Custom RSA-based encryption/decryption** (2048-bit keys) using the hybrid construction specified in the assignment
- **SHA-256** hash generation

Benchmarks are executed on randomly generated files of the exact sizes required by the assignment:
- 8, 64, 512, 4096, 32768, 262144, 2097152 bytes

All cryptographic operations are timed **only** (file generation and side effects are excluded). Multiple runs with statistical analysis (mean + standard deviation) ensure statistically significant results, as required.

## Features

- Automatic generation of random test files (`os.urandom`)
- High-precision timing using `timeit` + warm-up calls
- Statistical significance (mean time in microseconds + standard deviation)
- Different repetition counts for large files (RSA is slower)
- Log-log performance plots saved as `grafico.png`
- Fully compliant with points **A–E** of the assignment

## Dependencies & Required Versions

**Python Version:**  
Tested in `Python 3.12`.

**Python Packages versions used** (install via pip):

```bash
pip install cryptography==46.0.6 matplotlib==3.10.8
