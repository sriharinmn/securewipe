# Secure Data Wiper

A disk-wiping tool for Linux and Windows that overwrites a whole drive using NIST SP 800-88 or DoD 5220.22-M patterns, checks for hidden areas (HPA/DCO), and produces a JSON and PDF wipe certificate.

> ⚠️ **This permanently destroys all data on the selected device.** Run it only on a drive you mean to erase.

## Features

- **Wipe methods**
  - **NIST SP 800-88**: four passes (`0x00`, `0xFF`, `0xAA`, `0x55`)
  - **DoD 5220.22-M**: three passes (`0x00`, `0xFF`, random data)
- **Per-pass verification**: a SHA-256 hash is recorded for every pass.
- **Hidden areas**: detects and unlocks Host Protected Area (HPA) and Device Configuration Overlay (DCO) regions so the wipe covers them, then restores the drive's original configuration.
- **Device detection**: lists every drive, including external ones, and marks SSD/HDD and NVMe. It unmounts the target's volumes before wiping and remounts them afterwards.
- **Wipe certificates**: a JSON and a PDF certificate for every wipe, recording the device, method, timing and pass hashes, plus a SHA-256 hash of the certificate itself for tamper detection.
- **GUI and CLI**: a Tkinter GUI for one-click use and a command-line mode for scripting. It works fully offline.

## Install

Requires Python 3.8+ and administrator/root privileges (needed for raw device access).

```bash
pip install -r requirements.txt
```

## Usage

**GUI**

```bash
python main.py
```

Select the device, choose a method, review the device details, type `WIPE` to confirm, then save the certificates when it finishes.

**CLI**

```bash
python main.py --cli --device /dev/sdb --method nist
python main.py --cli --device /dev/sdb --method dod   # default
```

## Verify a certificate

```bash
python -c "from core.certificate import CertificateGenerator; print(CertificateGenerator().verify_certificate('cert.json'))"
```

## Tests

```bash
python -m pytest tests/
```

## Project layout

```
core/       wiping engine, device detection, HPA/DCO and mount handling, certificates
gui/        Tkinter interface
utils/      configuration and crypto helpers
tests/      test suite
main.py     entry point (GUI by default, --cli for command line)
```
