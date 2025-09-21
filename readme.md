

"""
# Secure Data Wiper

A NIST SP 800-88 compliant secure data wiping tool with tamper-proof certificate generation.

## Features

- **NIST SP 800-88 Rev. 1 Compliance** - Industry standard secure erasure
- **DoD 5220.22-M Support** - Military-grade data sanitization  
- **Tamper-Proof Certificates** - Cryptographically signed PDF and JSON certificates
- **Cross-Platform** - Works on Linux, Windows, and Android
- **One-Click Operation** - Simple GUI for non-technical users
- **Offline Operation** - No internet required
- **Third-Party Verification** - Independent certificate validation
- **Free & Open Source** - No licensing costs

## Installation

### Prerequisites

- Python 3.8 or higher
- Administrative/root privileges for device access

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Quick Start

```bash
# GUI Mode (recommended)
python main.py

# CLI Mode
python main.py --cli --device /dev/sdb --method nist
```

## Usage

### GUI Mode

1. Launch the application: `python main.py`
2. Select target device from dropdown
3. Choose wiping method (NIST recommended)
4. Review device information carefully
5. Click "Start Secure Wipe"
6. Confirm by typing "WIPE"
7. Wait for completion and save certificates

### CLI Mode

```bash
# Wipe device with NIST method
python main.py --cli --device /dev/sdb --method nist

# Wipe device with DoD method  
python main.py --cli --device /dev/sdb --method dod
```

## Certificate Verification

Certificates can be verified independently:

```bash
python -c "from core.certificate import CertificateGenerator; print(CertificateGenerator().verify_certificate('cert.json'))"
```

## Testing

Run the test suite:

```bash
python -m pytest tests/
```

## Security Features

- **Multi-pass overwriting** - NIST: 4 passes, DoD: 3 passes
- **Cryptographic verification** - SHA-256 hashing of each pass
- **Certificate integrity** - Tamper detection via digital signatures
- **Secure random generation** - Cryptographically secure random data
- **Hidden area coverage** - Includes HPA/DCO sectors on supported drives

## Standards Compliance

- **NIST SP 800-88 Rev. 1** - Guidelines for Media Sanitization
- **DoD 5220.22-M** - National Industrial Security Program Operating Manual

## Warning

⚠️ **This tool permanently destroys all data on target devices. Use with extreme caution!**

## License

MIT License - See LICENSE file for details

## Support

- Documentation: https://docs.securewiper.com
- Issues: https://github.com/securewiper/secure-data-wiper/issues
- Security: security@securewiper.com
"""