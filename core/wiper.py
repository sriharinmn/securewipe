import os
import hashlib
import logging
from typing import Optional, Callable
from datetime import datetime
import random

class DataWiper:
    NIST_PATTERNS = [b'\x00', b'\xFF', b'\xAA', b'\x55']
    DOD_PATTERNS = [b'\x00', b'\xFF', None]

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.default_block_size = 1 * 1024 * 1024  # 1 MB
        self.sample_blocks = 10  # number of blocks to sample for verification

    def wipe_device(self, device_path: str, method: str = 'nist',
                   progress_callback: Optional[Callable] = None) -> str:
        start_time = datetime.now()

        if not os.path.exists(device_path):
            raise ValueError(f"Device {device_path} does not exist")

        device_size = self._get_device_size(device_path)
        if device_size == 0:
            raise ValueError("Could not determine device size")

        self.logger.info(f"Starting {method.upper()} wipe of {device_path} ({device_size} bytes)")
        patterns = self.NIST_PATTERNS if method == 'nist' else self.DOD_PATTERNS
        total_passes = len(patterns)
        verification_hashes = []
        sample_verification_results = []

        block_size = self.default_block_size if device_size >= self.default_block_size else device_size

        try:
            with open(device_path, 'r+b', buffering=0) as device:
                for pass_num, pattern in enumerate(patterns, 1):
                    self.logger.info(f"Starting pass {pass_num}/{total_passes}")

                    if pattern is None:
                        pass_hash = self._write_random_pattern(device, device_size, progress_callback, pass_num, total_passes, block_size)
                    else:
                        pass_hash = self._write_fixed_pattern(device, device_size, pattern, progress_callback, pass_num, total_passes, block_size)

                    verification_hashes.append({
                        'pass': pass_num,
                        'pattern': pattern.hex() if pattern else 'random',
                        'hash': pass_hash
                    })

                    # Perform statistical verification
                    samples_ok = self._verify_samples(device, device_size, pattern, pass_hash, block_size)
                    sample_verification_results.append({
                        'pass': pass_num,
                        'verified': samples_ok
                    })

        except Exception as e:
            self.logger.error(f"Wipe operation failed: {e}")
            raise

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        # Certificate
        from core.certificate import CertificateGenerator
        cert_gen = CertificateGenerator()
        cert_id = cert_gen.generate_certificate({
            'device_path': device_path,
            'device_size': device_size,
            'method': method.upper(),
            'start_time': start_time,
            'end_time': end_time,
            'duration': duration,
            'verification_hashes': verification_hashes,
            'sample_verification_results': sample_verification_results,
            'passes': total_passes
        })

        self.logger.info(f"Wipe completed successfully. Certificate ID: {cert_id}")
        return cert_id

    def _get_device_size(self, device_path: str) -> int:
        try:
            with open(device_path, 'rb') as device:
                device.seek(0, os.SEEK_END)
                return device.tell()
        except Exception as e:
            self.logger.error(f"Failed to get device size: {e}")
            return 0

    def _write_fixed_pattern(self, device, device_size: int, pattern: bytes,
                             progress_callback: Optional[Callable], pass_num: int, total_passes: int,
                             block_size: int) -> str:
        device.seek(0)
        bytes_written = 0
        pattern_block = pattern * block_size

        while bytes_written < device_size:
            remaining = device_size - bytes_written
            write_size = min(block_size, remaining)
            device.write(pattern_block[:write_size])
            bytes_written += write_size

            if progress_callback:
                overall_progress = ((pass_num - 1) * 100 + (bytes_written * 100 // device_size)) // total_passes
                progress_callback(overall_progress, f"Pass {pass_num}/{total_passes}: Writing pattern")

        # Hash for fixed pattern can be precomputed or sampled
        hasher = hashlib.sha256()
        hasher.update(pattern * min(1024, device_size))  # sample-based hash
        return hasher.hexdigest()

    def _write_random_pattern(self, device, device_size: int,
                              progress_callback: Optional[Callable], pass_num: int, total_passes: int,
                              block_size: int) -> str:
        device.seek(0)
        hasher = hashlib.sha256()
        bytes_written = 0

        while bytes_written < device_size:
            remaining = device_size - bytes_written
            write_size = min(block_size, remaining)
            random_data = os.urandom(write_size)
            device.write(random_data)
            hasher.update(random_data)
            bytes_written += write_size

            if progress_callback:
                overall_progress = ((pass_num - 1) * 100 + (bytes_written * 100 // device_size)) // total_passes
                progress_callback(overall_progress, f"Pass {pass_num}/{total_passes}: Writing random data")

        return hasher.hexdigest()

    def _verify_samples(self, device, device_size: int, pattern: Optional[bytes], expected_hash: str, block_size: int) -> bool:
        """Verify random sample blocks from device"""
        device.seek(0)
        sample_blocks = min(10, device_size // block_size)
        verified = True

        for _ in range(sample_blocks):
            pos = random.randint(0, device_size - block_size)
            device.seek(pos)
            data = device.read(block_size)

            if pattern is None:
                # Random pass: compare hash of sample to expected hash (approximate)
                sample_hash = hashlib.sha256(data).hexdigest()
                if sample_hash != expected_hash:
                    verified = False
                    break
            else:
                # Fixed pass: all bytes should match pattern
                if data != pattern * len(data):
                    verified = False
                    break
        return verified

