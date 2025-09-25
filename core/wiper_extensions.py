    def _remove_hpa(self, device_path: str, native_max: int) -> None:
        """Remove Host Protected Area by restoring native max address"""
        try:
            # Use SET_MAX_ADDRESS command to restore native max
            self.ata_command.execute_ata_command(
                device_path,
                ATACommand.SET_MAX_ADDRESS,
                sector_count=native_max & 0xFF,
                lba_low=(native_max >> 8) & 0xFF,
                lba_mid=(native_max >> 16) & 0xFF,
                lba_high=(native_max >> 24) & 0xFF
            )
            self.logger.info("Successfully removed HPA")
        except Exception as e:
            self.logger.error(f"Failed to remove HPA: {e}")
            raise
            
    def _remove_dco(self, device_path: str) -> None:
        """Remove Device Configuration Overlay"""
        try:
            # Use DEVICE CONFIGURATION RESTORE command
            self.ata_command.execute_ata_command(
                device_path,
                ATACommand.READ_DCO,
                feature=0xC0  # Restore subcommand
            )
            self.logger.info("Successfully removed DCO")
        except Exception as e:
            self.logger.error(f"Failed to remove DCO: {e}")
            raise
            
    def _wipe_partition(self, device_path: str, partition: Dict[str, Any],
                      method: str, progress_callback: Optional[Callable]) -> None:
        """Securely wipe a specific partition"""
        try:
            offset = partition.get('offset', 0)
            size = partition.get('size', 0)
            
            self.logger.info(f"Wiping partition at offset {offset} with size {size}")
            
            # Open device with direct access
            with open(device_path, 'rb+') as device:
                device.seek(offset)
                total_bytes = 0
                
                # Use appropriate pattern based on method
                patterns = self.NIST_PATTERNS if method == 'nist' else self.DOD_PATTERNS
                
                for pattern in patterns:
                    device.seek(offset)
                    bytes_written = 0
                    
                    while bytes_written < size:
                        # Generate block data
                        if pattern is None:
                            # Random data for DoD method
                            block_data = os.urandom(min(self.block_size, size - bytes_written))
                        else:
                            # Fixed pattern
                            block_len = min(self.block_size, size - bytes_written)
                            block_data = pattern * block_len
                            
                        # Write block
                        device.write(block_data)
                        bytes_written += len(block_data)
                        total_bytes += len(block_data)
                        
                        # Update progress
                        if progress_callback:
                            progress = (total_bytes / size) * 100
                            progress_callback(progress)
                            
                # Verify wipe
                device.seek(offset)
                for i in range(0, size, self.block_size):
                    block = device.read(min(self.block_size, size - i))
                    if any(b != 0 for b in block):
                        raise Exception("Verification failed - non-zero data found")
                        
            self.logger.info(f"Successfully wiped partition at offset {offset}")
            
        except Exception as e:
            self.logger.error(f"Failed to wipe partition: {e}")
            raise