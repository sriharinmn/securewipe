# =============================================================================
# gui/interface.py - Enhanced GUI Interface with Hidden Partition Support
# =============================================================================

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import logging
import json
import os
from core.detector import DeviceDetector
from core.wiper import DataWiper
from core.certificate import CertificateGenerator

class SecureWiperGUI:
    """Enhanced GUI interface for the secure data wiper with hidden partition support"""
    
    def __init__(self):  # Changed from _init_ to __init__
        self.root = tk.Tk()
        self.root.title("Secure Data Wiper v2.0 - NIST SP 800-88 Rev. 1 Compliant")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        self.detector = DeviceDetector()
        self.wiper = DataWiper()
        self.cert_gen = CertificateGenerator()
        self.logger = logging.getLogger(__name__)  # Changed _name_ to __name__
        
        self.selected_device = None
        self.wipe_thread = None
        
        self.setup_ui()
        self.refresh_devices()
    
    def setup_ui(self):
        """Setup the enhanced user interface with hidden partition support"""
        # Configure styles
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("SSD.TLabel", foreground="blue", font=('Arial', 9, 'bold'))
        style.configure("HDD.TLabel", foreground="black", font=('Arial', 9))
        style.configure("Warning.TLabel", foreground="red", font=('Arial', 9, 'bold'))
        
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="Secure Data Wiper v2.0", 
                               font=('Arial', 18, 'bold'))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 5))
        
        subtitle_label = ttk.Label(main_frame, text="NIST SP 800-88 Rev. 1 Compliant with Hidden Partition Support", 
                                 font=('Arial', 10, 'italic'))
        subtitle_label.grid(row=1, column=0, columnspan=3, pady=(0, 20))
        
        # Device selection section
        device_frame = ttk.LabelFrame(main_frame, text="Device Selection", padding="10")
        device_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        device_frame.columnconfigure(1, weight=1)
        
        ttk.Label(device_frame, text="Select Device:").grid(row=0, column=0, sticky=tk.W, pady=5)
        
        self.device_var = tk.StringVar()
        self.device_combo = ttk.Combobox(device_frame, textvariable=self.device_var, 
                                       state="readonly", width=60)
        self.device_combo.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        
        refresh_btn = ttk.Button(device_frame, text="Refresh Devices", command=self.refresh_devices)
        refresh_btn.grid(row=0, column=2, pady=5, padx=(5, 0))
        
        # Device type indicator
        self.device_type_label = ttk.Label(device_frame, text="", font=('Arial', 10, 'bold'))
        self.device_type_label.grid(row=1, column=1, sticky=tk.W, pady=5, padx=(5, 0))
        
        # Wipe method selection with SSD awareness
        method_frame = ttk.LabelFrame(main_frame, text="Wiping Method Selection", padding="10")
        method_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        
        ttk.Label(method_frame, text="Available Methods:").grid(row=0, column=0, sticky=tk.W, pady=5)
        
        self.method_var = tk.StringVar(value="auto")
        
        # Auto-select method (recommended)
        self.auto_radio = ttk.Radiobutton(method_frame, text="Auto-Select (Recommended)", 
                                        variable=self.method_var, value="auto",
                                        command=self.update_method_description)
        self.auto_radio.grid(row=1, column=0, sticky=tk.W, padx=20)
        
        # SSD-specific methods
        self.crypto_radio = ttk.Radiobutton(method_frame, text="Cryptographic Erasure (SSD Only)", 
                                          variable=self.method_var, value="crypto_erase",
                                          command=self.update_method_description)
        self.crypto_radio.grid(row=2, column=0, sticky=tk.W, padx=20)
        
        self.secure_radio = ttk.Radiobutton(method_frame, text="ATA/NVMe Secure Erase (SSD Only)", 
                                          variable=self.method_var, value="secure_erase",
                                          command=self.update_method_description)
        self.secure_radio.grid(row=3, column=0, sticky=tk.W, padx=20)
        
        # Traditional methods
        self.nist_radio = ttk.Radiobutton(method_frame, text="NIST SP 800-88 Overwrite (All Drives)", 
                                        variable=self.method_var, value="nist",
                                        command=self.update_method_description)
        self.nist_radio.grid(row=4, column=0, sticky=tk.W, padx=20)
        
        self.dod_radio = ttk.Radiobutton(method_frame, text="DoD 5220.22-M Overwrite (All Drives)", 
                                       variable=self.method_var, value="dod",
                                       command=self.update_method_description)
        self.dod_radio.grid(row=5, column=0, sticky=tk.W, padx=20)
        
        # Method description
        self.method_desc_label = ttk.Label(method_frame, text="", wraplength=600, 
                                         font=('Arial', 9), foreground="blue")
        self.method_desc_label.grid(row=6, column=0, columnspan=2, sticky=tk.W, pady=(10, 0))
        
        # Device information with enhanced hidden partition details
        info_frame = ttk.LabelFrame(main_frame, text="Device Information & Hidden Partition Analysis", padding="10")
        info_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        
        # Configure grid weights for proper expansion
        info_frame.columnconfigure(0, weight=1)
        info_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(4, weight=1)
        
        # Make info text area larger and add scrollbar
        self.info_text = tk.Text(info_frame, height=20, width=80, state=tk.DISABLED, wrap=tk.WORD)
        info_scrollbar = ttk.Scrollbar(info_frame, orient=tk.VERTICAL, command=self.info_text.yview)
        self.info_text.configure(yscrollcommand=info_scrollbar.set)
        
        # Use proper sticky settings for text widget and scrollbar
        self.info_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 2))
        info_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Progress section
        progress_frame = ttk.LabelFrame(main_frame, text="Wipe Progress", padding="10")
        progress_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        progress_frame.columnconfigure(0, weight=1)
        
        self.progress = ttk.Progressbar(progress_frame, length=500, mode='determinate')
        self.progress.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        
        self.progress_label = ttk.Label(progress_frame, text="Ready to start secure wiping")
        self.progress_label.grid(row=1, column=0, pady=5)
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=6, column=0, columnspan=3, pady=20)
        
        self.wipe_btn = ttk.Button(button_frame, text="Start Secure Wipe", 
                                 command=self.start_wipe)
        self.wipe_btn.pack(side=tk.LEFT, padx=5)
        
        self.verify_btn = ttk.Button(button_frame, text="Verify Certificate", 
                                   command=self.verify_certificate)
        self.verify_btn.pack(side=tk.LEFT, padx=5)
        
        self.create_test_btn = ttk.Button(button_frame, text="Create Test Files", 
                                        command=self.create_test_files)
        self.create_test_btn.pack(side=tk.LEFT, padx=5)
        
        self.quit_btn = ttk.Button(button_frame, text="Exit", command=self.root.quit)
        self.quit_btn.pack(side=tk.LEFT, padx=5)
        
        # Bind events
        self.device_combo.bind('<<ComboboxSelected>>', self.on_device_selected)
    
    def refresh_devices(self):
        """Refresh the list of available devices with SSD detection"""
        try:
            devices = self.detector.get_all_devices()
            device_list = []
            self.device_data = {}
            
            for device in devices:
                # Enhanced display name with SSD/HDD indicator
                device_type = "SSD" if device.get('is_ssd', False) else "HDD"
                nvme_indicator = " (NVMe)" if device.get('is_nvme', False) else ""
                
                display_name = f"{device['name']} - {device['model']} ({device['size']}) [{device_type}{nvme_indicator}]"
                device_list.append(display_name)
                self.device_data[display_name] = device
            
            self.device_combo['values'] = device_list
            if device_list:
                self.device_combo.current(0)
                self.on_device_selected(None)
            else:
                self.info_text.config(state=tk.NORMAL)
                self.info_text.delete(1.0, tk.END)
                self.info_text.insert(1.0, "No devices found. Try creating test files or running as administrator.")
                self.info_text.config(state=tk.DISABLED)
        
        except Exception as e:
            self.logger.error(f"Failed to refresh devices: {e}")
            messagebox.showerror("Error", f"Failed to detect devices: {e}")
    
    def on_device_selected(self, event):
        """Handle device selection with enhanced hidden partition information"""
        selected = self.device_var.get()
        if selected in self.device_data:
            device = self.device_data[selected]
            self.selected_device = device
            
            # Check for hidden partitions immediately
            hidden_info = self.wiper.check_hidden_partitions(device['path'])
            
            if 'error' in hidden_info:
                self.info_text.config(state=tk.NORMAL)
                self.info_text.delete(1.0, tk.END)
                self.info_text.insert(1.0, f"Error checking hidden partitions: {hidden_info['error']}")
                self.info_text.config(state=tk.DISABLED)
                return
            
            # Update device info display
            info_text = f"""DEVICE INFORMATION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Device: {device['name']}
Path: {device['path']}
Size: {device['size']}
Model: {device['model']}

HIDDEN PARTITION ANALYSIS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
            if hidden_info['hpa_detected'] or hidden_info['dco_detected']:
                for area in hidden_info.get('hidden_details', []):
                    if area['type'] == 'HPA':
                        info_text += f"\n⚠ WARNING: Host Protected Area (HPA) Found\n"
                        info_text += f"   • Size: {area['size_mb']} MB\n"
                        info_text += f"   • Sectors: {area['start_lba']} to {area['end_lba']}\n"
                    elif area['type'] == 'DCO':
                        info_text += f"\n⚠ WARNING: Device Configuration Overlay (DCO) Found\n"
                        info_text += f"   • Size: {area['size_mb']} MB\n"
                        info_text += f"   • Hidden Sectors: {area['sectors']}\n"
                
                total_hidden_mb = (hidden_info['hidden_sectors'] * 512) // (1024 * 1024)
                info_text += f"\n⚠ TOTAL HIDDEN SPACE: {total_hidden_mb} MB will be included in secure wipe\n"
                
                # Show warning in GUI
                messagebox.showwarning(
                    "Hidden Partitions Detected",
                    f"WARNING: This device contains {total_hidden_mb} MB of hidden space!\n\n"
                    "These hidden areas will be included in the secure wipe process.\n"
                    "See the device information panel for details."
                )
            else:
                info_text += "\n✓ No hidden partitions detected\n"
            
            # Update info display
            self.info_text.config(state=tk.NORMAL)
            self.info_text.delete(1.0, tk.END)
            self.info_text.insert(1.0, info_text)
            self.info_text.config(state=tk.DISABLED)

    def update_method_options(self, device):
        """Enable/disable method options based on device capabilities"""
        is_ssd = device.get('is_ssd', False)
        supports_crypto = device.get('supports_crypto_erase', False)
        supports_secure = device.get('supports_secure_erase', False)
        
        if is_ssd:
            # Enable SSD-specific methods
            self.crypto_radio.config(state=tk.NORMAL if supports_crypto else tk.DISABLED)
            self.secure_radio.config(state=tk.NORMAL if supports_secure else tk.DISABLED)
        else:
            # Disable SSD-specific methods for HDDs
            self.crypto_radio.config(state=tk.DISABLED)
            self.secure_radio.config(state=tk.DISABLED)
            
            # Auto-select NIST for HDDs if crypto/secure was selected
            if self.method_var.get() in ['crypto_erase', 'secure_erase']:
                self.method_var.set('nist')
    
    def update_device_info(self, device: dict, hidden_info: dict = None):
        """Update device information display with enhanced hidden partition info"""
        self.info_text.config(state=tk.NORMAL)
        self.info_text.delete(1.0, tk.END)
        
        info_text = f"""DEVICE INFORMATION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Device Path: {device['path']}
Device Name: {device['name']}
Model: {device['model']}
Size: {device['size']}
Type: {device.get('type', 'Unknown')}
Bus Type: {device.get('bus_type', 'Unknown')}
Removable: {'Yes' if device.get('is_removable', False) else 'No'}
System Drive: {'Yes' if device.get('is_system', False) else 'No'}

HIDDEN PARTITION ANALYSIS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"""

        if hidden_info:
            if hidden_info['hpa_detected'] or hidden_info['dco_detected']:
                for area in hidden_info.get('hidden_details', []):
                    if area['type'] == 'HPA':
                        info_text += f"""
⚠ Host Protected Area (HPA) Detected:
   • Size: {area['size_mb']} MB
   • Hidden Sectors: {area['sectors']:,}
   • Sector Range: {area['start_lba']:,} to {area['end_lba']:,}
   • Status: {"Unlockable" if hidden_info['hpa_unlocked'] else "Locked"}\n"""
                    elif area['type'] == 'DCO':
                        info_text += f"""
⚠ Device Configuration Overlay (DCO) Detected:
   • Size: {area['size_mb']} MB
   • Hidden Sectors: {area['sectors']:,}
   • Status: {"Unlockable" if hidden_info['dco_unlocked'] else "Locked"}\n"""
                
                total_hidden_mb = (hidden_info['hidden_sectors'] * 512) // (1024 * 1024)
                info_text += f"""
Total Hidden Space: {total_hidden_mb:,} MB ({hidden_info['hidden_sectors']:,} sectors)
Original Size: {hidden_info['original_size']:,} bytes
Accessible Size: {hidden_info['accessible_size']:,} bytes\n"""

                if hidden_info.get('warnings'):
                    info_text += "\nWarnings:\n"
                    for warning in hidden_info['warnings']:
                        info_text += f"• {warning}\n"
            else:
                info_text += "✓ No hidden partitions detected on this device\n"
        else:
            info_text += "❔ Hidden partition analysis not yet performed\n"
        
        info_text += """
IMPORTANT NOTES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Hidden areas will be included in the secure wipe process
• All data in both visible and hidden areas will be permanently destroyed
• The process cannot be interrupted once started
• A certificate will be generated after successful completion"""

        self.info_text.insert(1.0, info_text)
        self.info_text.config(state=tk.DISABLED)
        
        # Scroll to top
        self.info_text.see("1.0")

    def update_method_description(self):
        """Update method description based on selected method and device"""
        if not self.selected_device:
            return
            
        method = self.method_var.get()
        is_ssd = self.selected_device.get('is_ssd', False)
        
        descriptions = {
            'auto': f"Automatically selects the best method for your {'SSD' if is_ssd else 'HDD'}. " +
                   f"{'Cryptographic erasure for SSDs with encryption support, secure erase for other SSDs' if is_ssd else 'NIST SP 800-88 overwrite for HDDs with hidden partition detection'}.",
            
            'crypto_erase': "Cryptographic Erasure: Destroys the encryption key, making all data instantly unrecoverable. " +
                           "Fastest and most secure method for SSDs. NIST SP 800-88 Rev. 1 compliant.",
            
            'secure_erase': "ATA/NVMe Secure Erase: Hardware-level command that erases all user data including " +
                           "spare blocks and remapped sectors. NIST SP 800-88 Rev. 1 compliant.",
            
            'nist': "NIST SP 800-88 Overwrite: Single pass with fixed pattern followed by verification. " +
                   f"Suitable for HDDs and SSDs. Government standard for non-classified data.{' Includes HPA/DCO detection for HDDs.' if not is_ssd else ''}",
            
            'dod': "DoD 5220.22-M: Three-pass overwrite (zeros, ones, random). Traditional method " +
                  f"required by some organizations. Works on all drive types.{' Includes HPA/DCO detection for HDDs.' if not is_ssd else ''}"
        }
        
        desc = descriptions.get(method, "")
        
        # Add warnings for inappropriate method selections
        if method in ['crypto_erase', 'secure_erase'] and not is_ssd:
            desc += "\n⚠ This method is only available for SSDs. Please select a different method."
        elif method == 'auto':
            recommended = self.selected_device.get('recommended_method', 'nist')
            desc += f"\n→ Auto-selected method: {recommended.upper()}"
            if not is_ssd:
                desc += " (with HPA/DCO detection)"
        
        self.method_desc_label.config(text=desc)
    
    def start_wipe(self):
        """Start the wiping process with method validation"""
        if not self.selected_device:
            messagebox.showerror("Error", "Please select a device first")
            return
        
        # Validate method selection
        method = self.method_var.get()
        is_ssd = self.selected_device.get('is_ssd', False)
        
        if method == 'auto':
            # Auto-select the recommended method
            method = self.selected_device.get('recommended_method', 'nist')
        
        # Prevent SSD-only methods on HDDs
        if method in ['crypto_erase', 'secure_erase'] and not is_ssd:
            messagebox.showerror("Invalid Method", 
                               f"{method.replace('_', ' ').title()} is only available for SSD drives. "
                               f"This device is detected as an HDD. Please select NIST or DoD method.")
            return
        
        # Final confirmation with method details
        device_name = self.selected_device['name']
        device_type = "SSD" if is_ssd else "HDD"
        method_display = method.replace('_', ' ').title()
        hidden_partition_warning = "\n⚠  Hidden partitions (HPA/DCO) will be detected and wiped!" if not is_ssd else ""
        
        confirm_msg = f"""FINAL CONFIRMATION REQUIRED

You are about to securely wipe:

Device: {device_name}
Path: {self.selected_device['path']}
Type: {device_type}
Size: {self.selected_device['size']}
Method: {method_display}{hidden_partition_warning}

⚠  THIS WILL PERMANENTLY DESTROY ALL DATA ON THE DEVICE!
⚠  This action CANNOT be undone!
⚠  Data recovery will be IMPOSSIBLE after completion!

To confirm this irreversible action, type exactly: WIPE {device_name}"""
        
        expected_confirmation = f"WIPE {device_name}"
        confirmation = tk.simpledialog.askstring("⚠ DESTRUCTIVE OPERATION CONFIRMATION ⚠", 
                                                confirm_msg, show='*')
        
        if confirmation != expected_confirmation:
            messagebox.showinfo("Operation Cancelled", "Wipe operation cancelled - confirmation text did not match.")
            return
        
        # Final safety check
        final_check = messagebox.askyesno("⚠ LAST CHANCE ⚠", 
                                        "Are you absolutely certain you want to proceed?\n\n"
                                        "Click 'Yes' to permanently destroy all data.\n"
                                        "Click 'No' to cancel and keep your data safe.")
        if not final_check:
            return
        
        # Disable UI during wipe
        self.wipe_btn.config(state=tk.DISABLED)
        self.device_combo.config(state=tk.DISABLED)
        for radio in [self.auto_radio, self.crypto_radio, self.secure_radio, self.nist_radio, self.dod_radio]:
            radio.config(state=tk.DISABLED)
        
        # Start wipe in separate thread
        self.wipe_thread = threading.Thread(target=self._perform_wipe, args=(method,))
        self.wipe_thread.daemon = True
        self.wipe_thread.start()
    
    def _perform_wipe(self, method):
        """Perform the actual wipe operation"""
        try:
            def progress_callback(percent, message):
                self.root.after(0, lambda: self._update_progress(percent, message))
            
            device_path = self.selected_device['path']
            
            cert_id = self.wiper.wipe_device(
                device_path=device_path, 
                method=method, 
                device_info=self.selected_device,
                progress_callback=progress_callback
            )
            
            # Success
            self.root.after(0, lambda: self._wipe_complete(cert_id, method))
        
        except Exception as e:
            error_message = str(e)  # Store error message in local variable
            self.logger.error(f"Wipe failed: {error_message}")
            self.root.after(0, lambda: self._wipe_failed(error_message))
    
    def _update_progress(self, percent, message):
        """Update progress bar and message"""
        self.progress['value'] = percent
        self.progress_label.config(text=message)
        self.root.update_idletasks()
    
    def _wipe_complete(self, cert_id, method):
        """Handle successful wipe completion with hidden partition information"""
        self.progress['value'] = 100
        self.progress_label.config(text="✓ Secure wipe completed successfully!")
        
        # Re-enable UI
        self._enable_ui()
        
        method_name = method.replace('_', ' ').title()
        device_type = "SSD" if self.selected_device.get('is_ssd', False) else "HDD"
        
        # Check if hidden partitions were involved
        hidden_info = ""
        try:
            # Try to load the certificate to get hidden partition info
            cert_path = os.path.join(self.cert_gen.cert_dir, f'{cert_id}.json')
            if os.path.exists(cert_path):
                with open(cert_path, 'r') as f:
                    cert_data = json.load(f)
                    hidden_partition_analysis = cert_data.get('hidden_partition_analysis', {})
                    
                    if hidden_partition_analysis.get('hpa_detected') or hidden_partition_analysis.get('dco_detected'):
                        hidden_sectors = hidden_partition_analysis.get('hidden_sectors', 0)
                        hidden_mb = (hidden_sectors * 512) // (1024 * 1024) if hidden_sectors > 0 else 0
                        
                        hidden_info = f"""
🔍 HIDDEN PARTITION ANALYSIS:
✓ HPA (Host Protected Area): {'Detected and Wiped' if hidden_partition_analysis.get('hpa_unlocked') else 'Not Found'}
✓ DCO (Device Configuration Overlay): {'Detected and Wiped' if hidden_partition_analysis.get('dco_unlocked') else 'Not Found'}
✓ Hidden Space Processed: {hidden_mb} MB ({hidden_sectors:,} sectors)
✓ All hidden areas included in secure erasure process
"""
                    
                    mount_analysis = cert_data.get('mount_analysis', {})
                    if mount_analysis.get('unmounted_partitions'):
                        hidden_info += f"""
💾 DRIVE MANAGEMENT:
✓ External partitions safely unmounted: {len(mount_analysis['unmounted_partitions'])}
✓ System drives protected from unmounting
✓ Drive states restored after wiping
"""
        except Exception as e:
            self.logger.warning(f"Could not load certificate details: {e}")
        
        success_msg = f"""✅ SECURE WIPE COMPLETED SUCCESSFULLY!

Device: {self.selected_device['name']}
Type: {device_type}
Method: {method_name}
Certificate ID: {cert_id}
{hidden_info}
📁 Certificates Location: ./certificates/

🛡 Your wipe certificates include:
✓ Cryptographic proof of secure erasure
✓ Hidden partition analysis and verification
✓ Tamper-proof digital signatures  
✓ Full NIST SP 800-88 Rev. 1 compliance verification
✓ Third-party verification support
✓ Detailed forensic audit trail

📋 Certificate Files Generated:
• {cert_id}.pdf (Human-readable certificate)
• {cert_id}.json (Machine-readable verification data)

Keep these certificates as legal proof of secure data destruction."""
        
        messagebox.showinfo("🎉 Wipe Complete", success_msg)
    
    def _wipe_failed(self, error_msg):
        """Handle wipe failure"""
        self.progress['value'] = 0
        self.progress_label.config(text="❌ Wipe operation failed!")
        
        # Re-enable UI
        self._enable_ui()
        
        messagebox.showerror("Wipe Failed", f"Secure wipe operation failed:\n\n{error_msg}\n\n"
                                          f"Please check the logs for detailed error information.")
    
    def _enable_ui(self):
        """Re-enable UI controls after wipe operation"""
        self.wipe_btn.config(state=tk.NORMAL)
        self.device_combo.config(state="readonly")
        
        # Re-enable appropriate radio buttons
        if self.selected_device:
            self.update_method_options(self.selected_device)
        
        for radio in [self.auto_radio, self.nist_radio, self.dod_radio]:
            radio.config(state=tk.NORMAL)
    
    def verify_certificate(self):
        """Verify a certificate file"""
        cert_path = filedialog.askopenfilename(
            title="Select Certificate File to Verify",
            filetypes=[("JSON certificates", ".json"), ("All files", ".*")],
            initialdir="./certificates"
        )
        
        if cert_path:
            try:
                valid, message = self.cert_gen.verify_certificate(cert_path)
                if valid:
                    messagebox.showinfo("✅ Certificate Valid", f"Certificate verification successful!\n\n{message}")
                else:
                    messagebox.showerror("❌ Certificate Invalid", f"Certificate verification failed!\n\n{message}")
            except Exception as e:
                messagebox.showerror("Verification Error", f"Failed to verify certificate:\n\n{e}")
    
    def create_test_files(self):
        """Create test files for safe testing"""
        try:
            import tempfile
            import os
            
            # Create test files in system temp directory
            temp_dir = tempfile.gettempdir()
            
            # Create different types of test files
            test_files = [
                ('test_drive_ssd_small.img', 10 * 1024 * 1024),  # 10MB SSD
                ('test_drive_hdd_small.img', 10 * 1024 * 1024),  # 10MB HDD
                ('test_drive_nvme_medium.img', 50 * 1024 * 1024)  # 50MB NVMe
            ]
            
            created_files = []
            for filename, size in test_files:
                filepath = os.path.join(temp_dir, filename)
                
                # Create file with random data
                with open(filepath, 'wb') as f:
                    remaining = size
                    while remaining > 0:
                        chunk_size = min(64 * 1024, remaining)
                        f.write(os.urandom(chunk_size))
                        remaining -= chunk_size
                
                created_files.append(filepath)
            
            messagebox.showinfo("Test Files Created", 
                              f"Created test files for safe wiping practice:\n\n" + 
                              "\n".join([f"• {os.path.basename(f)}" for f in created_files]) +
                              f"\n\nLocation: {temp_dir}\n\n"
                              f"Click 'Refresh Devices' to see the test files in the device list.")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create test files: {e}")
    
    def run(self):
        """Run the GUI application"""
        try:
            # Add missing import for simpledialog
            import tkinter.simpledialog
            tk.simpledialog = tkinter.simpledialog
            
            self.root.mainloop()
        except Exception as e:
            self.logger.error(f"GUI error: {e}")
            messagebox.showerror("Application Error", f"Application error: {e}")