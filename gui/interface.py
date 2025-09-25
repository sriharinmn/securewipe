# =============================================================================
# gui/interface.py - Enhanced GUI Interface with SSD Support
# =============================================================================

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import logging
from core.detector import DeviceDetector
from core.wiper import DataWiper
from core.certificate import CertificateGenerator

class SecureWiperGUI:
    """Enhanced GUI interface for the secure data wiper with SSD support"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Secure Data Wiper v2.0 - NIST SP 800-88 Rev. 1 Compliant")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        self.detector = DeviceDetector()
        self.wiper = DataWiper()
        self.cert_gen = CertificateGenerator()
        self.logger = logging.getLogger(__name__)
        
        self.selected_device = None
        self.wipe_thread = None
        
        self.setup_ui()
        self.refresh_devices()
    
    def setup_ui(self):
        """Setup the enhanced user interface with SSD support"""
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
        
        subtitle_label = ttk.Label(main_frame, text="NIST SP 800-88 Rev. 1 Compliant with SSD Support", 
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
        
        # Device information with enhanced SSD details
        info_frame = ttk.LabelFrame(main_frame, text="Device Information & Capabilities", padding="10")
        info_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        info_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(4, weight=1)
        
        self.info_text = tk.Text(info_frame, height=10, state=tk.DISABLED, wrap=tk.WORD)
        info_scrollbar = ttk.Scrollbar(info_frame, orient=tk.VERTICAL, command=self.info_text.yview)
        self.info_text.configure(yscrollcommand=info_scrollbar.set)
        
        self.info_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
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
        
        self.hpa_dco_btn = ttk.Button(button_frame, text="Show HPA/DCO Info", command=self.print_hpa_dco_summary)
        self.hpa_dco_btn.pack(side=tk.LEFT, padx=5)
        
        # Bind events
        self.device_combo.bind('<<ComboboxSelected>>', self.on_device_selected)
    
    def refresh_devices(self):
        """Refresh the list of available devices with SSD, HPA, DCO, and hidden partition detection"""
        try:
            devices = self.detector.get_all_devices()
            device_list = []
            self.device_data = {}

            for device in devices:
                # Detect HPA, DCO, hidden partitions
                has_hpa, native_max, current_max = self.detector.detect_hpa(device['path'])
                has_dco, dco_info = self.detector.detect_dco(device['path'])
                hidden_partitions = self.detector.detect_hidden_partitions(device['path'])

                device['has_hpa'] = has_hpa
                device['native_max'] = native_max
                device['current_max'] = current_max
                device['has_dco'] = has_dco
                device['dco_info'] = dco_info
                device['hidden_partitions'] = hidden_partitions

                # Normal device display
                device_type = "SSD" if device.get('is_ssd', False) else "HDD"
                nvme_indicator = " (NVMe)" if device.get('is_nvme', False) else ""
                display_name = f"{device['name']} - {device['model']} ({device['size']}) [{device_type}{nvme_indicator}]"
                device_list.append(display_name)
                self.device_data[display_name] = device

                # Add HPA entry if detected
                if has_hpa:
                    hpa_name = f"HPA on {device['name']}"
                    device_list.append(hpa_name)
                    self.device_data[hpa_name] = {
                        'type': 'HPA',
                        'native_max': native_max,
                        'current_max': current_max,
                        'path': device['path'],
                        'is_ssd': device.get('is_ssd', False),
                        'is_nvme': device.get('is_nvme', False)
                    }

                # Add DCO entry if detected
                if has_dco:
                    dco_name = f"DCO on {device['name']}"
                    device_list.append(dco_name)
                    self.device_data[dco_name] = {
                        'type': 'DCO',
                        'info': dco_info,
                        'path': device['path'],
                        'is_ssd': device.get('is_ssd', False),
                        'is_nvme': device.get('is_nvme', False)
                    }

                # Add hidden partitions
                for idx, part in enumerate(hidden_partitions):
                    part_name = f"Hidden Partition {idx+1} on {device['name']}"
                    device_list.append(part_name)
                    self.device_data[part_name] = {
                        'type': 'Hidden Partition',
                        'offset': part['offset'],
                        'size': part['size'],
                        'path': device['path'],
                        'is_ssd': device.get('is_ssd', False),
                        'is_nvme': device.get('is_nvme', False)
                    }

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
        """Handle device selection with enhanced SSD, HPA, DCO, and hidden partition info"""
        selected = self.device_var.get()
        if selected in self.device_data:
            device = self.device_data[selected]
            self.selected_device = device

            type_ = device.get('type', 'Device')
            is_ssd = device.get('is_ssd', False)
            is_nvme = device.get('is_nvme', False)

            # Update device type indicator
            if type_ == 'Device':
                if is_ssd:
                    device_type_text = f"{'NVMe SSD' if is_nvme else 'SATA SSD'} - Optimized methods available"
                    self.device_type_label.config(text=device_type_text, style="SSD.TLabel")
                else:
                    self.device_type_label.config(text="HDD - Traditional overwrite methods", style="HDD.TLabel")
            else:
                # HPA/DCO/Hidden Partition indicator
                self.device_type_label.config(text=f"{type_} detected on device", style="Warning.TLabel")

            # Enable/disable method options based on device type (only for normal devices)
            if type_ == 'Device':
                self.update_method_options(device)
            else:
                # Disable SSD-specific methods for HPA/DCO/Hidden partitions
                for radio in [self.crypto_radio, self.secure_radio]:
                    radio.config(state=tk.DISABLED)
                self.method_var.set('nist')

            # Update device info display
            info_text = ""
            if type_ == 'HPA':
                info_text = f"""Host Protected Area (HPA) Detected
    Device Path: {device['path']}
    Native Max Address: {device.get('native_max')}
    Current Max Address: {device.get('current_max')}"""
            elif type_ == 'DCO':
                info_text = f"""Device Configuration Overlay (DCO) Detected
    Device Path: {device['path']}
    DCO Info: {device.get('dco_info')}"""
            elif type_ == 'Hidden Partition':
                info_text = f"""Hidden Partition Detected
    Device Path: {device['path']}
    Offset: {device.get('offset')}
    Size: {device.get('size')}"""
            else:
                # Normal device display
                info_text = f"""DEVICE INFORMATION:
    Device Path: {device['path']}
    Device Name: {device['name']}
    Model: {device['model']}
    Size: {device['size']}
    Type: {'SSD' if is_ssd else 'HDD'}
    Interface: {'NVMe' if is_nvme else ('SATA SSD' if is_ssd else 'SATA/IDE')}"""

            self.info_text.config(state=tk.NORMAL)
            self.info_text.delete(1.0, tk.END)
            self.info_text.insert(1.0, info_text)
            self.info_text.config(state=tk.DISABLED)

            # Update method description
            self.update_method_description()

            # Check if device is safe to wipe (skip for HPA/DCO/hidden partitions if needed)
            if type_ == 'Device':
                safe, reason = self.detector.is_device_safe_to_wipe(device['path'])
                if not safe:
                    self.wipe_btn.config(state=tk.DISABLED)
                    messagebox.showwarning("Device Warning", f"Cannot wipe this device: {reason}")
                else:
                    self.wipe_btn.config(state=tk.NORMAL)
            else:
                # Allow wipe for HPA/DCO/hidden partitions but disable method selection
                self.wipe_btn.config(state=tk.NORMAL)

    
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
    
    def update_device_info(self, device):
        self.info_text.config(state=tk.NORMAL)
        self.info_text.delete(1.0, tk.END)
        
        is_ssd = device.get('is_ssd', False)
        is_nvme = device.get('is_nvme', False)
        
        info_text = f"""DEVICE INFORMATION:
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    Device Path: {device['path']}
    Device Name: {device['name']}
    Model: {device['model']}
    Size: {device['size']}
    Type: {device.get('type', 'Unknown')}
    Mounted: {'Yes' if device.get('mounted', False) else 'No'}

    STORAGE TECHNOLOGY:
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    Storage Type: {'SSD (Solid State Drive)' if is_ssd else 'HDD (Hard Disk Drive)'}
    Interface: {'NVMe' if is_nvme else ('SATA SSD' if is_ssd else 'SATA/IDE')}

    SSD CAPABILITIES:
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    """

        if is_ssd:
            info_text += f"""
    Cryptographic Erasure Support: {'✓ Yes' if device.get('supports_crypto_erase', False) else '✗ No'}
    Secure Erase Support: {'✓ Yes' if device.get('supports_secure_erase', False) else '✗ No'}
    Recommended Method: {device.get('recommended_method', 'nist').upper()}

    WHY SSD METHODS ARE BETTER:
    • Cryptographic Erasure: Instantly destroys encryption keys, making data unrecoverable
    • Secure Erase: Hardware-level erasure including spare blocks and wear-leveled areas
    • Traditional overwrite methods may not reach all NAND cells due to wear leveling
    """
        else:
            info_text += """
    This is a traditional hard disk drive (HDD).
    • Uses magnetic storage technology
    • Data is stored on spinning platters
    • Overwrite methods are effective for complete data destruction
    • Recommended methods: NIST SP 800-88 or DoD 5220.22-M
    """

        hpa_info = device.get('hpa', [])
        dco_info = device.get('dco', [])
        hidden_partitions = device.get('hidden_partitions', [])

        info_text += f"""
    HPA / DCO / HIDDEN PARTITIONS:
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    HPA Areas: {len(hpa_info)} {'(Offsets: ' + ', '.join(str(h['start']) for h in hpa_info) + ')' if hpa_info else ''}
    DCO Entries: {len(dco_info)} {'(Details: ' + ', '.join(str(d) for d in dco_info) + ')' if dco_info else ''}
    Hidden Partitions: {len(hidden_partitions)} {'(Offsets: ' + ', '.join(str(p['offset']) for p in hidden_partitions) + ')' if hidden_partitions else ''}
    """

        info_text += f"""

    SELECTED WIPING METHOD:
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    Current Selection: {self.method_var.get().upper()}

    ⚠️  IMPORTANT WARNINGS:
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    🔴 This operation will PERMANENTLY DESTROY all data on the selected device
    🔴 Data recovery will be impossible after the wipe process completes
    🔴 Ensure you have backups of any important data before proceeding
    🔴 Verify you have selected the correct device - mistakes cannot be undone
    🔴 The process may take several hours depending on device size and method

    COMPLIANCE STANDARDS:
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    • NIST SP 800-88 Rev. 1: Guidelines for Media Sanitization
    • DoD 5220.22-M: Department of Defense standard
    • Common Criteria Protection Profiles
    • Federal Information Processing Standards (FIPS)
    """

        self.info_text.insert(1.0, info_text)
        self.info_text.config(state=tk.DISABLED)

    def update_method_description(self):
        """Update method description based on selected method and device"""
        if not self.selected_device:
            return
            
        method = self.method_var.get()
        is_ssd = self.selected_device.get('is_ssd', False)
        
        descriptions = {
            'auto': f"Automatically selects the best method for your {'SSD' if is_ssd else 'HDD'}. " +
                   f"{'Cryptographic erasure for SSDs with encryption support, secure erase for other SSDs' if is_ssd else 'NIST SP 800-88 overwrite for HDDs'}.",
            
            'crypto_erase': "Cryptographic Erasure: Destroys the encryption key, making all data instantly unrecoverable. " +
                           "Fastest and most secure method for SSDs. NIST SP 800-88 Rev. 1 compliant.",
            
            'secure_erase': "ATA/NVMe Secure Erase: Hardware-level command that erases all user data including " +
                           "spare blocks and remapped sectors. NIST SP 800-88 Rev. 1 compliant.",
            
            'nist': "NIST SP 800-88 Overwrite: Single pass with fixed pattern followed by verification. " +
                   "Suitable for HDDs and SSDs. Government standard for non-classified data.",
            
            'dod': "DoD 5220.22-M: Three-pass overwrite (zeros, ones, random). Traditional method " +
                  "required by some organizations. Works on all drive types."
        }
        
        desc = descriptions.get(method, "")
        
        # Add warnings for inappropriate method selections
        if method in ['crypto_erase', 'secure_erase'] and not is_ssd:
            desc += "\n⚠️ This method is only available for SSDs. Please select a different method."
        elif method == 'auto':
            recommended = self.selected_device.get('recommended_method', 'nist')
            desc += f"\n→ Auto-selected method: {recommended.upper()}"
        
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
        
        confirm_msg = f"""FINAL CONFIRMATION REQUIRED

You are about to securely wipe:

Device: {device_name}
Path: {self.selected_device['path']}
Type: {device_type}
Size: {self.selected_device['size']}
Method: {method_display}

⚠️  THIS WILL PERMANENTLY DESTROY ALL DATA ON THE DEVICE!
⚠️  This action CANNOT be undone!
⚠️  Data recovery will be IMPOSSIBLE after completion!

To confirm this irreversible action, type exactly: WIPE {device_name}"""
        
        expected_confirmation = f"WIPE {device_name}"
        confirmation = tk.simpledialog.askstring("⚠️ DESTRUCTIVE OPERATION CONFIRMATION ⚠️", 
                                                confirm_msg, show='*')
        
        if confirmation != expected_confirmation:
            messagebox.showinfo("Operation Cancelled", "Wipe operation cancelled - confirmation text did not match.")
            return
        
        # Final safety check
        final_check = messagebox.askyesno("⚠️ LAST CHANCE ⚠️", 
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
            # Defensive checks for device selection
            if not isinstance(self.selected_device, dict):
                self.logger.error(f"selected_device is not a dict: {self.selected_device}")
                raise ValueError("No valid device selected")
            device_path = self.selected_device.get('path')
            if not device_path:
                self.logger.error(f"selected_device missing 'path': {self.selected_device}")
                raise ValueError("Invalid device: no path specified")
            self.logger.info(f"Wipe started for device: {self.selected_device}")
            # Setup progress callback
            def progress_callback(percent, message=""):
                self.root.after(0, lambda: self._update_progress(percent, message))
            
            # Perform the wipe operation
            cert_id = self.wiper.wipe_device(
                device_path=device_path, 
                method=method, 
                device_info=self.selected_device,
                progress_callback=progress_callback
            )
            
            # Handle success
            self.root.after(0, lambda: self._wipe_complete(cert_id, method))
        
        except Exception as e:
            error_message = str(e)
            self.logger.error(f"Wipe failed: {error_message}")
            self.root.after(0, lambda: self._wipe_failed(error_message))
    
    def _update_progress(self, percent, message):
        """Update progress bar and message"""
        self.progress['value'] = percent
        self.progress_label.config(text=message)
        self.root.update_idletasks()
    
    def _wipe_complete(self, cert_id, method):
        """Handle successful wipe completion"""
        self.progress['value'] = 100
        self.progress_label.config(text="✓ Secure wipe completed successfully!")
        
        # Re-enable UI
        self._enable_ui()
        
        method_name = method.replace('_', ' ').title()
        device_type = "SSD" if self.selected_device.get('is_ssd', False) else "HDD"
        
        success_msg = f"""✅ SECURE WIPE COMPLETED SUCCESSFULLY!

Device: {self.selected_device['name']}
Type: {device_type}
Method: {method_name}
Certificate ID: {cert_id}

📁 Certificates Location: ./certificates/

🛡️ Your wipe certificates include:
✓ Cryptographic proof of secure erasure
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
        self.progress_label.config(text="❌ Wipe failed!")
        
        # Re-enable UI
        self._enable_ui()
        
        # Show error message
        messagebox.showerror("Wipe Failed", 
                          f"The secure wipe operation failed:\n\n{error_msg}\n\n"
                          "Please check the logs for more details.")
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
            filetypes=[("JSON certificates", "*.json"), ("All files", "*.*")],
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

    def print_hpa_dco_summary(self):
        """Print the number and paths of detected HPA and DCO areas"""
        hpa_count = 0
        dco_count = 0
        hpa_paths = []
        dco_paths = []
        devices = self.detector.get_all_devices()
        for device in devices:
            has_hpa, native_max, current_max = self.detector.detect_hpa(device['path'])
            has_dco, dco_info = self.detector.detect_dco(device['path'])
            if has_hpa:
                hpa_count += 1
                hpa_paths.append(device['path'])
            if has_dco:
                dco_count += 1
                dco_paths.append(device['path'])
        print(f"HPA areas detected: {hpa_count}")
        for path in hpa_paths:
            print(f"  HPA path: {path}")
        print(f"DCO areas detected: {dco_count}")
        for path in dco_paths:
            print(f"  DCO path: {path}")
