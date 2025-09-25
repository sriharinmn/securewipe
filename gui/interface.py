# =============================================================================
# gui/interface.py - Enhanced GUI Interface with SSD Support and Scroll Wheel
# =============================================================================

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import logging
from core.detector import DeviceDetector
from core.wiper import DataWiper
from core.certificate import CertificateGenerator

class SecureWiperGUI:
    """Enhanced GUI interface for the secure data wiper with SSD support and scroll wheel"""
    
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
        self.setup_scroll_bindings()
        self.refresh_devices()
    
    def setup_scroll_bindings(self):
        """Setup mouse wheel scrolling for the entire interface"""
        def _on_mousewheel(event):
            # Determine which widget should receive the scroll event
            widget = event.widget
            
            # Find the closest scrollable parent
            scrollable_widget = self._find_scrollable_parent(widget)
            
            if scrollable_widget:
                if hasattr(scrollable_widget, 'yview_scroll'):
                    # For Text widgets and other scrollable widgets
                    scrollable_widget.yview_scroll(int(-1 * (event.delta / 120)), "units")
                elif hasattr(scrollable_widget, 'yview'):
                    # For other widgets with yview
                    scrollable_widget.yview_scroll(int(-1 * (event.delta / 120)), "units")
        
        def _bind_mousewheel(widget):
            """Recursively bind mousewheel to widget and all children"""
            widget.bind("<MouseWheel>", _on_mousewheel)  # Windows
            widget.bind("<Button-4>", lambda e: _on_mousewheel(self._create_wheel_event(e, 120)))  # Linux scroll up
            widget.bind("<Button-5>", lambda e: _on_mousewheel(self._create_wheel_event(e, -120)))  # Linux scroll down
            
            # Bind to all children
            for child in widget.winfo_children():
                _bind_mousewheel(child)
        
        # Bind mousewheel to root and all widgets
        _bind_mousewheel(self.root)
    
    def _create_wheel_event(self, event, delta):
        """Create a wheel event with delta for Linux compatibility"""
        class WheelEvent:
            def __init__(self, widget, delta):
                self.widget = widget
                self.delta = delta
        return WheelEvent(event.widget, delta)
    
    def _find_scrollable_parent(self, widget):
        """Find the closest scrollable parent widget"""
        current = widget
        
        # Check if current widget is scrollable
        while current:
            if isinstance(current, tk.Text) and current == self.info_text:
                return current
            elif hasattr(current, 'yview') and hasattr(current, 'yview_scroll'):
                return current
            
            try:
                current = current.master
            except:
                break
        
        # Default to info_text if no specific scrollable widget found
        return self.info_text if hasattr(self, 'info_text') else None
    
    def setup_ui(self):
        """Setup the enhanced user interface with SSD support"""
        # Configure styles
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("SSD.TLabel", foreground="blue", font=('Arial', 9, 'bold'))
        style.configure("HDD.TLabel", foreground="black", font=('Arial', 9))
        style.configure("Warning.TLabel", foreground="red", font=('Arial', 9, 'bold'))
        
        # Main container with scrollable frame
        self.canvas = tk.Canvas(self.root)
        self.scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)
        
        # Configure canvas scrolling
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        # Pack canvas and scrollbar
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        
        # Main frame inside scrollable area
        main_frame = ttk.Frame(self.scrollable_frame, padding="10")
        main_frame.pack(fill="both", expand=True)
        
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
        
        # Device information with enhanced SSD details and improved scrolling
        info_frame = ttk.LabelFrame(main_frame, text="Device Information & Capabilities", padding="10")
        info_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        info_frame.columnconfigure(0, weight=1)
        info_frame.rowconfigure(0, weight=1)
        
        # Create text widget with scrollbar
        text_frame = ttk.Frame(info_frame)
        text_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        text_frame.columnconfigure(0, weight=1)
        text_frame.rowconfigure(0, weight=1)
        
        self.info_text = tk.Text(text_frame, height=12, state=tk.DISABLED, wrap=tk.WORD,
                                font=('Consolas', 9), bg='#f8f9fa', fg='#333333')
        info_scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=self.info_text.yview)
        self.info_text.configure(yscrollcommand=info_scrollbar.set)
        
        self.info_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        info_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Enhanced mouse wheel binding for info text
        def _on_info_text_mousewheel(event):
            self.info_text.yview_scroll(int(-1 * (event.delta / 120)), "units")
            return "break"  # Prevent event propagation
        
        self.info_text.bind("<MouseWheel>", _on_info_text_mousewheel)
        self.info_text.bind("<Button-4>", lambda e: _on_info_text_mousewheel(self._create_wheel_event(e, 120)))
        self.info_text.bind("<Button-5>", lambda e: _on_info_text_mousewheel(self._create_wheel_event(e, -120)))
        
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
        
        # Add scroll wheel support to canvas
        def _on_canvas_mousewheel(event):
            self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        
        self.canvas.bind("<MouseWheel>", _on_canvas_mousewheel)
        self.canvas.bind("<Button-4>", lambda e: _on_canvas_mousewheel(self._create_wheel_event(e, 120)))
        self.canvas.bind("<Button-5>", lambda e: _on_canvas_mousewheel(self._create_wheel_event(e, -120)))
        
        # Allow canvas to receive focus for scrolling
        self.canvas.focus_set()
    
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
        """Handle device selection with enhanced SSD information"""
        selected = self.device_var.get()
        if selected in self.device_data:
            device = self.device_data[selected]
            self.selected_device = device
            
            is_ssd = device.get('is_ssd', False)
            is_nvme = device.get('is_nvme', False)
            
            # Update device type indicator
            if is_ssd:
                device_type_text = f"{'NVMe SSD' if is_nvme else 'SATA SSD'} - Optimized methods available"
                self.device_type_label.config(text=device_type_text, style="SSD.TLabel")
            else:
                self.device_type_label.config(text="HDD - Traditional overwrite methods", style="HDD.TLabel")
            
            # Enable/disable method options based on device type
            self.update_method_options(device)
            
            # Update device info display with enhanced SSD details
            self.update_device_info(device)
            
            # Update method description
            self.update_method_description()
            
            # Check if device is safe to wipe
            safe, reason = self.detector.is_device_safe_to_wipe(device['path'])
            if not safe:
                self.wipe_btn.config(state=tk.DISABLED)
                messagebox.showwarning("Device Warning", f"Cannot wipe this device: {reason}")
            else:
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
        """Update device information display with SSD capabilities"""
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

💡 TIP: Use mouse wheel to scroll through this information area
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
            self.logger.error(f"Wipe failed: {e}")
            self.root.after(0, lambda: self._wipe_failed(str(e)))
    
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
        """Run the GUI application with enhanced scroll support"""
        try:
            # Add missing import for simpledialog
            import tkinter.simpledialog
            tk.simpledialog = tkinter.simpledialog
            
            # Set up additional keyboard shortcuts for scrolling
            def on_key_press(event):
                if event.keysym == 'Up':
                    self.canvas.yview_scroll(-1, "units")
                elif event.keysym == 'Down':
                    self.canvas.yview_scroll(1, "units")
                elif event.keysym == 'Prior':  # Page Up
                    self.canvas.yview_scroll(-10, "units")
                elif event.keysym == 'Next':   # Page Down
                    self.canvas.yview_scroll(10, "units")
                elif event.keysym == 'Home':
                    self.canvas.yview_moveto(0)
                elif event.keysym == 'End':
                    self.canvas.yview_moveto(1)
            
            self.root.bind('<Key>', on_key_press)
            
            # Update scroll region when window is resized
            def on_frame_configure(event):
                self.canvas.configure(scrollregion=self.canvas.bbox("all"))
            
            self.scrollable_frame.bind('<Configure>', on_frame_configure)
            
            # Make sure canvas can receive keyboard focus
            self.root.focus_set()
            
            self.root.mainloop()
            
        except Exception as e:
            self.logger.error(f"GUI error: {e}")
            messagebox.showerror("Application Error", f"Application error: {e}")