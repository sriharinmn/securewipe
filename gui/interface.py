
import tkinter as tk
from tkinter import simpledialog
from tkinter import ttk, messagebox, filedialog
import threading
import logging
from core.detector import DeviceDetector
from core.wiper import DataWiper
from core.certificate import CertificateGenerator

class SecureWiperGUI:
    """GUI interface for the secure data wiper"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Secure Data Wiper v1.0")
        self.root.geometry("800x600")
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
        """Setup the user interface"""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W + tk.E + tk.N + tk.S))
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="Secure Data Wiper", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Device selection
        ttk.Label(main_frame, text="Select Device:").grid(row=1, column=0, sticky=tk.W, pady=5)
        
        self.device_var = tk.StringVar()
        self.device_combo = ttk.Combobox(main_frame, textvariable=self.device_var, 
                                       state="readonly", width=50)
        self.device_combo.grid(row=1, column=1, sticky=(tk.W + tk.E), pady=5, padx=(5, 0))
        
        refresh_btn = ttk.Button(main_frame, text="Refresh", command=self.refresh_devices)
        refresh_btn.grid(row=1, column=2, pady=5, padx=(5, 0))
        
        # Wipe method selection
        ttk.Label(main_frame, text="Wipe Method:").grid(row=2, column=0, sticky=tk.W, pady=5)
        
        self.method_var = tk.StringVar(value="nist")
        method_frame = ttk.Frame(main_frame)
        method_frame.grid(row=2, column=1, sticky=tk.W, pady=5, padx=(5, 0))
        
        ttk.Radiobutton(method_frame, text="NIST SP 800-88 (Recommended)", 
                       variable=self.method_var, value="nist").pack(side=tk.LEFT)
        ttk.Radiobutton(method_frame, text="DoD 5220.22-M", 
                       variable=self.method_var, value="dod").pack(side=tk.LEFT, padx=(20, 0))
        
        # Device information
        info_frame = ttk.LabelFrame(main_frame, text="Device Information", padding="10")
        info_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W + tk.E + tk.N + tk.S), pady=10)
        info_frame.columnconfigure(1, weight=1)
        
        self.info_text = tk.Text(info_frame, height=8, state=tk.DISABLED)
        info_scrollbar = ttk.Scrollbar(info_frame, orient=tk.VERTICAL, command=self.info_text.yview)
        self.info_text.configure(yscrollcommand=info_scrollbar.set)
        
        self.info_text.grid(row=0, column=0, columnspan=2, sticky=(tk.W + tk.E + tk.N + tk.S))
        info_scrollbar.grid(row=0, column=2, sticky=(tk.N + tk.S))
        
        # Progress section
        progress_frame = ttk.LabelFrame(main_frame, text="Progress", padding="10")
        progress_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W + tk.E), pady=10)
        progress_frame.columnconfigure(0, weight=1)
        
        self.progress = ttk.Progressbar(progress_frame, length=400, mode='determinate')
        self.progress.grid(row=0, column=0, sticky=(tk.W + tk.E), pady=5)
        
        self.progress_label = ttk.Label(progress_frame, text="Ready to start wiping")
        self.progress_label.grid(row=1, column=0, pady=5)
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=5, column=0, columnspan=3, pady=20)
        
        self.wipe_btn = ttk.Button(button_frame, text="Start Secure Wipe", 
                                 command=self.start_wipe, style="Accent.TButton")
        self.wipe_btn.pack(side=tk.LEFT, padx=5)
        
        self.verify_btn = ttk.Button(button_frame, text="Verify Certificate", 
                                   command=self.verify_certificate)
        self.verify_btn.pack(side=tk.LEFT, padx=5)
        
        self.quit_btn = ttk.Button(button_frame, text="Quit", command=self.root.quit)
        self.quit_btn.pack(side=tk.LEFT, padx=5)
        
        # Bind device selection
        self.device_combo.bind('<<ComboboxSelected>>', self.on_device_selected)
    
    def refresh_devices(self):
        """Refresh the list of available devices"""
        try:
            devices = self.detector.get_all_devices()
            device_list = []
            self.device_data = {}
            
            for device in devices:
                display_name = f"{device['name']} - {device['model']} ({device['size']})"
                device_list.append(display_name)
                self.device_data[display_name] = device
            
            self.device_combo['values'] = device_list
            if device_list:
                self.device_combo.current(0)
                self.on_device_selected(None)
        
        except Exception as e:
            self.logger.error(f"Failed to refresh devices: {e}")
            messagebox.showerror("Error", f"Failed to detect devices: {e}")
    
    def on_device_selected(self, event):
        """Handle device selection"""
        selected = self.device_var.get()
        if selected in self.device_data:
            device = self.device_data[selected]
            self.selected_device = device
            
            # Update device info display
            self.info_text.config(state=tk.NORMAL)
            self.info_text.delete(1.0, tk.END)
            
            info_text = f"""Device Path: {device['path']}
Name: {device['name']}
Model: {device['model']}
Size: {device['size']}
Type: {device['type']}
Mounted: {'Yes' if device.get('mounted', False) else 'No'}

⚠️  WARNING: This operation will PERMANENTLY DESTROY all data on this device!
⚠️  Make sure you have selected the correct device before proceeding.
⚠️  This action cannot be undone!

Selected Method: {self.method_var.get().upper()}
Standards Compliance: {'NIST SP 800-88 Rev. 1' if self.method_var.get() == 'nist' else 'DoD 5220.22-M'}
"""
            
            self.info_text.insert(1.0, info_text)
            self.info_text.config(state=tk.DISABLED)
            
            # Check if device is safe to wipe
            safe, reason = self.detector.is_device_safe_to_wipe(device['path'])
            if not safe:
                self.wipe_btn.config(state=tk.DISABLED)
                messagebox.showwarning("Device Warning", f"Cannot wipe this device: {reason}")
            else:
                self.wipe_btn.config(state=tk.NORMAL)
    
    def start_wipe(self):
        """Start the wiping process"""
        if not self.selected_device:
            messagebox.showerror("Error", "Please select a device first")
            return
        
        # Final confirmation
        device_name = self.selected_device['name']
        method = self.method_var.get().upper()
        
        confirm_msg = f"""Are you absolutely sure you want to securely wipe:

Device: {device_name}
Path: {self.selected_device['path']}
Method: {method}

THIS WILL PERMANENTLY DESTROY ALL DATA ON THE DEVICE!
This action cannot be undone!

Type 'WIPE' to confirm:"""
        
        confirmation = simpledialog.askstring("Final Confirmation", confirm_msg)
        if confirmation != "WIPE":
            return
        
        # Disable UI during wipe
        self.wipe_btn.config(state=tk.DISABLED)
        self.device_combo.config(state=tk.DISABLED)
        
        # Start wipe in separate thread
        self.wipe_thread = threading.Thread(target=self._perform_wipe)
        self.wipe_thread.daemon = True
        self.wipe_thread.start()
    
    def _perform_wipe(self):
        """Perform the actual wipe operation"""
        try:
            def progress_callback(percent, message):
                self.root.after(0, lambda: self._update_progress(percent, message))
            
            if not self.selected_device:
                messagebox.showerror("Error", "No device selected. Please choose a device first.")
                return  # Exit early, don't try to wipe anything


            device_path = self.selected_device['path']
            method = self.method_var.get()
            
            cert_id = self.wiper.wipe_device(device_path, method, progress_callback)
            
            # Success
            self.root.after(0, lambda: self._wipe_complete(cert_id))
        
        except Exception as e:
            self.logger.error(f"Wipe failed: {e}")
            self.root.after(0, lambda: self._wipe_failed(str(e)))
    
    def _update_progress(self, percent, message):
        """Update progress bar and message"""
        self.progress['value'] = percent
        self.progress_label.config(text=message)
        self.root.update_idletasks()
    
    def _wipe_complete(self, cert_id):
        """Handle successful wipe completion"""
        self.progress['value'] = 100
        self.progress_label.config(text="Wipe completed successfully!")
        
        # Re-enable UI
        self.wipe_btn.config(state=tk.NORMAL)
        self.device_combo.config(state="readonly")
        
        success_msg = f"""Secure wipe completed successfully!

Certificate ID: {cert_id}
Certificates saved in: ./certificates/

Your wipe certificates (PDF and JSON) have been generated with:
✓ Cryptographic proof of secure erasure
✓ Tamper-proof digital signatures  
✓ Full compliance verification
✓ Third-party verification support

Keep these certificates as proof of secure data destruction."""
        
        messagebox.showinfo("Wipe Complete", success_msg)
    
    def _wipe_failed(self, error_msg):
        """Handle wipe failure"""
        self.progress['value'] = 0
        self.progress_label.config(text="Wipe failed!")
        
        # Re-enable UI
        self.wipe_btn.config(state=tk.NORMAL)
        self.device_combo.config(state="readonly")
        
        messagebox.showerror("Wipe Failed", f"Secure wipe failed:\n\n{error_msg}")
    
    def verify_certificate(self):
        """Verify a certificate file"""
        cert_path = filedialog.askopenfilename(
            title="Select Certificate File",
            filetypes=[("JSON certificates", "*.json"), ("All files", "*.*")],
            initialdir="./certificates"
        )
        
        if cert_path:
            try:
                valid, message = self.cert_gen.verify_certificate(cert_path)
                if valid:
                    messagebox.showinfo("Certificate Valid", message)
                else:
                    messagebox.showerror("Certificate Invalid", message)
            except Exception as e:
                messagebox.showerror("Verification Error", f"Failed to verify certificate: {e}")
    
    def run(self):
        """Run the GUI application"""
        try:
            # Add missing import for simpledialog
            from tkinter import simpledialog

            
            
            self.root.mainloop()
        except Exception as e:
            self.logger.error(f"GUI error: {e}")
            messagebox.showerror("Application Error", f"Application error: {e}")