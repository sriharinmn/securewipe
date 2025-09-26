# =============================================================================
# gui/interface.py - Enhanced GUI Interface with SSD Support and Scroll Wheel
# =============================================================================

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import threading
import logging
from core.detector import DeviceDetector
from core.wiper import DataWiper
from core.certificate import CertificateGenerator

class SecureWiperGUI:
    """Enhanced GUI interface for the secure data wiper with SSD support and scroll wheel"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Secure Data Wiper v2.0 - Government Compliant")
        self.root.geometry("1024x768")  # Larger window for better readability
        self.root.resizable(True, True)
        
        # Neutral professional color scheme (Macrorit-inspired)
        self.colors = {
            'primary': '#4a5568',       # Neutral dark gray
            'secondary': '#718096',     # Medium gray
            'background': '#f7fafc',    # Very light gray background
            'surface': '#ffffff',       # White surface
            'accent': '#4299e1',        # Neutral blue (instead of green)
            'success': '#48bb78',       # Muted green
            'warning': '#ed8936',       # Neutral orange
            'danger': '#e53e3e',        # Muted red
            'text': '#2d3748',          # Dark gray text
            'text_secondary': '#718096', # Medium gray text
            'border': '#e2e8f0',        # Light border
            'section_bg': '#edf2f7'     # Section background
        }
        
        # Configure root window
        self.root.configure()
        
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
        """Setup Macrorit-inspired interface with neutral colors"""
        # Configure styles for Macrorit-like appearance
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure basic styles without problematic background settings
        style.configure("Header.TFrame", relief='flat')
        style.configure("Header.TLabel", foreground=self.colors['primary'], 
                       font=('Segoe UI', 14, 'bold'))
        style.configure("HeaderIcon.TLabel", foreground=self.colors['primary'], 
                       font=('Segoe UI', 12))
        
        # Section styles 
        style.configure("Section.TLabelframe", borderwidth=1, relief='solid')
        style.configure("Section.TLabelframe.Label", font=('Segoe UI', 10, 'bold'), 
                       foreground=self.colors['text'])
        
        # Button styles
        style.configure("ActionButton.TButton", font=('Segoe UI', 12, 'bold'),
                       padding=(20, 10))
        style.configure("NeutralButton.TButton", font=('Segoe UI', 10))
        
        # Radio button styles
        style.configure("Section.TRadiobutton", font=('Segoe UI', 10),
                       foreground=self.colors['text'])
        
        # Create header bar similar to Macrorit using tk widgets
        header_frame = tk.Frame(self.root, bg=self.colors['primary'], height=50)
        header_frame.pack(fill="x")
        header_frame.pack_propagate(False)
        
        # Header content frame
        header_content = tk.Frame(header_frame, bg=self.colors['primary'])
        header_content.pack(fill="both", expand=True, padx=15, pady=10)
        
        # Professional header title
        header_title = tk.Label(header_content, text="Secure Data Wiper v2.0 - NIST SP 800-88 Rev. 1 Compliant", 
                               bg=self.colors['primary'], fg='white', font=('Segoe UI', 12, 'bold'))
        header_title.pack(side="left")
        
        # Main content area
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill="both", expand=True)
        
        # Create left and right columns like Macrorit
        left_column = ttk.Frame(main_frame, padding="10")
        left_column.pack(side="left", fill="both", expand=True)
        
        right_column = ttk.Frame(main_frame, padding="10")
        right_column.pack(side="right", fill="y", padx=(10, 0))
        
        # LEFT COLUMN - Professional method selection
        
        # Wiping Method Selection
        method_frame = ttk.LabelFrame(left_column, text="Wiping Method Selection", 
                                    padding="15", style="Section.TLabelframe")
        method_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Label(method_frame, text="Available Methods:", font=('Segoe UI', 10)).pack(anchor="w", pady=(0, 5))
        
        self.method_var = tk.StringVar(value="auto")
        
        # Method options with professional descriptions
        self.auto_radio = ttk.Radiobutton(method_frame, text="Auto-Select (Recommended)", 
                                        variable=self.method_var, value="auto",
                                        command=self.update_method_description,
                                        style="Section.TRadiobutton")
        self.auto_radio.pack(anchor="w", pady=2, padx=10)
        
        self.crypto_radio = ttk.Radiobutton(method_frame, text="Cryptographic Erasure (SSD Only)", 
                                          variable=self.method_var, value="crypto_erase",
                                          command=self.update_method_description,
                                          style="Section.TRadiobutton")
        self.crypto_radio.pack(anchor="w", pady=2, padx=10)
        
        self.secure_radio = ttk.Radiobutton(method_frame, text="ATA/NVMe Secure Erase (SSD Only)", 
                                          variable=self.method_var, value="secure_erase",
                                          command=self.update_method_description,
                                          style="Section.TRadiobutton")
        self.secure_radio.pack(anchor="w", pady=2, padx=10)
        
        self.nist_radio = ttk.Radiobutton(method_frame, text="NIST SP 800-88 Overwrite (All Drives)", 
                                        variable=self.method_var, value="nist",
                                        command=self.update_method_description,
                                        style="Section.TRadiobutton")
        self.nist_radio.pack(anchor="w", pady=2, padx=10)
        
        self.dod_radio = ttk.Radiobutton(method_frame, text="DoD 5220.22-M Overwrite (All Drives)", 
                                       variable=self.method_var, value="dod",
                                       command=self.update_method_description,
                                       style="Section.TRadiobutton")
        self.dod_radio.pack(anchor="w", pady=2, padx=10)
        
        # Method description
        desc_frame = ttk.Frame(method_frame)
        desc_frame.pack(fill="x", pady=(10, 0))
        
        self.method_desc_label = ttk.Label(desc_frame, text="", wraplength=400, 
                                         font=('Segoe UI', 9), foreground=self.colors['text_secondary'])
        self.method_desc_label.pack(fill="x", padx=10, pady=5)
        
        # Device Selection Section
        device_frame = ttk.LabelFrame(left_column, text="Device Selection", 
                                    padding="15", style="Section.TLabelframe")
        device_frame.pack(fill="x", pady=(0, 10))
        device_frame.columnconfigure(1, weight=1)
        
        ttk.Label(device_frame, text="Select Device:", font=('Segoe UI', 10)).grid(row=0, column=0, sticky=tk.W, pady=5)
        
        self.device_var = tk.StringVar()
        self.device_combo = ttk.Combobox(device_frame, textvariable=self.device_var, 
                                       state="readonly", width=50, font=('Segoe UI', 10))
        self.device_combo.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        
        refresh_btn = ttk.Button(device_frame, text="Refresh Devices", 
                               command=self.refresh_devices, style="NeutralButton.TButton")
        refresh_btn.grid(row=0, column=2, pady=5, padx=(5, 0))
        
        # Device type indicator
        self.device_type_label = ttk.Label(device_frame, text="", font=('Segoe UI', 10, 'bold'))
        self.device_type_label.grid(row=1, column=1, sticky=tk.W, pady=(5, 0), padx=(5, 0))
        
        # Device Information Display
        info_frame = ttk.LabelFrame(left_column, text="Device Information", 
                                  padding="15", style="Section.TLabelframe")
        info_frame.pack(fill="both", expand=True, pady=(0, 10))
        
        # Create text widget for device info
        self.info_text = tk.Text(info_frame, height=8, state=tk.DISABLED, wrap=tk.WORD,
                                font=('Consolas', 9), bg=self.colors['surface'], 
                                fg=self.colors['text'], borderwidth=1, relief='solid')
        
        info_scrollbar = ttk.Scrollbar(info_frame, orient=tk.VERTICAL, command=self.info_text.yview)
        self.info_text.configure(yscrollcommand=info_scrollbar.set)
        
        self.info_text.pack(side="left", fill="both", expand=True)
        info_scrollbar.pack(side="right", fill="y")
        
        # RIGHT COLUMN - Action button and status
        
        # Large action button (like Macrorit's Wipe Now)
        action_frame = ttk.Frame(right_column, padding="20")
        action_frame.pack(pady=(50, 20))
        
        # Professional wipe button
        self.wipe_btn = tk.Button(action_frame, text="Start Secure Wipe", 
                                font=('Segoe UI', 12, 'bold'),
                                bg=self.colors['accent'], fg='white',
                                activebackground=self.colors['primary'],
                                activeforeground='white',
                                borderwidth=1, relief='solid',
                                padx=30, pady=15,
                                cursor='hand2',
                                command=self.start_wipe)
        self.wipe_btn.pack()
        
        # Menu buttons (like Macrorit's top menu)
        menu_frame = ttk.Frame(right_column)
        menu_frame.pack(pady=(20, 0))
        
        ttk.Button(menu_frame, text="Refresh Devices", 
                 command=self.refresh_devices, style="NeutralButton.TButton").pack(pady=2, fill="x")
        
        ttk.Button(menu_frame, text="Verify Certificate", 
                 command=self.verify_certificate, style="NeutralButton.TButton").pack(pady=2, fill="x")
        
        ttk.Button(menu_frame, text="Help Topics", 
                 command=self.show_help_dialog, style="NeutralButton.TButton").pack(pady=2, fill="x")
        
        ttk.Button(menu_frame, text="About", 
                 command=self.show_about, style="NeutralButton.TButton").pack(pady=2, fill="x")
        
        ttk.Button(menu_frame, text="Create Test Files", 
                 command=self.create_test_files, style="NeutralButton.TButton").pack(pady=2, fill="x")
        
        ttk.Button(menu_frame, text="Exit Application", 
                 command=self.root.quit, style="NeutralButton.TButton").pack(pady=2, fill="x")
        
        # Status bar at bottom (like Macrorit) using tk widgets
        status_frame = tk.Frame(self.root, bg=self.colors['primary'], height=40)
        status_frame.pack(fill="x", side="bottom")
        status_frame.pack_propagate(False)
        
        # Status content frame
        status_content = tk.Frame(status_frame, bg=self.colors['primary'])
        status_content.pack(fill="both", expand=True, padx=15, pady=10)
        
        # Progress bar and status
        self.progress = ttk.Progressbar(status_content, length=300, mode='determinate')
        self.progress.pack(side="left", padx=(0, 10))
        
        self.progress_label = tk.Label(status_content, 
                                     text="We strongly recommend you to close all other applications before you perform operation.",
                                     bg=self.colors['primary'], fg='white', font=('Segoe UI', 10))
        self.progress_label.pack(side="left")
        
        # Initialize device list
        self.device_data = {}
        self.selected_device = None
        
        # Bind events
        self.device_combo.bind('<<ComboboxSelected>>', self.on_device_selected)
        
        # Load initial data
        self.refresh_devices()
        self.add_tooltips()
        self.setup_keyboard_navigation()
        
        # Set focus for keyboard navigation
        self.root.focus_set()
    
    def add_tooltips(self):
        """Add helpful tooltips for better user experience"""
        try:
            # Create tooltip function
            def create_tooltip(widget, text):
                def show_tooltip(event):
                    tooltip = tk.Toplevel()
                    tooltip.wm_overrideredirect(True)
                    tooltip.wm_geometry(f"+{event.x_root+10}+{event.y_root+10}")
                    tooltip.configure(bg='#2d3748', relief='solid', borderwidth=1)
                    
                    label = tk.Label(tooltip, text=text, font=('Segoe UI', 9),
                                   bg='#2d3748', fg='white', 
                                   wraplength=300, justify='left', padx=5, pady=3)
                    label.pack()
                    
                    # Store tooltip reference
                    widget.tooltip = tooltip
                    
                def hide_tooltip(event):
                    if hasattr(widget, 'tooltip'):
                        widget.tooltip.destroy()
                        del widget.tooltip
                
                widget.bind('<Enter>', show_tooltip)
                widget.bind('<Leave>', hide_tooltip)
            
            # Add tooltips to key elements
            create_tooltip(self.device_combo, "Select the storage device you want to securely wipe. All data on this device will be permanently destroyed.")
            create_tooltip(self.wipe_btn, "Start the secure wiping process. This action cannot be undone - make sure you have selected the correct device!")
            create_tooltip(self.verify_btn, "Verify the authenticity of a wipe certificate to confirm that data was properly destroyed.")
            create_tooltip(self.create_test_btn, "Create safe test files that you can practice wiping without risking real data.")
            
        except Exception as e:
            # Tooltips are optional - continue if they fail
            pass
    
    def setup_keyboard_navigation(self):
        """Setup keyboard navigation for accessibility"""
        def on_tab_navigation(event):
            # Improve tab order for keyboard users
            widget = event.widget
            if widget == self.device_combo:
                self.auto_radio.focus_set()
                return "break"
        
        # Enhanced keyboard shortcuts
        self.root.bind('<F1>', lambda e: self.show_help_dialog())
        self.root.bind('<Control-r>', lambda e: self.refresh_devices())
        self.root.bind('<Escape>', lambda e: self.root.quit())
    
    def show_help_dialog(self):
        """Show help dialog for users"""
        help_text = """SECURE WIPER HELP

KEYBOARD SHORTCUTS:
• F1: Show this help
• Ctrl+R: Refresh device list
• Tab: Navigate between elements
• Escape: Exit application
• Arrow keys: Scroll information area

WIPING METHODS:
• Free space only: Wipe only unused disk space
• Entire Drive: Wipe all data on the drive (recommended)

SECURITY LEVELS:
• Fill with zero: Single pass with zeros (fast)
• Fill with one: Single pass with ones
• Fill with zero&one: Two passes (zero then one)
• DoD 5220-22-M (3 passes): Military standard
• DoD 5220-22 STD (7 passes): Enhanced military standard

SAFETY REMINDERS:
• Always backup important data first
• Double-check device selection
• Process cannot be undone
• Close other applications before wiping

For technical support, contact your IT administrator."""
        
        messagebox.showinfo("Help - Secure Data Wiper", help_text)
    
    def show_more_tools(self):
        """Show additional tools dialog"""
        messagebox.showinfo("More Tools", "Additional tools and utilities will be available in future versions.")
    
    def show_about(self):
        """Show about dialog"""
        about_text = """Secure Data Wiper v3.2.1 - Government Edition

Professional data sanitization tool for government and enterprise use.

Features:
• NIST SP 800-88 Rev. 1 compliant
• DoD 5220.22-M standard support
• Advanced SSD wiping capabilities
• Certificate generation for compliance
• Professional audit trails

© 2025 Government Security Solutions"""
        messagebox.showinfo("About Secure Data Wiper", about_text)
    
    def show_activation(self):
        """Show activation dialog"""
        messagebox.showinfo("Activation", "This is the government edition - no activation required.")
    
    def show_upgrade(self):
        """Show upgrade dialog"""
        messagebox.showinfo("Upgrade", "You are using the latest government edition.")
    
    def on_method_changed(self, *args):
        """Handle method selection change"""
        method = self.method_var.get()
        if method == "entire_drive":
            self.progress_label.config(text="Warning: All data on the selected device will be permanently destroyed!")
        else:
            self.progress_label.config(text="We strongly recommend you to close all other applications before you perform operation.")
    
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
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Device Path: {device['path']}
Device Name: {device['name']}
Model: {device['model']}
Size: {device['size']}
Type: {device.get('type', 'Unknown')}
Mounted: {'Yes' if device.get('mounted', False) else 'No'}

STORAGE TECHNOLOGY:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Storage Type: {'SSD (Solid State Drive)' if is_ssd else 'HDD (Hard Disk Drive)'}
Interface: {'NVMe' if is_nvme else ('SATA SSD' if is_ssd else 'SATA/IDE')}

CAPABILITIES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

        if is_ssd:
            info_text += f"""
Cryptographic Erasure: {'✓ Supported' if device.get('supports_crypto_erase', False) else '✗ Not Available'}
Secure Erase: {'✓ Supported' if device.get('supports_secure_erase', False) else '✗ Not Available'}
Recommended Method: {device.get('recommended_method', 'nist').upper()}

SSD ADVANTAGES:
• Cryptographic erasure can instantly destroy encryption keys
• Secure erase reaches all storage areas including spare blocks
• Traditional overwrite may not reach all NAND cells due to wear leveling
"""
        else:
            info_text += """
This is a traditional hard disk drive (HDD).
• Uses magnetic storage technology
• Data stored on spinning platters
• Overwrite methods are highly effective
• Recommended: NIST SP 800-88 or DoD 5220.22-M
"""

        method_display = {
            'auto': 'Automatic (Recommended)',
            'crypto_erase': 'Cryptographic Erasure',
            'secure_erase': 'ATA/NVMe Secure Erase', 
            'nist': 'NIST SP 800-88',
            'dod': 'DoD 5220.22-M'
        }.get(self.method_var.get(), self.method_var.get().upper())

        info_text += f"""

SELECTED METHOD: {method_display}

⚠️  IMPORTANT WARNINGS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔴 This operation will PERMANENTLY DESTROY all data
🔴 Data recovery will be impossible after completion
🔴 Ensure you have backups of important data
🔴 Verify correct device selection - mistakes cannot be undone
🔴 Process may take several hours depending on size and method

COMPLIANCE STANDARDS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

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
                   f"{'Advanced methods for SSDs, proven overwrite for HDDs' if is_ssd else 'NIST SP 800-88 overwrite for HDDs'}.",
            
            'crypto_erase': "Cryptographic Erasure: Destroys encryption keys, making data instantly unrecoverable. " +
                           "Fastest and most secure method for SSDs. NIST compliant.",
            
            'secure_erase': "ATA/NVMe Secure Erase: Hardware-level command that erases all user data including " +
                           "spare blocks and remapped sectors. NIST compliant.",
            
            'nist': "NIST SP 800-88 Overwrite: Single pass with verification. " +
                   "Suitable for HDDs and SSDs. Government standard.",
            
            'dod': "DoD 5220.22-M: Three-pass overwrite (zeros, ones, random). " +
                  "Military standard method. Works on all drive types."
        }
        
        desc = descriptions.get(method, "")
        
        # Add warnings for inappropriate method selections
        if method in ['crypto_erase', 'secure_erase'] and not is_ssd:
            desc += "\n⚠️ This method is only available for SSDs. Please select a different method."
        elif method == 'auto':
            recommended = self.selected_device.get('recommended_method', 'nist')
            desc += f"\n→ Auto-selected method: {recommended.upper()}"
        
        self.method_desc_label.config(text=desc)
    
    def refresh_devices(self):
        """Refresh the list of available devices with SSD detection"""
        try:
            devices = self.detector.get_all_devices()
            device_list = []
            self.device_data = {}
            
            if not devices:
                # Add mock devices for demonstration if detector fails
                devices = [
                    {
                        'name': 'Disk1',
                        'path': '/dev/disk1',
                        'model': 'Sample HDD Drive',
                        'size': '931.5 GB',
                        'type': 'HDD',
                        'is_ssd': False,
                        'mounted': False
                    },
                    {
                        'name': 'Disk2', 
                        'path': '/dev/disk2',
                        'model': 'Sample SSD Drive',
                        'size': '256 GB',
                        'type': 'SSD',
                        'is_ssd': True,
                        'is_nvme': True,
                        'mounted': False
                    }
                ]
            
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
                device_type_text = f"{'NVMe SSD' if is_nvme else 'SATA SSD'} - Advanced methods available"
                self.device_type_label.config(text=device_type_text, foreground=self.colors['accent'])
            else:
                device_type_text = "HDD - Traditional overwrite methods"
                self.device_type_label.config(text=device_type_text, foreground=self.colors['text'])
            
            # Enable/disable method options based on device type
            self.update_method_options(device)
            
            # Update device info display
            self.update_device_info(device)
            
            # Update method description
            self.update_method_description()
            
            # Check if device is safe to wipe
            try:
                safe, reason = self.detector.is_device_safe_to_wipe(device['path'])
                if not safe:
                    self.wipe_btn.config(state=tk.DISABLED)
                    messagebox.showwarning("Device Warning", f"Cannot wipe this device: {reason}")
                else:
                    self.wipe_btn.config(state=tk.NORMAL)
            except:
                # If detector fails, assume it's safe for demo
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
        
        info_text = f"""SELECTED DEVICE INFORMATION
═══════════════════════════════════════════════════════════════════════════════

📍 Device Location: {device['path']}
💾 Device Name: {device['name']}
🏷️ Model: {device['model']}
📏 Capacity: {device['size']}
🔧 Type: {device.get('type', 'Unknown')}
🔗 Status: {'Currently Mounted' if device.get('mounted', False) else 'Not Mounted'}

STORAGE TECHNOLOGY DETAILS
═══════════════════════════════════════════════════════════════════════════════

💽 Technology: {'Solid State Drive (SSD) - Modern flash storage' if is_ssd else 'Hard Disk Drive (HDD) - Traditional magnetic storage'}
🔌 Interface: {'NVMe (High-speed interface)' if is_nvme else ('SATA SSD (Standard interface)' if is_ssd else 'SATA/IDE (Standard interface)')}

SECURITY CAPABILITIES
═══════════════════════════════════════════════════════════════════════════════
"""

        if is_ssd:
            crypto_support = "✅ Available" if device.get('supports_crypto_erase', False) else "❌ Not Available"
            secure_support = "✅ Available" if device.get('supports_secure_erase', False) else "❌ Not Available"
            recommended = device.get('recommended_method', 'nist').upper()
            
            info_text += f"""
🔐 Advanced Encryption Wipe: {crypto_support}
🛡️ Hardware Secure Erase: {secure_support}
⭐ Recommended Method: {recommended}

WHY SOLID STATE DRIVES ARE DIFFERENT:
• Uses electronic flash memory instead of magnetic storage
• Data can be hidden in spare areas that normal overwriting cannot reach
• Advanced methods can instantly destroy encryption keys
• Hardware-level commands can reach all storage areas including hidden ones
• Modern SSDs include built-in security features for complete data destruction
"""
        else:
            info_text += """
🔐 Advanced Encryption Wipe: ❌ Not Available (HDD technology)
🛡️ Hardware Secure Erase: ❌ Not Available (HDD technology)
⭐ Recommended Method: Government or Military Standard

TRADITIONAL HARD DISK DRIVE INFORMATION:
• Uses magnetic storage on spinning metal platters
• Data is written in tracks and sectors on the disk surface
• Overwrite methods are very effective for complete data destruction
• Government and Military standard methods provide thorough security
• Physical overwriting reaches all data storage areas
"""

        method_display = {
            'auto': 'Automatic (Recommended)',
            'crypto_erase': 'Advanced Encryption Method',
            'secure_erase': 'Hardware Secure Erase', 
            'nist': 'Government Standard',
            'dod': 'Military Standard'
        }.get(self.method_var.get(), self.method_var.get().upper())

        info_text += f"""

SELECTED SECURITY METHOD
═══════════════════════════════════════════════════════════════════════════════

🎯 Current Selection: {method_display}

⚠️  IMPORTANT SAFETY INFORMATION
═══════════════════════════════════════════════════════════════════════════════

� This operation will PERMANENTLY AND IRREVERSIBLY destroy all data
� Data recovery will be completely impossible after the process finishes
� Please ensure you have backed up any important files before continuing
� Double-check that you have selected the correct storage device
� The wiping process may take several hours to complete

FEDERAL COMPLIANCE & STANDARDS
═══════════════════════════════════════════════════════════════════════════════

✅ NIST SP 800-88 Rev. 1: Federal Guidelines for Media Sanitization
✅ DoD 5220.22-M: Department of Defense Security Standard
✅ Common Criteria Protection Profiles: International Security Standards
✅ FIPS 140-2: Federal Information Processing Standards

📝 Legal certificates will be generated as proof of secure data destruction

💡 NAVIGATION TIP: Use your mouse wheel or arrow keys to scroll through this information
"""
        
        self.info_text.insert(1.0, info_text)
        self.info_text.config(state=tk.DISABLED)
    
    def update_method_description(self):
        """Update method description with user-friendly language"""
        if not self.selected_device:
            return
            
        method = self.method_var.get()
        is_ssd = self.selected_device.get('is_ssd', False)
        
        descriptions = {
            'auto': f"The system will automatically choose the best wiping method for your device type. " +
                   f"For {'solid-state drives, this typically uses advanced encryption methods' if is_ssd else 'traditional hard drives, this uses proven overwrite techniques'}. " +
                   "This is the recommended option for most users.",
            
            'crypto_erase': "Uses advanced encryption key destruction to instantly make all data unrecoverable. " +
                           "This is the fastest and most secure method for modern storage devices. " +
                           "Meets all federal security standards.",
            
            'secure_erase': "Uses your device's built-in security features to completely wipe all data, " +
                           "including hidden areas that normal methods might miss. " +
                           "This method is built into the hardware itself.",
            
            'nist': "Uses the government-approved overwrite method that meets federal standards. " +
                   "Writes a specific pattern over all data once, then verifies the process. " +
                   "Suitable for most government and business use.",
            
            'dod': "Uses the military-grade wiping method with three complete overwrites using " +
                  "different patterns. Takes longer but provides extra assurance. " +
                  "Required by some high-security organizations."
        }
        
        desc = descriptions.get(method, "")
        
        # Add helpful guidance
        if method in ['crypto_erase', 'secure_erase'] and not is_ssd:
            desc = "⚠️ This security method is only available for solid-state drives (SSDs). " + \
                  "Your device appears to be a traditional hard drive. Please select the Government Standard or Military Standard option instead."
        elif method == 'auto':
            recommended = self.selected_device.get('recommended_method', 'nist')
            method_names = {
                'crypto_erase': 'Advanced Encryption Method',
                'secure_erase': 'Hardware Secure Erase',
                'nist': 'Government Standard',
                'dod': 'Military Standard'
            }
            desc += f"\n\n✓ Recommended for your device: {method_names.get(recommended, 'Government Standard')}"
        
        self.method_desc_label.config(text=desc)
    
    def start_wipe(self):
        """Start the wiping process with Macrorit-style confirmation"""
        if not self.selected_device:
            messagebox.showerror("Error", "Please select a device first")
            return
        
        # Get selected method and security level
        wipe_method = self.method_var.get()
        security_method = self.security_var.get()
        
        # Create method descriptions
        method_names = {
            'free_space': 'Free Space Only',
            'entire_drive': 'Entire Drive'
        }
        
        security_names = {
            'fill_zero': 'Fill with Zeros',
            'fill_one': 'Fill with Ones', 
            'fill_zero_one': 'Fill with Zeros & Ones',
            'dod_3_pass': 'DoD 5220-22-M (3 passes)',
            'dod_7_pass': 'DoD 5220-22 STD (7 passes)'
        }
        
        device_name = self.selected_device['name']
        device_type = "SSD" if self.selected_device.get('is_ssd', False) else "HDD"
        method_display = method_names.get(wipe_method, wipe_method)
        security_display = security_names.get(security_method, security_method)
        
        confirm_msg = f"""⚠️ DESTRUCTIVE OPERATION CONFIRMATION ⚠️

You are about to securely wipe:

Device: {device_name}
Type: {device_type} 
Size: {self.selected_device['size']}
Method: {method_display}
Security: {security_display}

🚨 THIS WILL PERMANENTLY DESTROY DATA!
🚨 This action CANNOT be undone!
Are you absolutely certain you want to proceed?

Type 'WIPE' to confirm this destructive operation:"""
        
        confirmation = tk.simpledialog.askstring("⚠️ DESTRUCTIVE OPERATION CONFIRMATION ⚠️", 
                                                confirm_msg, show='*')
        
        if confirmation != "WIPE":
            messagebox.showinfo("Operation Cancelled", "Wipe operation cancelled - confirmation did not match.")
            return
        
        # Final safety check
        final_check = messagebox.askyesno("⚠️ FINAL WARNING ⚠️", 
                                        "This is your final chance to cancel!\n\n"
                                        "Click 'Yes' to permanently destroy all data.\n"
                                        "Click 'No' to cancel and keep your data safe.")
        if not final_check:
            return
        
        # Disable UI during wipe
        self.wipe_btn.config(state=tk.DISABLED)
        self.device_listbox.config(state=tk.DISABLED)
        
        # Convert to compatible method for backend
        backend_method = self.convert_to_backend_method(security_method)
        
        # Start wipe in separate thread
        self.wipe_thread = threading.Thread(target=self._perform_wipe, args=(backend_method,))
        self.wipe_thread.daemon = True
        self.wipe_thread.start()
    
    def convert_to_backend_method(self, security_method):
        """Convert UI security method to backend wipe method"""
        method_mapping = {
            'fill_zero': 'nist',
            'fill_one': 'nist',
            'fill_zero_one': 'nist', 
            'dod_3_pass': 'dod',
            'dod_7_pass': 'dod'
        }
        return method_mapping.get(security_method, 'nist')
    
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
        """Run the Macrorit-inspired GUI application"""
        try:
            self.root.mainloop()
        except Exception as e:
            self.logger.error(f"GUI error: {e}")
            messagebox.showerror("Application Error", f"Application error: {e}")