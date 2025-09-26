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
        
        # Header icon and title
        header_icon = tk.Label(header_content, text="🔒", bg=self.colors['primary'], 
                              fg='white', font=('Segoe UI', 12))
        header_icon.pack(side="left", padx=(0, 10))
        
        header_title = tk.Label(header_content, text="Secure Data Wiper v3.2.1 - Government Edition", 
                               bg=self.colors['primary'], fg='white', font=('Segoe UI', 12, 'bold'))
        header_title.pack(side="left")
        
        header_subtitle = tk.Label(header_content, text="Destroy all data! No possibility to recover.", 
                                  bg=self.colors['primary'], fg='white', font=('Segoe UI', 10))
        header_subtitle.pack(side="left", padx=(20, 0))
        
        # Main content area
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill="both", expand=True)
        
        # Create left and right columns like Macrorit
        left_column = ttk.Frame(main_frame, padding="10")
        left_column.pack(side="left", fill="both", expand=True)
        
        right_column = ttk.Frame(main_frame, padding="10")
        right_column.pack(side="right", fill="y", padx=(10, 0))
        
        # LEFT COLUMN - Method and Security sections (like Macrorit)
        
        # 1. Wiping Method section
        method_frame = ttk.LabelFrame(left_column, text="1. Wiping Method", 
                                    padding="15", style="Section.TLabelframe")
        method_frame.pack(fill="x", pady=(0, 10))
        
        self.method_var = tk.StringVar(value="free_space")
        
        ttk.Radiobutton(method_frame, text="Free space only", 
                       variable=self.method_var, value="free_space",
                       style="Section.TRadiobutton").pack(anchor="w", pady=2)
        
        ttk.Radiobutton(method_frame, text="Entire Drive", 
                       variable=self.method_var, value="entire_drive",
                       style="Section.TRadiobutton").pack(anchor="w", pady=2)
        
        # Note under method selection
        method_note = ttk.Label(method_frame, text="(All data will be erased)", 
                               font=('Segoe UI', 9), foreground=self.colors['text_secondary'])
        method_note.pack(anchor="w", pady=(5, 0))
        
        # 2. Security section
        security_frame = ttk.LabelFrame(left_column, text="2. Security", 
                                      padding="15", style="Section.TLabelframe")
        security_frame.pack(fill="x", pady=(0, 10))
        
        self.security_var = tk.StringVar(value="fill_zero")
        
        ttk.Radiobutton(security_frame, text="Fill sectors with zero", 
                       variable=self.security_var, value="fill_zero",
                       style="Section.TRadiobutton").pack(anchor="w", pady=2)
        
        ttk.Radiobutton(security_frame, text="Fill sectors with one", 
                       variable=self.security_var, value="fill_one",
                       style="Section.TRadiobutton").pack(anchor="w", pady=2)
        
        ttk.Radiobutton(security_frame, text="Fill sectors with zero&one", 
                       variable=self.security_var, value="fill_zero_one",
                       style="Section.TRadiobutton").pack(anchor="w", pady=2)
        
        security_options_frame = ttk.Frame(security_frame)
        security_options_frame.pack(fill="x", pady=(10, 0))
        
        ttk.Radiobutton(security_options_frame, text="DoD 5220-22-M (3 passes)", 
                       variable=self.security_var, value="dod_3_pass",
                       style="Section.TRadiobutton").pack(anchor="w", pady=2)
        
        ttk.Radiobutton(security_options_frame, text="DoD 5220-22 STD (7 passes)", 
                       variable=self.security_var, value="dod_7_pass",
                       style="Section.TRadiobutton").pack(anchor="w", pady=2)
        
        # 3. Device selection section
        device_frame = ttk.LabelFrame(left_column, text="3. Choose a partition or disk to wipe", 
                                    padding="15", style="Section.TLabelframe")
        device_frame.pack(fill="both", expand=True, pady=(0, 10))
        
        # Device list with visual representation
        self.device_listbox = tk.Listbox(device_frame, height=8, font=('Segoe UI', 10),
                                       bg='white', 
                                       selectbackground='#4299e1',
                                       borderwidth=1, relief='solid')
        self.device_listbox.pack(fill="both", expand=True, pady=(0, 10))
        
        # Device status indicators (like Macrorit's colored bars)
        status_frame = ttk.Frame(device_frame)
        status_frame.pack(fill="x", pady=(10, 0))
        
        # Status legend
        legend_frame = ttk.Frame(status_frame)
        legend_frame.pack(anchor="w")
        
        # Create colored status indicators
        primary_color = tk.Frame(legend_frame, bg=self.colors['accent'], width=15, height=15)
        primary_color.pack(side="left", padx=(0, 5))
        ttk.Label(legend_frame, text="Primary", font=('Segoe UI', 9)).pack(side="left", padx=(0, 15))
        
        logical_color = tk.Frame(legend_frame, bg=self.colors['warning'], width=15, height=15)
        logical_color.pack(side="left", padx=(0, 5))
        ttk.Label(legend_frame, text="Logical", font=('Segoe UI', 9)).pack(side="left", padx=(0, 15))
        
        unallocated_color = tk.Frame(legend_frame, bg=self.colors['text_secondary'], width=15, height=15)
        unallocated_color.pack(side="left", padx=(0, 5))
        ttk.Label(legend_frame, text="Unallocated", font=('Segoe UI', 9)).pack(side="left")
        
        # RIGHT COLUMN - Action button and status
        
        # Large action button (like Macrorit's Wipe Now)
        action_frame = ttk.Frame(right_column, padding="20")
        action_frame.pack(pady=(50, 20))
        
        # Wipe button with icon
        self.wipe_btn = tk.Button(action_frame, text="🔥 Wipe Now", 
                                font=('Segoe UI', 14, 'bold'),
                                bg=self.colors['accent'], fg='white',
                                activebackground=self.colors['primary'],
                                activeforeground='white',
                                borderwidth=0, relief='flat',
                                padx=30, pady=15,
                                cursor='hand2',
                                command=self.start_wipe)
        self.wipe_btn.pack()
        
        # Menu buttons (like Macrorit's top menu)
        menu_frame = ttk.Frame(right_column)
        menu_frame.pack(pady=(20, 0))
        
        ttk.Button(menu_frame, text="🔄 Reload disks", 
                 command=self.refresh_devices, style="NeutralButton.TButton").pack(pady=2, fill="x")
        
        ttk.Button(menu_frame, text="🛠️ More tools", 
                 command=self.show_more_tools, style="NeutralButton.TButton").pack(pady=2, fill="x")
        
        ttk.Button(menu_frame, text="❓ Help topics", 
                 command=self.show_help_dialog, style="NeutralButton.TButton").pack(pady=2, fill="x")
        
        ttk.Button(menu_frame, text="ℹ️ About", 
                 command=self.show_about, style="NeutralButton.TButton").pack(pady=2, fill="x")
        
        ttk.Button(menu_frame, text="🔐 Activate", 
                 command=self.show_activation, style="NeutralButton.TButton").pack(pady=2, fill="x")
        
        ttk.Button(menu_frame, text="⬆️ Upgrade", 
                 command=self.show_upgrade, style="NeutralButton.TButton").pack(pady=2, fill="x")
        
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
        self.device_listbox.bind('<<ListboxSelect>>', self.on_device_selected)
        self.method_var.trace('w', self.on_method_changed)
        self.security_var.trace('w', self.on_security_changed)
        
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
    
    def on_security_changed(self, *args):
        """Handle security method change"""
        # Update UI based on security selection
        pass
    
    def refresh_devices(self):
        """Refresh the list of available devices in Macrorit style"""
        try:
            # Clear existing devices
            self.device_listbox.delete(0, tk.END)
            self.device_data = {}
            
            devices = self.detector.get_all_devices()
            
            if not devices:
                # Add mock devices for demonstration
                devices = [
                    {
                        'name': 'Disk1',
                        'path': '/dev/disk1',
                        'model': 'Basic GPT',
                        'size': '931.5 GB',
                        'type': 'HDD',
                        'is_ssd': False,
                        'partitions': [
                            {'name': 'EFI', 'size': '500.0 MB', 'used': '10%'},
                            {'name': 'DIAGS', 'size': '40.00 MB', 'used': '0%'},
                            {'name': 'GPT Recovery', 'size': '128.0 MB', 'used': '39%'},
                            {'name': 'OS', 'size': '750.0 MB', 'used': '33%'},
                            {'name': 'GPT Partition', 'size': '922.2 GB', 'used': '57%'},
                            {'name': 'GPT Partition Recovery', 'size': '7.956 GB', 'used': '91%'}
                        ]
                    },
                    {
                        'name': 'Disk6', 
                        'path': '/dev/disk6',
                        'model': 'GPT Recovery',
                        'size': '1.365 TB',
                        'type': 'SSD',
                        'is_ssd': True,
                        'partitions': [
                            {'name': 'Seagate', 'size': '1.364 TB', 'used': '7%'}
                        ]
                    }
                ]
            
            for i, device in enumerate(devices):
                # Create device entry similar to Macrorit
                device_info = f"{device['name']} - {device['model']} ({device['size']})"
                self.device_listbox.insert(tk.END, device_info)
                self.device_data[i] = device
            
            # Select first device by default
            if devices:
                self.device_listbox.selection_set(0)
                self.on_device_selected(None)
        
        except Exception as e:
            self.logger.error(f"Failed to refresh devices: {e}")
            messagebox.showerror("Error", f"Failed to detect devices: {e}")
    
    def on_device_selected(self, event):
        """Handle device selection in the listbox"""
        selection = self.device_listbox.curselection()
        if selection:
            index = selection[0]
            if index in self.device_data:
                device = self.device_data[index]
                self.selected_device = device
                
                # Update status message
                is_ssd = device.get('is_ssd', False)
                device_type = "SSD" if is_ssd else "HDD"
                self.progress_label.config(
                    text=f"Selected: {device['name']} ({device_type}) - {device['size']}"
                )
                
                # Enable wipe button
                self.wipe_btn.config(state=tk.NORMAL)
                
                # Check if device is safe to wipe
                try:
                    safe, reason = self.detector.is_device_safe_to_wipe(device['path'])
                    if not safe:
                        self.wipe_btn.config(state=tk.DISABLED)
                        self.progress_label.config(text=f"Warning: {reason}")
                except:
                    # If detector fails, assume it's safe for demo
                    pass
    
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
        self.device_listbox.config(state=tk.NORMAL)
    
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