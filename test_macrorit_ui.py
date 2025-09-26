#!/usr/bin/env python3
"""
Test script for the new Macrorit-inspired SecureWipe interface
"""

import tkinter as tk
from tkinter import ttk, messagebox
import sys
import os

def create_macrorit_demo():
    """Create a demo showing the Macrorit-inspired interface"""
    
    root = tk.Tk()
    root.title("SecureWipe - Macrorit Style Demo")
    root.geometry("900x650")
    
    # Neutral color scheme
    colors = {
        'primary': '#4a5568',
        'secondary': '#718096', 
        'background': '#f7fafc',
        'surface': '#ffffff',
        'accent': '#4299e1',
        'text': '#2d3748',
        'text_secondary': '#718096',
        'border': '#e2e8f0'
    }
    
    root.configure(bg=colors['background'])
    
    # Header bar (like Macrorit)
    header_frame = tk.Frame(root, bg=colors['primary'], height=50)
    header_frame.pack(fill="x")
    header_frame.pack_propagate(False)
    
    # Header content
    header_content = tk.Frame(header_frame, bg=colors['primary'])
    header_content.pack(fill="both", expand=True, padx=15, pady=10)
    
    tk.Label(header_content, text="🔒", bg=colors['primary'], fg='white', 
             font=('Segoe UI', 14)).pack(side="left", padx=(0, 10))
    
    tk.Label(header_content, text="Secure Data Wiper v3.2.1 - Government Edition", 
             bg=colors['primary'], fg='white', font=('Segoe UI', 12, 'bold')).pack(side="left")
    
    tk.Label(header_content, text="Destroy all data! No possibility to recover.", 
             bg=colors['primary'], fg='white', font=('Segoe UI', 10)).pack(side="left", padx=(20, 0))
    
    # Main content area
    main_frame = tk.Frame(root, bg=colors['background'])
    main_frame.pack(fill="both", expand=True, padx=20, pady=20)
    
    # Left column
    left_frame = tk.Frame(main_frame, bg=colors['background'])
    left_frame.pack(side="left", fill="both", expand=True, padx=(0, 10))
    
    # Right column
    right_frame = tk.Frame(main_frame, bg=colors['background'])
    right_frame.pack(side="right", fill="y", padx=(10, 0))
    
    # 1. Wiping Method
    method_frame = tk.LabelFrame(left_frame, text="1. Wiping Method", 
                                font=('Segoe UI', 10, 'bold'), 
                                bg=colors['surface'], fg=colors['text'])
    method_frame.pack(fill="x", pady=(0, 10), padx=10, ipady=10)
    
    method_var = tk.StringVar(value="entire_drive")
    
    tk.Radiobutton(method_frame, text="Free space only", variable=method_var, 
                   value="free_space", bg=colors['surface'], fg=colors['text'],
                   font=('Segoe UI', 10)).pack(anchor="w", padx=10, pady=2)
    
    tk.Radiobutton(method_frame, text="Entire Drive", variable=method_var, 
                   value="entire_drive", bg=colors['surface'], fg=colors['text'],
                   font=('Segoe UI', 10)).pack(anchor="w", padx=10, pady=2)
    
    tk.Label(method_frame, text="(All data will be erased)", 
             bg=colors['surface'], fg=colors['text_secondary'],
             font=('Segoe UI', 9)).pack(anchor="w", padx=10, pady=(5, 0))
    
    # 2. Security
    security_frame = tk.LabelFrame(left_frame, text="2. Security", 
                                  font=('Segoe UI', 10, 'bold'),
                                  bg=colors['surface'], fg=colors['text'])
    security_frame.pack(fill="x", pady=(0, 10), padx=10, ipady=10)
    
    security_var = tk.StringVar(value="dod_3_pass")
    
    security_options = [
        ("Fill sectors with zero", "fill_zero"),
        ("Fill sectors with one", "fill_one"), 
        ("Fill sectors with zero&one", "fill_zero_one"),
        ("DoD 5220-22-M (3 passes)", "dod_3_pass"),
        ("DoD 5220-22 STD (7 passes)", "dod_7_pass")
    ]
    
    for text, value in security_options:
        tk.Radiobutton(security_frame, text=text, variable=security_var, 
                       value=value, bg=colors['surface'], fg=colors['text'],
                       font=('Segoe UI', 10)).pack(anchor="w", padx=10, pady=2)
    
    # 3. Device Selection
    device_frame = tk.LabelFrame(left_frame, text="3. Choose a partition or disk to wipe", 
                                font=('Segoe UI', 10, 'bold'),
                                bg=colors['surface'], fg=colors['text'])
    device_frame.pack(fill="both", expand=True, padx=10, ipady=10)
    
    # Device listbox
    device_listbox = tk.Listbox(device_frame, height=8, font=('Segoe UI', 10),
                               bg=colors['surface'], selectbackground=colors['accent'],
                               borderwidth=1, relief='solid')
    device_listbox.pack(fill="both", expand=True, padx=10, pady=10)
    
    # Add sample devices
    devices = [
        "Disk1 - Basic GPT (931.5 GB)",
        "Disk6 - GPT Recovery (1.365 TB)",
        "USB Drive - Removable (32.0 GB)"
    ]
    
    for device in devices:
        device_listbox.insert(tk.END, device)
    
    device_listbox.selection_set(0)  # Select first item
    
    # Status indicators
    status_frame = tk.Frame(device_frame, bg=colors['surface'])
    status_frame.pack(fill="x", padx=10, pady=(0, 10))
    
    # Color legend
    legend_items = [
        ("Primary", colors['accent']),
        ("Logical", colors['secondary']),
        ("Unallocated", colors['text_secondary'])
    ]
    
    for text, color in legend_items:
        item_frame = tk.Frame(status_frame, bg=colors['surface'])
        item_frame.pack(side="left", padx=(0, 15))
        
        color_box = tk.Frame(item_frame, bg=color, width=15, height=15)
        color_box.pack(side="left", padx=(0, 5))
        
        tk.Label(item_frame, text=text, bg=colors['surface'], fg=colors['text'],
                font=('Segoe UI', 9)).pack(side="left")
    
    # Right column - Action button and menu
    
    # Wipe button
    wipe_frame = tk.Frame(right_frame, bg=colors['background'])
    wipe_frame.pack(pady=(50, 20))
    
    def on_wipe_click():
        messagebox.showinfo("Demo", "This is a demonstration. No actual wiping will occur.")
    
    wipe_btn = tk.Button(wipe_frame, text="🔥 Wipe Now", 
                        font=('Segoe UI', 14, 'bold'),
                        bg=colors['accent'], fg='white',
                        activebackground=colors['primary'],
                        activeforeground='white',
                        borderwidth=0, relief='flat',
                        padx=30, pady=15,
                        cursor='hand2',
                        command=on_wipe_click)
    wipe_btn.pack()
    
    # Menu buttons
    menu_buttons = [
        ("🔄 Reload disks", lambda: messagebox.showinfo("Demo", "Reload disks feature")),
        ("🛠️ More tools", lambda: messagebox.showinfo("Demo", "More tools feature")),
        ("❓ Help topics", lambda: messagebox.showinfo("Demo", "Help topics feature")),
        ("ℹ️ About", lambda: messagebox.showinfo("Demo", "About this application")),
        ("🔐 Activate", lambda: messagebox.showinfo("Demo", "Government edition - no activation needed")),
        ("⬆️ Upgrade", lambda: messagebox.showinfo("Demo", "You have the latest version"))
    ]
    
    for text, command in menu_buttons:
        btn = tk.Button(right_frame, text=text, command=command,
                       font=('Segoe UI', 10), bg=colors['surface'],
                       fg=colors['text'], borderwidth=1, relief='solid',
                       padx=10, pady=5, cursor='hand2')
        btn.pack(fill="x", pady=2)
    
    # Bottom status bar
    status_bar = tk.Frame(root, bg=colors['primary'], height=40)
    status_bar.pack(fill="x", side="bottom")
    status_bar.pack_propagate(False)
    
    status_content = tk.Frame(status_bar, bg=colors['primary'])
    status_content.pack(fill="both", expand=True, padx=15, pady=10)
    
    # Progress bar
    progress = ttk.Progressbar(status_content, length=300, mode='determinate')
    progress.pack(side="left", padx=(0, 10))
    
    tk.Label(status_content, 
             text="We strongly recommend you to close all other applications before you perform operation.",
             bg=colors['primary'], fg='white', font=('Segoe UI', 10)).pack(side="left")
    
    root.mainloop()

if __name__ == "__main__":
    print("SecureWipe Macrorit-Style Interface Demo")
    print("=" * 45)
    print("This demo shows the new Macrorit-inspired interface")
    print("with neutral colors suitable for government use.")
    print()
    
    try:
        create_macrorit_demo()
    except Exception as e:
        print(f"Demo error: {e}")
        print("The new interface has been implemented in gui/interface.py")
    
    print("\nNew Macrorit-Style Features:")
    print("- Clean header bar with application info")
    print("- Left column with method, security, and device selection")
    print("- Right column with large action button and menu")
    print("- Neutral color scheme (blues and grays)")
    print("- Professional government-appropriate styling")
    print("- Visual device selection with status indicators")
    print("- Bottom status bar with progress information")