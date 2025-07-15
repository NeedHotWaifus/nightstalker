#!/usr/bin/env python3
"""
NightStalker GUI EXE Builder
Cross-platform GUI for building payloads and compiling to EXE
"""

import os
import sys
import subprocess
import shutil
import time
from pathlib import Path

# Check if we're on Linux and Tkinter is available
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False
    print("Tkinter not available, using CLI interface")

from nightstalker.redteam.payload_builder import PayloadBuilder

class ExeBuilderGUI:
    def __init__(self, root=None):
        if root is None and TKINTER_AVAILABLE:
            root = tk.Tk()
        self.root = root
        self.pb = PayloadBuilder()
        self.payloads = self.pb.list_payloads()
        self.formats = self.pb.list_formats()
        self.selected_payloads = []
        self.selected_format = 'python'
        self.status_var = "Ready."
        self.icon_path = ""
        self.build_dir = "output/payloads"
        
        if TKINTER_AVAILABLE and root:
            self.root.title("NightStalker EXE Builder")
            self._build_gui()
        else:
            self._cli_interface()

    def _cli_interface(self):
        """CLI interface for Linux systems without Tkinter"""
        print("NightStalker EXE Builder - CLI Mode")
        print("=" * 40)
        
        # List available payloads
        print(f"Available payloads: {len(self.payloads)}")
        for i, payload in enumerate(self.payloads):
            print(f"  {i+1}. {payload}")
        
        # List available formats
        print(f"\nAvailable formats: {', '.join(self.formats)}")
        
        # Get user input
        try:
            payload_choice = input("\nEnter payload number (or 'all'): ").strip()
            format_choice = input("Enter format (python/powershell/bash): ").strip() or 'python'
            output_dir = input("Enter output directory (default: output/payloads): ").strip() or 'output/payloads'
            
            # Process choices
            if payload_choice.lower() == 'all':
                selected_payloads = self.payloads
            else:
                try:
                    idx = int(payload_choice) - 1
                    selected_payloads = [self.payloads[idx]] if 0 <= idx < len(self.payloads) else []
                except ValueError:
                    selected_payloads = []
            
            if not selected_payloads:
                print("No valid payloads selected")
                return
            
            # Build payloads
            print(f"\nBuilding {len(selected_payloads)} payload(s) in {format_choice} format...")
            for payload in selected_payloads:
                try:
                    output_path = self.pb.build_payload(payload, format_choice, output_path=None)
                    print(f"✓ Built: {output_path}")
                    
                    # Compile to EXE if Python
                    if format_choice == 'python':
                        self._build_exe_cli(output_path, output_dir)
                except Exception as e:
                    print(f"✗ Failed to build {payload}: {e}")
            
            print(f"\nBuild complete! Check {output_dir} for output files.")
            
        except KeyboardInterrupt:
            print("\nBuild cancelled by user")
        except Exception as e:
            print(f"Build failed: {e}")

    def _build_exe_cli(self, py_path, out_dir):
        """Build EXE from Python file using CLI"""
        try:
            exe_name = os.path.splitext(os.path.basename(py_path))[0] + ".exe"
            exe_dir = os.path.abspath(out_dir)
            
            print(f"Compiling {py_path} to EXE...")
            
            pyinstaller_cmd = [
                sys.executable, '-m', 'PyInstaller', '--onefile', 
                '--distpath', exe_dir, '--workpath', 'build', 
                '--specpath', 'build', '--noconsole', py_path
            ]
            
            result = subprocess.run(pyinstaller_cmd, capture_output=True, text=True)
            if result.returncode == 0:
                exe_path = os.path.join(exe_dir, exe_name)
                print(f"✓ EXE created: {exe_path}")
            else:
                print(f"✗ PyInstaller failed: {result.stderr}")
        except Exception as e:
            print(f"✗ EXE build failed: {e}")

    def _build_gui(self):
        """Build GUI interface (Windows/macOS)"""
        frame = ttk.Frame(self.root, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Payloads (Ctrl+Click to select multiple):").grid(row=0, column=0, sticky=tk.W)
        self.payload_listbox = tk.Listbox(frame, selectmode=tk.MULTIPLE, exportselection=0, height=8)
        for p in self.payloads:
            self.payload_listbox.insert(tk.END, p)
        self.payload_listbox.grid(row=0, column=1, sticky=tk.EW)

        ttk.Label(frame, text="Format:").grid(row=1, column=0, sticky=tk.W)
        format_combo = ttk.Combobox(frame, textvariable=tk.StringVar(value=self.selected_format), values=self.formats, state="readonly")
        format_combo.grid(row=1, column=1, sticky=tk.EW)

        ttk.Label(frame, text="Output Directory:").grid(row=2, column=0, sticky=tk.W)
        out_entry = ttk.Entry(frame, textvariable=tk.StringVar(value=self.build_dir), width=30)
        out_entry.grid(row=2, column=1, sticky=tk.EW)
        ttk.Button(frame, text="Browse", command=self._choose_dir).grid(row=2, column=2, sticky=tk.E)

        ttk.Label(frame, text="Icon (optional, .ico):").grid(row=3, column=0, sticky=tk.W)
        icon_entry = ttk.Entry(frame, textvariable=tk.StringVar(value=self.icon_path), width=30)
        icon_entry.grid(row=3, column=1, sticky=tk.EW)
        ttk.Button(frame, text="Browse", command=self._choose_icon).grid(row=3, column=2, sticky=tk.E)

        build_btn = ttk.Button(frame, text="Build Payload(s)", command=self._start_build)
        build_btn.grid(row=4, column=0, columnspan=2, pady=10, sticky=tk.EW)

        clear_btn = ttk.Button(frame, text="Clear Payloads", command=self._clear_payloads)
        clear_btn.grid(row=4, column=2, pady=10, sticky=tk.EW)

        self.status_label = ttk.Label(frame, textvariable=tk.StringVar(value=self.status_var), foreground="blue")
        self.status_label.grid(row=5, column=0, columnspan=3, sticky=tk.W)

        frame.columnconfigure(1, weight=1)

    def _choose_dir(self):
        if TKINTER_AVAILABLE:
            d = filedialog.askdirectory()
            if d:
                self.build_dir = d

    def _choose_icon(self):
        if TKINTER_AVAILABLE:
            f = filedialog.askopenfilename(filetypes=[("Icon files", "*.ico")])
            if f:
                self.icon_path = f

    def _start_build(self):
        if TKINTER_AVAILABLE:
            import threading
            threading.Thread(target=self._build_payload, daemon=True).start()

    def _build_payload(self):
        if not TKINTER_AVAILABLE:
            return
            
        selected_indices = self.payload_listbox.curselection()
        if not selected_indices:
            self.status_var = "No payloads selected."
            messagebox.showwarning("No Payloads", "Please select at least one payload.")
            return
        selected_payloads = [self.payloads[i] for i in selected_indices]
        fmt = self.selected_format
        out_dir = self.build_dir
        icon = self.icon_path
        self.status_var = f"Building {', '.join(selected_payloads)} ({fmt})..."
        try:
            if len(selected_payloads) == 1:
                # Single payload
                output_path = self.pb.build_payload(selected_payloads[0], fmt, output_path=None)
                self.status_var = f"Payload built: {output_path}"
                if fmt == 'python':
                    self._build_exe(output_path, out_dir, icon)
                else:
                    messagebox.showinfo("Build Complete", f"Payload created: {output_path}")
            else:
                # Multi-payload: concatenate with divider
                divider = f"\n# --- PAYLOAD DIVIDER ---\n"
                code = divider.join([self.pb.get_payload(p, fmt) for p in selected_payloads])
                timestamp = str(int(time.time()))
                filename = f"payload_multi_{timestamp}.{fmt if fmt != 'python' else 'py'}"
                output_path = os.path.join(out_dir, filename)
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(code)
                self.status_var = f"Multi-payload built: {output_path}"
                if fmt == 'python':
                    self._build_exe(output_path, out_dir, icon)
                else:
                    messagebox.showinfo("Build Complete", f"Payload created: {output_path}")
        except Exception as e:
            self.status_var = f"Build failed: {e}"
            messagebox.showerror("Build Failed", str(e))

    def _build_exe(self, py_path, out_dir, icon):
        exe_name = os.path.splitext(os.path.basename(py_path))[0] + ".exe"
        exe_dir = os.path.abspath(out_dir)
        pyinstaller_cmd = [
            sys.executable, '-m', 'PyInstaller', '--onefile', '--distpath', exe_dir, '--workpath', 'build', '--specpath', 'build', '--noconsole', py_path
        ]
        if icon:
            pyinstaller_cmd.insert(-1, f'--icon={icon}')
        self.status_var = "Running PyInstaller..."
        result = subprocess.run(pyinstaller_cmd, capture_output=True, text=True)
        if result.returncode == 0:
            exe_path = os.path.join(exe_dir, exe_name)
            self.status_var = f"EXE created: {exe_path}"
            messagebox.showinfo("Build Complete", f"EXE created: {exe_path}")
        else:
            self.status_var = "PyInstaller failed. See details."
            messagebox.showerror("PyInstaller Error", result.stderr)

    def _clear_payloads(self):
        out_dir = self.build_dir
        if not os.path.exists(out_dir):
            if TKINTER_AVAILABLE:
                messagebox.showinfo("Nothing to clear", "Output directory does not exist.")
            else:
                print("Output directory does not exist.")
            return
        try:
            for fname in os.listdir(out_dir):
                fpath = os.path.join(out_dir, fname)
                if os.path.isfile(fpath):
                    os.remove(fpath)
            self.status_var = "All payloads cleared."
            if TKINTER_AVAILABLE:
                messagebox.showinfo("Cleared", "All payloads in output directory have been deleted.")
            else:
                print("All payloads in output directory have been deleted.")
        except Exception as e:
            self.status_var = f"Failed to clear payloads: {e}"
            if TKINTER_AVAILABLE:
                messagebox.showerror("Error", f"Failed to clear payloads: {e}")
            else:
                print(f"Failed to clear payloads: {e}")

if __name__ == "__main__":
    if TKINTER_AVAILABLE:
        root = tk.Tk()
        app = ExeBuilderGUI(root)
        root.mainloop()
    else:
        app = ExeBuilderGUI() 