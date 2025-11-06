import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from intelhex import IntelHex


class HexMergerApp:
    def __init__(self, master):
        self.master = master
        master.title("IntelHex Merger Tool")
        master.geometry("600x500")
        master.resizable(False, False)

        self.create_widgets()

    def create_widgets(self):
        # File selectors
        frm_files = ttk.LabelFrame(self.master, text="Input Files")
        frm_files.pack(fill="x", padx=10, pady=10)

        self.bootloader_path = tk.StringVar()
        self.firmware_path = tk.StringVar()
        self.eeprom_path = tk.StringVar()

        self.add_file_selector(frm_files, "Bootloader:", self.bootloader_path, 0)
        self.add_file_selector(frm_files, "Firmware:", self.firmware_path, 1)
        self.add_file_selector(frm_files, "EEPROM:", self.eeprom_path, 2)

        # Options
        frm_options = ttk.LabelFrame(self.master, text="Options")
        frm_options.pack(fill="x", padx=10, pady=10)

        self.replace_var = tk.BooleanVar()
        self.fresh_var = tk.BooleanVar()
        self.verbose_var = tk.BooleanVar()

        # ttk.Checkbutton(frm_options, text="Replace overlapping data", variable=self.replace_var).pack(anchor="w", padx=10)
        # ttk.Checkbutton(frm_options, text="Make EEPROM look fresh", variable=self.fresh_var).pack(anchor="w", padx=10)
        ttk.Checkbutton(frm_options, text="Verbose output", variable=self.verbose_var).pack(anchor="w", padx=10)

        # MCU and address options
        frm_addr = ttk.LabelFrame(self.master, text="MCU and Address Configuration")
        frm_addr.pack(fill="x", padx=10, pady=10)

        ttk.Label(frm_addr, text="Base Address:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.baseaddr_entry = ttk.Entry(frm_addr)
        self.baseaddr_entry.insert(0, "0x08000000")
        self.baseaddr_entry.grid(row=0, column=1, sticky="w", padx=5, pady=5)

        # ttk.Label(frm_addr, text="EEPROM Address:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        # self.eepromaddr_entry = ttk.Entry(frm_addr)
        # self.eepromaddr_entry.insert(0, "0x7C00")
        # self.eepromaddr_entry.grid(row=1, column=1, sticky="w", padx=5, pady=5)

        ttk.Label(frm_addr, text="MCU Type:").grid(row=2, column=0, sticky="e", padx=5, pady=5)
        self.mcu_combobox = ttk.Combobox(frm_addr, values=["f051", "f031", "e230", "g071", "g031" , "f421", "f415", "l431", "g431"], state="readonly")
        self.mcu_combobox.current(0)
        self.mcu_combobox.grid(row=2, column=1, sticky="w", padx=5, pady=5)

        # Output path
        frm_out = ttk.LabelFrame(self.master, text="Output")
        frm_out.pack(fill="x", padx=10, pady=10)

        self.output_path = tk.StringVar()
        self.add_file_selector(frm_out, "Output Path:", self.output_path, 0, dir_mode=True)

        # Run button
        ttk.Button(self.master, text="Merge and Save", command=self.run_merge).pack(pady=10)

        # Console output
        self.output_console = tk.Text(self.master, height=10, width=70, wrap="word", state="disabled", bg="#f7f7f7")
        self.output_console.pack(padx=10, pady=5, fill="both", expand=True)

    def add_file_selector(self, parent, label, variable, row, dir_mode=False):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="e", padx=5, pady=5)
        ttk.Entry(parent, textvariable=variable, width=50).grid(row=row, column=1, padx=5, pady=5)
        ttk.Button(
            parent,
            text="Browse...",
            command=lambda: self.browse_file(variable, dir_mode)
        ).grid(row=row, column=2, padx=5, pady=5)

    def browse_file(self, var, dir_mode=False):
        if dir_mode:
            path = filedialog.askdirectory(title="Select Output Folder")
        else:
            path = filedialog.askopenfilename(
                title="Select File",
                filetypes=[("All Files", "*.*")]
            )
        if path:
            var.set(path)

    def log(self, text):
        self.output_console.config(state="normal")
        self.output_console.insert("end", text + "\n")
        self.output_console.config(state="disabled")
        self.output_console.see("end")

    def run_merge(self):
        try:
            self.output_console.config(state="normal")
            self.output_console.delete("1.0", "end")
            self.output_console.config(state="disabled")

            bootloader = self.bootloader_path.get().strip() or 'x'
            firmware = self.firmware_path.get().strip() or 'x'
            eeprom = self.eeprom_path.get().strip() or None
            outpath = self.output_path.get().strip() or "."

            replace = self.replace_var.get()
            fresh = self.fresh_var.get()
            verbose = self.verbose_var.get()
            baseaddr = self.baseaddr_entry.get().strip()
            # eepromaddr = self.eepromaddr_entry.get().strip()
            mcu = self.mcu_combobox.get().strip()
            if mcu == 'f051':
                eepromaddr ='0x7C00'
            if mcu == 'f031':
                eepromaddr ='0x7C00'
            if mcu == 'e230':
                eepromaddr ='0x7C00'    
            if mcu == 'f421':
                eepromaddr ='0x7C00'
            if mcu == 'f415':
                eepromaddr ='0x7C00'
            if mcu == 'g071':
                eepromaddr ='0xF800'
            if mcu == 'g031':
                eepromaddr ='0xF800'
            if mcu == 'l431':
                eepromaddr ='0xF800'
            if mcu == 'g431':
                eepromaddr ='0xF800'

            self.log("Merging files...")
            self.master.update()

            # --- Adapted main logic here ---
            self.merge_hex_files(
                bootloader, firmware, replace, fresh, baseaddr, eeprom,
                eepromaddr, mcu, outpath, verbose
            )
            self.log("✅ Merge complete!")

        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.log("❌ Error: " + str(e))

    def merge_hex_files(self, bootloader, firmware, replace, fresh, baseaddr,
                        eeprom, eepromaddr, mcu, outpath, verbose):
        # --- Original script logic simplified and embedded here ---
        def vprint(msg):
            if verbose:
                self.log(msg)

        if "0x" in baseaddr.lower():
            base_address = int(baseaddr, 16)
        else:
            base_address = int(baseaddr, 10)

        vprint(f"Base address: 0x{base_address:08X}")

        bl_ihex, fw_ihex = None, None

        if bootloader != 'x':
            ext = os.path.splitext(bootloader)[1].lower()
            bl_ihex = IntelHex(bootloader) if ext == ".hex" else IntelHex()
            if ext == ".bin":
                bl_ihex.loadbin(bootloader, offset=base_address)
            vprint(f"Loaded bootloader: {bootloader}")

        if firmware != 'x':
            ext = os.path.splitext(firmware)[1].lower()
            if ext != ".hex":
                raise Exception("Firmware must be a .hex file")
            fw_ihex = IntelHex(firmware)
            vprint(f"Loaded firmware: {firmware}")

        if bl_ihex is None and fw_ihex is None:
            raise Exception("No bootloader or firmware provided")

        if bl_ihex and fw_ihex:
            bl_ihex.merge(fw_ihex, overlap='replace' if replace else 'ignore')
            vprint("Merged firmware into bootloader")

        if eeprom:
            ext = os.path.splitext(eeprom)[1].lower()
            if ext != ".bin":
                raise Exception("EEPROM must be a .bin file")
            if "0x" in eepromaddr.lower():
                eep_addr = int(eepromaddr, 16)
            else:
                eep_addr = int(eepromaddr, 10)
            eep_ihex = IntelHex()
            eep_ihex.loadbin(eeprom, offset=base_address + eep_addr)
            if fresh:
                eep_ihex[base_address + eep_addr + 3] = 0
                eep_ihex[base_address + eep_addr + 4] = 0
            bl_ihex.merge(eep_ihex, overlap='replace')
            vprint("EEPROM merged")

        # Determine output path
        if not outpath.lower().endswith(".hex"):
            if not os.path.exists(outpath):
                os.makedirs(outpath)
            outpath = os.path.join(outpath, "merged_output.hex")

        bl_ihex.write_hex_file(outpath)
        self.log(f"Saved to {outpath}")


if __name__ == "__main__":
    root = tk.Tk()
    app = HexMergerApp(root)
    root.mainloop()
