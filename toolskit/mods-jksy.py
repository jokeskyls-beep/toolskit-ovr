import ctypes
import json
import os
import struct
import threading
import time
from tkinter import messagebox, ttk
import customtkinter as ctk

PRESET_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'mods_presets.json')

if os.name != 'nt':
    def open_window(parent):
        messagebox.showerror('Mods', 'Fitur Mods hanya tersedia di Windows.', parent=parent)
        return None
else:
    kernel32 = ctypes.windll.kernel32
    psapi = ctypes.windll.psapi

    MAX_RESULTS = 300000
    MEM_COMMIT = 0x1000
    PAGE_GUARD = 0x100
    PAGE_NOACCESS = 0x01
    PROCESS_QUERY_LIMITED = 0x1000
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    PROCESS_VM_WRITE = 0x0020
    PROCESS_VM_OPERATION = 0x0008
    PROCESS_ALL_ACCESS = 0x1F0FFF
    MAX_REGION_READ = 0x4000000  # 64 MB — aman untuk ReadProcessMemory

    TYPE_SIZES = {'INT32': 4, 'INT64': 8, 'FLOAT': 4, 'DOUBLE': 8, 'STRING': 0}

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ('BaseAddress', ctypes.c_void_p),
            ('AllocationBase', ctypes.c_void_p),
            ('AllocationProtect', ctypes.c_ulong),
            ('RegionSize', ctypes.c_size_t),
            ('State', ctypes.c_ulong),
            ('Protect', ctypes.c_ulong),
            ('Type', ctypes.c_ulong),
        ]

    class MODULEINFO(ctypes.Structure):
        _fields_ = [
            ('lpBaseOfDll', ctypes.c_void_p),
            ('SizeOfImage', ctypes.c_ulong),
            ('EntryPoint', ctypes.c_void_p),
        ]

    # ---------- WinAPI helpers ----------
    def list_processes():
        procs, seen = [], set()
        arr = (ctypes.c_ulong * 4096)()
        returned = ctypes.c_ulong()
        if not psapi.EnumProcesses(arr, ctypes.sizeof(arr), ctypes.byref(returned)):
            return procs
        count = returned.value // ctypes.sizeof(ctypes.c_ulong)
        for i in range(count):
            pid = arr[i]
            if pid == 0 or pid in seen:
                continue
            seen.add(pid)
            h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED | PROCESS_VM_READ, False, pid)
            if not h:
                continue
            buf = ctypes.create_unicode_buffer(1024)
            if psapi.GetModuleBaseNameW(h, None, buf, 1024) and buf.value:
                procs.append((pid, buf.value))
            kernel32.CloseHandle(h)
        procs.sort(key=lambda x: (x[1].lower(), x[0]))
        return procs

    def list_modules(handle):
        mods = []
        arr = (ctypes.c_void_p * 2048)()
        needed = ctypes.c_ulong()
        if not psapi.EnumProcessModules(handle, arr, ctypes.sizeof(arr), ctypes.byref(needed)):
            return mods
        count = needed.value // ctypes.sizeof(ctypes.c_void_p)
        for i in range(count):
            hmod = arr[i]
            name_buf = ctypes.create_unicode_buffer(260)
            if not psapi.GetModuleBaseNameW(handle, hmod, name_buf, 260):
                continue
            info = MODULEINFO()
            if psapi.GetModuleInformation(handle, hmod, ctypes.byref(info), ctypes.sizeof(info)):
                mods.append({
                    'name': name_buf.value,
                    'base': int(info.lpBaseOfDll or 0),
                    'size': int(info.SizeOfImage),
                })
        return mods

    def get_readable_regions(handle, base=0, size_limit=0):
        regions = []
        address = base
        upper = (base + size_limit) if size_limit else 0x7FFFFFFEFFFF
        mbi = MEMORY_BASIC_INFORMATION()
        while address < upper:
            r = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address),
                                        ctypes.byref(mbi), ctypes.sizeof(mbi))
            if not r:
                break
            rbase = int(mbi.BaseAddress or 0)
            rsize = int(mbi.RegionSize)
            if (mbi.State == MEM_COMMIT
                    and not (mbi.Protect & PAGE_GUARD)
                    and mbi.Protect != PAGE_NOACCESS):
                end = rbase + rsize
                if size_limit and end > upper:
                    rsize = max(0, upper - rbase)
                if rsize > 0:
                    regions.append((rbase, rsize))
            nxt = rbase + rsize
            if nxt <= address:
                break
            address = nxt
        return regions

    def read_memory(handle, addr, size):
        if size <= 0 or size > MAX_REGION_READ:
            return None
        buf = ctypes.create_string_buffer(size)
        br = ctypes.c_size_t(0)
        if not kernel32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf,
                                          ctypes.c_size_t(size), ctypes.byref(br)):
            return None
        return buf.raw[:br.value]

    def write_memory(handle, addr, data):
        if not data:
            return False
        buf = ctypes.create_string_buffer(data, len(data))
        br = ctypes.c_size_t(0)
        return bool(kernel32.WriteProcessMemory(handle, ctypes.c_void_p(addr), buf,
                                                 ctypes.c_size_t(len(data)),
                                                 ctypes.byref(br)))

    def read_region_chunked(handle, base, size):
        """Read region in chunks ≤ 64 MB to avoid ReadProcessMemory failure."""
        out = []
        offset = 0
        while offset < size:
            chunk = min(MAX_REGION_READ, size - offset)
            part = read_memory(handle, base + offset, chunk)
            if part is None:
                # fallback smaller chunk
                part = read_memory(handle, base + offset, min(0x400000, chunk)) or b''
            out.append(part)
            offset += len(part) if part else chunk
            if not part:
                break
        return b''.join(out)

    # ---------- serialization ----------
    def pack_value(text, vtype):
        if vtype == 'INT32':
            return struct.pack('<i', int(text))
        if vtype == 'INT64':
            return struct.pack('<q', int(text))
        if vtype == 'FLOAT':
            return struct.pack('<f', float(text))
        if vtype == 'DOUBLE':
            return struct.pack('<d', float(text))
        if vtype == 'STRING':
            return text.encode('utf-8')
        raise ValueError('Unknown type')

    def pack_value_padded(text, vtype, old_len=None):
        """Pack with null-padding for STRING to avoid residual trailing bytes."""
        raw = pack_value(text, vtype)
        if vtype == 'STRING' and old_len:
            if len(raw) < old_len:
                raw = raw + b'\x00' * (old_len - len(raw))
            elif len(raw) >= old_len:
                # keep extra null so reader stops correctly
                raw = raw + b'\x00'
        return raw

    def unpack_value(data, vtype):
        try:
            if vtype == 'INT32':
                return struct.unpack('<i', data[:4])[0]
            if vtype == 'INT64':
                return struct.unpack('<q', data[:8])[0]
            if vtype == 'FLOAT':
                return round(struct.unpack('<f', data[:4])[0], 4)
            if vtype == 'DOUBLE':
                return round(struct.unpack('<d', data[:8])[0], 4)
            if vtype == 'STRING':
                return data.split(b'\x00')[0].decode('utf-8', errors='replace')
        except Exception:
            return None
        return None

    def format_value(data, vtype):
        v = unpack_value(data, vtype)
        return str(v) if v is not None else '?'

    # ---------- preset I/O ----------
    def load_presets():
        try:
            with open(PRESET_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {'presets': []}

    def save_presets(data):
        """Return None on success, or error string."""
        try:
            with open(PRESET_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            return None
        except Exception as e:
            return str(e)

    # ---------- main window ----------
    def open_window(parent):
        win = ctk.CTkToplevel(parent)
        win.title('JKSY • Mods v2.1 — Memory Editor + Speed Hack')
        win.geometry('1000x800')
        win.minsize(960, 760)
        win.configure(fg_color='#0f1012')
        win.transient(parent)

        state = {
            'handle': None, 'pid': None, 'proc_name': '',
            'modules': [], 'main_module': None,
            'results': [], 'frozen': {},
            'stop_flag': False, 'value_type': 'INT32',
            'scan_scope': 'Process',
        }
        freeze_ctl = {'flag': False}
        scan_busy = {'flag': False}
        preset_data = load_presets()

        def safe_after(ms, fn):
            try:
                if win.winfo_exists():
                    win.after(ms, fn)
            except Exception:
                pass

        # ---------- header ----------
        header = ctk.CTkFrame(win, fg_color='#17181b', corner_radius=10)
        header.pack(fill='x', padx=12, pady=(10, 6))
        ctk.CTkLabel(header, text='⚡ JKSY MODS v2.1 — PROCESS MEMORY EDITOR',
                     font=('Segoe UI', 18, 'bold'), text_color='#00ff66'
                     ).pack(anchor='w', padx=14, pady=(10, 2))
        ctk.CTkLabel(header,
            text='Untuk aplikasi milik sendiri / debugging / single-player. '
                 'Server-side validation (game online) tidak bisa diakali dari client. '
                 'Penggunaan terhadap aplikasi pihak lain = tanggung jawab pengguna.',
            font=('Segoe UI', 10), text_color='#f59e0b',
            wraplength=960, justify='left').pack(anchor='w', padx=14, pady=(0, 10))

        # ---------- target row ----------
        target_row = ctk.CTkFrame(win, fg_color='#17181b', corner_radius=10)
        target_row.pack(fill='x', padx=12, pady=(0, 6))
        ctk.CTkLabel(target_row, text='Target:', text_color='#c0c0c0',
                     font=('Segoe UI', 11, 'bold')
                     ).pack(side='left', padx=(12, 4), pady=10)
        proc_var = ctk.StringVar(value='(no process)')
        proc_menu = ctk.CTkOptionMenu(target_row, variable=proc_var,
                                      values=['(no process)'], width=300,
                                      fg_color='#1f538d', button_color='#143c68')
        proc_menu.pack(side='left', padx=2, pady=10)
        refresh_btn = ctk.CTkButton(target_row, text='⟳', width=36, height=28,
                                    fg_color='#334155', hover_color='#475569')
        refresh_btn.pack(side='left', padx=2, pady=10)
        ctk.CTkButton(target_row, text='Attach', width=80, height=28,
                      fg_color='#2b8a3e', hover_color='#216e31',
                      command=lambda: attach_proc()
                      ).pack(side='left', padx=2, pady=10)
        ctk.CTkButton(target_row, text='Detach', width=80, height=28,
                      fg_color='#991B1B', hover_color='#7f1d1d',
                      command=lambda: detach()
                      ).pack(side='left', padx=2, pady=10)
        status_label = ctk.CTkLabel(target_row, text='DETACHED',
                                    font=('Consolas', 11, 'bold'), text_color='#ef4444')
        status_label.pack(side='left', padx=(10, 4))

        # ---------- module + scope row ----------
        mod_row = ctk.CTkFrame(win, fg_color='#17181b', corner_radius=10)
        mod_row.pack(fill='x', padx=12, pady=(0, 6))
        ctk.CTkLabel(mod_row, text='Module:', text_color='#c0c0c0',
                     font=('Segoe UI', 11, 'bold')
                     ).pack(side='left', padx=(12, 4), pady=10)
        module_var = ctk.StringVar(value='(no modules)')
        module_menu = ctk.CTkOptionMenu(mod_row, variable=module_var,
                                        values=['(no modules)'], width=300,
                                        fg_color='#0d9488', button_color='#0f766e')
        module_menu.pack(side='left', padx=2, pady=10)
        scope_var = ctk.StringVar(value='Process')
        ctk.CTkLabel(mod_row, text='Scan scope:', text_color='#c0c0c0',
                     font=('Segoe UI', 11, 'bold')
                     ).pack(side='left', padx=(10, 4), pady=10)
        ctk.CTkOptionMenu(mod_row, variable=scope_var,
                          values=['Process', 'Module'],
                          width=120, fg_color='#7c3aed', button_color='#6d28d9',
                          command=lambda v: state.update({'scan_scope': v})
                          ).pack(side='left', padx=2, pady=10)
        ctk.CTkButton(mod_row, text='⚡ Speed Hack', width=130, height=28,
                      fg_color='#f59e0b', hover_color='#d97706',
                      text_color='#000',
                      command=lambda: open_speed_hack()
                      ).pack(side='right', padx=(0, 10), pady=10)

        # ---------- scan row ----------
        scan_row = ctk.CTkFrame(win, fg_color='#17181b', corner_radius=10)
        scan_row.pack(fill='x', padx=12, pady=(0, 6))
        ctk.CTkLabel(scan_row, text='Value:', text_color='#c0c0c0',
                     font=('Segoe UI', 11, 'bold')
                     ).pack(side='left', padx=(12, 4), pady=10)
        value_entry = ctk.CTkEntry(scan_row, width=170, height=28,
                                   placeholder_text='e.g. 100')
        value_entry.pack(side='left', padx=2, pady=10)
        type_var = ctk.StringVar(value='INT32')
        ctk.CTkOptionMenu(scan_row, variable=type_var, values=list(TYPE_SIZES.keys()),
                          width=110, fg_color='#1f538d', button_color='#143c68',
                          command=lambda v: state.update({'value_type': v})
                          ).pack(side='left', padx=2, pady=10)
        filter_var = ctk.StringVar(value='Exact')
        ctk.CTkOptionMenu(scan_row, variable=filter_var,
                          values=['Exact', 'Changed', 'Unchanged', 'Increased', 'Decreased'],
                          width=130, fg_color='#0891b2', button_color='#0e7490'
                          ).pack(side='left', padx=2, pady=10)
        first_btn = ctk.CTkButton(scan_row, text='First Scan (Ctrl+G)', width=150,
                                  height=28, fg_color='#0891b2', hover_color='#0e7490',
                                  command=lambda: first_scan())
        first_btn.pack(side='left', padx=2, pady=10)
        next_btn = ctk.CTkButton(scan_row, text='Next Scan (Ctrl+S)', width=150,
                                 height=28, fg_color='#0891b2', hover_color='#0e7490',
                                 command=lambda: next_scan())
        next_btn.pack(side='left', padx=2, pady=10)
        ctk.CTkButton(scan_row, text='Clear', width=70, height=28,
                      fg_color='#334155', hover_color='#475569',
                      command=lambda: clear_results()
                      ).pack(side='left', padx=2, pady=10)

        # ---------- progress ----------
        prog_bar = ctk.CTkProgressBar(win, height=10, progress_color='#22c55e')
        prog_bar.pack(fill='x', padx=12, pady=(0, 3))
        prog_bar.set(0)
        prog_label = ctk.CTkLabel(win, text='Ready.', text_color='#a0a0a0',
                                  font=('Consolas', 10))
        prog_label.pack(anchor='w', padx=14, pady=(0, 4))

        # ---------- tree ----------
        table_frame = ctk.CTkFrame(win, fg_color='#0b0c0e', corner_radius=8)
        table_frame.pack(fill='both', expand=True, padx=12, pady=(0, 6))
        style = ttk.Style()
        try:
            style.theme_use('clam')
        except Exception:
            pass
        style.configure('Mods.Treeview', background='#0b0c0e', foreground='#e5e7eb',
                        fieldbackground='#0b0c0e', rowheight=24,
                        font=('Consolas', 10))
        style.configure('Mods.Treeview.Heading', background='#17181b',
                        foreground='#00ff66', font=('Segoe UI', 10, 'bold'))
        style.map('Mods.Treeview', background=[('selected', '#1f538d')])
        tree = ttk.Treeview(table_frame, columns=('addr', 'module', 'value', 'frozen'),
                            show='headings', style='Mods.Treeview', height=14)
        for c, w, t in [('addr', 170, 'Address'), ('module', 130, 'Module'),
                        ('value', 220, 'Value'), ('frozen', 80, 'Frozen')]:
            tree.heading(c, text=t)
            tree.column(c, width=w, anchor='w' if c != 'frozen' else 'center')
        tree.pack(side='left', fill='both', expand=True, padx=4, pady=4)
        sc = ttk.Scrollbar(table_frame, orient='vertical', command=tree.yview)
        sc.pack(side='right', fill='y', pady=4, padx=(0, 4))
        tree.configure(yscrollcommand=sc.set)

        # ---------- actions ----------
        actions = ctk.CTkFrame(win, fg_color='transparent')
        actions.pack(fill='x', padx=12, pady=(0, 4))
        ctk.CTkButton(actions, text='✎ Edit (Ctrl+E)', width=125, height=28,
                      fg_color='#1f538d', hover_color='#143c68',
                      command=lambda: edit_selected()
                      ).pack(side='left', padx=(0, 6))
        ctk.CTkButton(actions, text='🔒 Freeze (Ctrl+F)', width=135, height=28,
                      fg_color='#7c3aed', hover_color='#6d28d9',
                      command=lambda: freeze_selected(True)
                      ).pack(side='left', padx=(0, 6))
        ctk.CTkButton(actions, text='🔓 Unfreeze', width=105, height=28,
                      fg_color='#a16207', hover_color='#854d0e',
                      command=lambda: freeze_selected(False)
                      ).pack(side='left', padx=(0, 6))
        ctk.CTkButton(actions, text='✖ Delete (Ctrl+D)', width=125, height=28,
                      fg_color='#991B1B', hover_color='#7f1d1d',
                      command=lambda: delete_selected()
                      ).pack(side='left', padx=(0, 6))
        ctk.CTkButton(actions, text='💾 Save Preset', width=130, height=28,
                      fg_color='#0d9488', hover_color='#0f766e',
                      command=lambda: save_preset()
                      ).pack(side='left', padx=(0, 6))
        ctk.CTkButton(actions, text='📂 Load Preset', width=130, height=28,
                      fg_color='#0d9488', hover_color='#0f766e',
                      command=lambda: load_preset()
                      ).pack(side='left', padx=(0, 6))
        ctk.CTkButton(actions, text='← Kembali', width=110, height=28,
                      fg_color='#991B1B', hover_color='#7f1d1d',
                      command=lambda: close_win()).pack(side='right')

        # ---------- log ----------
        log_box = ctk.CTkTextbox(win, height=90, font=('Consolas', 10),
                                  fg_color='#000000', text_color='#22c55e')
        log_box.pack(fill='x', padx=12, pady=(0, 10))
        log_box.configure(state='disabled')

        def log(msg):
            try:
                if not win.winfo_exists():
                    return
                log_box.configure(state='normal')
                log_box.insert('end', msg + '\n')
                log_box.see('end')
                log_box.configure(state='disabled')
            except Exception:
                pass

        def set_progress(pct, msg=None):
            try:
                prog_bar.set(min(1.0, max(0.0, pct)))
                if msg is not None:
                    prog_label.configure(text=msg)
            except Exception:
                pass

        def set_scan_buttons(enabled):
            st = 'normal' if enabled else 'disabled'
            try:
                first_btn.configure(state=st)
                next_btn.configure(state=st)
            except Exception:
                pass

        def module_of(addr):
            for m in state['modules']:
                if m['base'] <= addr < m['base'] + m['size']:
                    return m['name']
            return '?'

        def render_results():
            try:
                for i in tree.get_children():
                    tree.delete(i)
                for addr, data in state['results'][:5000]:
                    val = format_value(data, state['value_type'])
                    frz = 'YES' if addr in state['frozen'] else ''
                    tree.insert('', 'end',
                                values=(f'0x{addr:X}', module_of(addr), val, frz))
                if len(state['results']) > 5000:
                    log(f'[!] Menampilkan 5000 dari {len(state["results"])} hasil.')
            except Exception:
                pass

        # ---------- process actions ----------
        def refresh_procs():
            def worker():
                try:
                    procs = list_processes()
                    entries = ([f'{name}  [pid {pid}]' for pid, name in procs]
                               or ['(none)'])
                    def apply():
                        try:
                            if win.winfo_exists():
                                proc_menu.configure(values=entries)
                                proc_var.set(entries[0])
                        except Exception:
                            pass
                    safe_after(0, apply)
                except Exception:
                    pass
            threading.Thread(target=worker, daemon=True).start()

        refresh_btn.configure(command=refresh_procs)

        def on_module_change(value):
            try:
                name = value.rsplit('  [', 1)[0]
                for m in state['modules']:
                    if m['name'] == name:
                        state['main_module'] = m
                        log(f'[*] Module scope = {name}')
                        return
            except Exception:
                pass

        module_menu.configure(command=on_module_change)

        def attach_proc():
            text = proc_var.get()
            if text in ('(no process)', '(none)', ''):
                messagebox.showwarning('Mods', 'Pilih proses terlebih dahulu.', parent=win)
                return
            try:
                pid = int(text.rsplit('pid ', 1)[1].rstrip(']'))
            except Exception:
                messagebox.showerror('Mods', 'Format proses tidak valid.', parent=win)
                return
            h = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not h:
                h = kernel32.OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
                    PROCESS_VM_WRITE | PROCESS_VM_OPERATION, False, pid)
            if not h:
                messagebox.showerror('Mods',
                    f'Gagal attach PID {pid}.\n'
                    'Jalankan JKSY sebagai Administrator untuk akses penuh.',
                    parent=win)
                return
            if state['handle']:
                kernel32.CloseHandle(state['handle'])
            state.update(handle=h, pid=pid, proc_name=text, results=[], frozen={})
            state['modules'] = list_modules(h)
            base_name = text.split('  ')[0].lower()
            main = next((m for m in state['modules']
                         if m['name'].lower() == base_name), None)
            state['main_module'] = main or (state['modules'][0] if state['modules'] else None)
            mod_entries = ([f"{m['name']}  [0x{m['base']:X}]" for m in state['modules']]
                           or ['(no modules)'])
            module_menu.configure(values=mod_entries)
            if state['main_module']:
                module_var.set(next(e for e in mod_entries
                                    if e.startswith(state['main_module']['name'])))
            else:
                module_var.set(mod_entries[0])
            status_label.configure(text=f'ATTACHED pid {pid}', text_color='#22c55e')
            render_results()
            log(f'[+] Attached PID {pid} ({text}) — {len(state["modules"])} module(s)')
            if state['main_module']:
                log(f'[*] Main module: {state["main_module"]["name"]}')

        def detach():
            freeze_ctl['flag'] = False
            if state['handle']:
                kernel32.CloseHandle(state['handle'])
            state.update(handle=None, pid=None, proc_name='', modules=[],
                         main_module=None, results=[], frozen={})
            status_label.configure(text='DETACHED', text_color='#ef4444')
            module_menu.configure(values=['(no modules)'])
            module_var.set('(no modules)')
            render_results()
            log('[*] Detached')

        # ---------- freeze thread (bug 5) ----------
        def ensure_freeze_thread():
            if freeze_ctl['flag']:
                return
            freeze_ctl['flag'] = True
            def loop():
                warned = set()
                while freeze_ctl['flag'] and state['handle']:
                    handle = state['handle']
                    for addr, data in list(state['frozen'].items()):
                        if not write_memory(handle, addr, data):
                            if addr not in warned:
                                warned.add(addr)
                                safe_after(0, lambda a=addr: log(
                                    f'[!] Freeze 0x{a:X} gagal write (read-only/denied)'))
                    time.sleep(0.05)
                freeze_ctl['flag'] = False
            threading.Thread(target=loop, daemon=True).start()

        def selected_addr():
            sel = tree.selection()
            if not sel:
                return None
            try:
                return int(tree.item(sel[0], 'values')[0], 16)
            except Exception:
                return None

        def scope_regions(handle):
            if state['scan_scope'] == 'Module':
                if state['main_module']:
                    m = state['main_module']
                    return get_readable_regions(handle, m['base'], m['size'])
                log('[!] Scope=Module tapi modul belum dipilih — fallback full process.')
            return get_readable_regions(handle)

        # ---------- scans (bug 4, 6, 7) ----------
        def first_scan():
            if scan_busy['flag']:
                return
            if not state['handle']:
                messagebox.showwarning('Mods', 'Attach ke proses terlebih dahulu.', parent=win)
                return
            try:
                needle = pack_value(value_entry.get(), state['value_type'])
            except Exception as e:
                messagebox.showerror('Mods', f'Value tidak valid: {e}', parent=win)
                return
            if not needle:
                messagebox.showerror('Mods', 'Value kosong.', parent=win)
                return
            state['results'], state['frozen'] = [], {}
            state['stop_flag'] = False
            render_results()
            set_progress(0, 'Scanning...')
            set_scan_buttons(False)
            scan_busy['flag'] = True
            log(f'[*] First scan {state["value_type"]} = {value_entry.get()} '
                f'[scope={state["scan_scope"]}]')
            handle = state['handle']

            def worker():
                found = []
                try:
                    regions = scope_regions(handle)
                    total = sum(r[1] for r in regions) or 1
                    processed = 0
                    for base, size in regions:
                        if state['stop_flag'] or state['handle'] != handle:
                            break
                        data = read_region_chunked(handle, base, size)
                        if data:
                            idx = 0
                            while True:
                                idx = data.find(needle, idx)
                                if idx < 0:
                                    break
                                found.append([base + idx, needle])
                                idx += 1
                                if len(found) >= MAX_RESULTS:
                                    break
                        processed += size
                        if len(found) >= MAX_RESULTS:
                            break
                        if (processed & 0x3FFFFF) < size:
                            pct, n = processed / total, len(found)
                            safe_after(0, lambda p=pct, c=n:
                                       set_progress(p, f'Scanning... {c} found'))
                except Exception as e:
                    safe_after(0, lambda err=str(e): log(f'[!] Scan error: {err}'))
                def done():
                    try:
                        state['results'] = found
                        render_results()
                        set_progress(1.0, f'Done. {len(found)} result(s).')
                        log(f'[+] First scan done: {len(found)} result(s)')
                    finally:
                        scan_busy['flag'] = False
                        set_scan_buttons(True)
                safe_after(0, done)
            threading.Thread(target=worker, daemon=True).start()

        def next_scan():
            if scan_busy['flag']:
                return
            if not state['handle'] or not state['results']:
                messagebox.showwarning('Mods', 'Lakukan First Scan terlebih dahulu.', parent=win)
                return
            mode = filter_var.get().lower()
            handle, vtype = state['handle'], state['value_type']
            size = TYPE_SIZES.get(vtype, 0)
            read_size = size if size else 256
            snapshot = list(state['results'])
            try:
                exact_target = pack_value(value_entry.get(), vtype) if mode == 'exact' else None
            except Exception as e:
                messagebox.showerror('Mods', f'Value tidak valid: {e}', parent=win)
                return
            set_progress(0, f'Next scan ({mode})...')
            set_scan_buttons(False)
            scan_busy['flag'] = True
            log(f'[*] Next scan filter={mode}')

            def worker():
                survivors = []
                try:
                    for addr, prev_bytes in snapshot:
                        if state['handle'] != handle:
                            return
                        cur = read_memory(handle, addr, read_size)
                        if cur is None:
                            continue
                        keep, new_bytes = False, prev_bytes
                        if mode == 'exact':
                            if cur.startswith(exact_target):
                                keep, new_bytes = True, exact_target
                        else:
                            new_bytes = cur[:len(prev_bytes)] if len(cur) >= len(prev_bytes) else cur
                            if mode == 'changed':
                                keep = new_bytes != prev_bytes
                            elif mode == 'unchanged':
                                keep = new_bytes == prev_bytes
                            elif mode in ('increased', 'decreased') and \
                                    vtype in ('INT32', 'INT64', 'FLOAT', 'DOUBLE'):
                                a = unpack_value(prev_bytes, vtype)
                                b = unpack_value(cur, vtype)
                                if a is not None and b is not None:
                                    keep = (b > a) if mode == 'increased' else (b < a)
                        if keep:
                            survivors.append([addr, new_bytes])
                            if len(survivors) >= MAX_RESULTS:
                                break
                except Exception as e:
                    safe_after(0, lambda err=str(e): log(f'[!] Next scan error: {err}'))
                def done():
                    try:
                        state['results'] = survivors
                        still_frozen = sum(1 for a in state['frozen']
                                           if any(a == s[0] for s in survivors))
                        hidden = len(state['frozen']) - still_frozen
                        if hidden > 0:
                            log(f'[!] {hidden} address masih frozen tapi tidak terlihat di results.')
                        render_results()
                        set_progress(1.0, f'Next scan done: {len(survivors)} result(s).')
                        log(f'[+] Next scan ({mode}): {len(survivors)} result(s)')
                    finally:
                        scan_busy['flag'] = False
                        set_scan_buttons(True)
                safe_after(0, done)
            threading.Thread(target=worker, daemon=True).start()

        def clear_results():
            state['results'], state['frozen'] = [], {}
            render_results()
            log('[*] Results cleared')

        # ---------- edit (bug 2: STRING null-pad) ----------
        def edit_dialog(addr):
            old_data = next((d for a, d in state['results'] if a == addr), b'')
            dlg = ctk.CTkToplevel(win)
            dlg.title('Edit Value')
            dlg.geometry('380x210')
            dlg.transient(win)
            dlg.grab_set()
            dlg.attributes('-topmost', True)
            ctk.CTkLabel(dlg, text=f'0x{addr:X}  ({state["value_type"]})',
                         font=('Consolas', 12, 'bold')).pack(pady=(16, 6))
            if state['value_type'] == 'STRING':
                ctk.CTkLabel(dlg,
                    text=f'Old length: {len(old_data)} bytes — new string akan null-padded',
                    font=('Segoe UI', 9), text_color='#94a3b8').pack()
            entry = ctk.CTkEntry(dlg, width=320, height=32)
            entry.pack(pady=6)
            entry.insert(0, format_value(old_data, state['value_type']))
            def apply():
                try:
                    new_bytes = pack_value_padded(entry.get(), state['value_type'],
                                                   old_len=len(old_data))
                except Exception as e:
                    messagebox.showerror('Mods', f'Value tidak valid: {e}', parent=dlg)
                    return
                if not write_memory(state['handle'], addr, new_bytes):
                    messagebox.showerror('Mods',
                        'Gagal menulis memori (read-only atau access denied).',
                        parent=dlg)
                    return
                for i, (a, _) in enumerate(state['results']):
                    if a == addr:
                        state['results'][i] = [a, new_bytes]
                        break
                if addr in state['frozen']:
                    state['frozen'][addr] = new_bytes
                render_results()
                log(f'[✓] Write 0x{addr:X} = {entry.get()}')
                dlg.destroy()
            btns = ctk.CTkFrame(dlg, fg_color='transparent')
            btns.pack(pady=10)
            ctk.CTkButton(btns, text='Apply', width=130,
                          fg_color='#2b8a3e', command=apply
                          ).pack(side='left', padx=4)
            ctk.CTkButton(btns, text='Cancel', width=130,
                          fg_color='#991B1B', command=dlg.destroy
                          ).pack(side='left', padx=4)
            entry.focus_set()
            entry.bind('<Return>', lambda e: apply())

        def edit_selected():
            a = selected_addr()
            if a is None:
                messagebox.showwarning('Mods', 'Pilih baris dulu.', parent=win)
                return
            edit_dialog(a)

        def freeze_selected(freeze):
            a = selected_addr()
            if a is None:
                messagebox.showwarning('Mods', 'Pilih baris dulu.', parent=win)
                return
            if freeze:
                for ad, data in state['results']:
                    if ad == a:
                        state['frozen'][a] = data
                        break
                ensure_freeze_thread()
                log(f'[❄] Freeze 0x{a:X}')
            else:
                state['frozen'].pop(a, None)
                log(f'[☀] Unfreeze 0x{a:X}')
            render_results()

        def delete_selected():
            a = selected_addr()
            if a is None:
                return
            state['results'] = [r for r in state['results'] if r[0] != a]
            state['frozen'].pop(a, None)
            render_results()

        # ---------- preset save (bug 9) ----------
        def save_preset():
            if not state['results']:
                messagebox.showwarning('Mods', 'Tidak ada hasil untuk disimpan.', parent=win)
                return
            dlg = ctk.CTkToplevel(win)
            dlg.title('Save Preset')
            dlg.geometry('360x190')
            dlg.transient(win)
            dlg.grab_set()
            dlg.attributes('-topmost', True)
            ctk.CTkLabel(dlg, text='Nama preset:').pack(pady=(16, 6))
            name_e = ctk.CTkEntry(dlg, width=280, height=30)
            name_e.pack(pady=4)
            name_e.insert(0, (state['proc_name'].split('  ')[0] or 'preset').strip())
            def do_save():
                nm = name_e.get().strip()
                if not nm:
                    return
                preset_data.setdefault('presets', []).append({
                    'name': nm,
                    'type': state['value_type'],
                    'scope': state['scan_scope'],
                    'entries': [[f'{a:X}', data.hex()]
                                for a, data in state['results'][:200]],
                })
                err = save_presets(preset_data)
                if err:
                    messagebox.showerror('Mods',
                        f'Gagal menyimpan preset:\n{err}\n\n'
                        'Pastikan folder toolskit/ dapat ditulis.',
                        parent=dlg)
                    return
                log(f'[💾] Preset "{nm}" disimpan ({len(state["results"])} entri).')
                dlg.destroy()
            ctk.CTkButton(dlg, text='Save', width=130,
                          fg_color='#0d9488', command=do_save
                          ).pack(pady=10)
            name_e.focus_set()

        # ---------- preset load (bug 8: validasi) ----------
        def load_preset():
            presets = preset_data.get('presets', [])
            if not presets:
                messagebox.showinfo('Mods', 'Belum ada preset tersimpan.', parent=win)
                return
            if not state['handle']:
                messagebox.showwarning('Mods',
                    'Attach ke proses dulu sebelum load preset.', parent=win)
                return
            dlg = ctk.CTkToplevel(win)
            dlg.title('Load Preset')
            dlg.geometry('420x340')
            dlg.transient(win)
            dlg.grab_set()
            dlg.attributes('-topmost', True)
            ctk.CTkLabel(dlg, text='Pilih preset:').pack(pady=(14, 6))
            lb = ctk.CTkScrollableFrame(dlg, width=360, height=220,
                                        fg_color='#111', corner_radius=6)
            lb.pack(padx=14, pady=6)
            def pick(idx):
                chosen = presets[idx]
                handle = state['handle']
                valid, invalid = [], 0
                for a_hex, data_hex in chosen.get('entries', []):
                    try:
                        addr = int(a_hex, 16)
                        if read_memory(handle, addr, 8) is not None:
                            valid.append([addr, bytes.fromhex(data_hex)])
                        else:
                            invalid += 1
                    except Exception:
                        invalid += 1
                if not valid:
                    messagebox.showwarning('Mods',
                        'Semua address tidak valid untuk proses saat ini.\n'
                        'Preset mungkin dari PID berbeda atau layout memori berubah.',
                        parent=dlg)
                    return
                state['value_type'] = chosen.get('type', state['value_type'])
                type_var.set(state['value_type'])
                state['results'] = valid
                state['frozen'] = {}
                render_results()
                if invalid:
                    log(f'[📂] Preset "{chosen["name"]}" loaded — '
                        f'{len(valid)} valid, {invalid} dilewati.')
                else:
                    log(f'[📂] Preset "{chosen["name"]}" loaded — {len(valid)} addr.')
                dlg.destroy()
            for i, p in enumerate(presets):
                txt = f"{p['name']}  •  {p.get('type','?')}  •  {len(p.get('entries',[]))} addr"
                ctk.CTkButton(lb, text=txt, width=340, height=28,
                              fg_color='#1f538d', hover_color='#143c68',
                              command=lambda idx=i: pick(idx)).pack(pady=3)

        # ---------- speed hack (bug 10 + akurasi) ----------
        def open_speed_hack():
            if not state['handle']:
                messagebox.showwarning('Mods', 'Attach dulu ke proses.', parent=win)
                return
            if not state['modules']:
                messagebox.showwarning('Mods', 'Tidak ada modul terdeteksi.', parent=win)
                return
            sh = ctk.CTkToplevel(win)
            sh.title('Speed Hack')
            sh.geometry('500x600')
            sh.transient(win)
            sh.attributes('-topmost', True)
            sh.configure(fg_color='#0f1012')
            sh_state = {
                'module': state['main_module'] or state['modules'][0],
                'scan_value': 1.0,
                'freeze_value': 2.0,
                'found': [],
                'applied': [],
            }
            ctk.CTkLabel(sh, text='⚡ SPEED HACK',
                         font=('Segoe UI', 17, 'bold'), text_color='#f59e0b'
                         ).pack(pady=(14, 4))
            ctk.CTkLabel(sh,
                text='Scan nilai float "baseline" lalu freeze ke nilai baru.\n'
                     '• Engine modern (Unity/Unreal/Godot): baseline = 1.0 (time_scale)\n'
                     '• Engine custom: baseline ≈ 0.016 (delta time)\n'
                     '• Freeze 2.0 dengan baseline 1.0 → 2× lebih cepat.',
                wraplength=460, justify='left', text_color='#94a3b8',
                font=('Segoe UI', 10)).pack(padx=20, pady=(0, 8))

            # module selector (bug 10)
            mod_frame = ctk.CTkFrame(sh, fg_color='#17181b', corner_radius=8)
            mod_frame.pack(fill='x', padx=20, pady=4)
            ctk.CTkLabel(mod_frame, text='Module:',
                         font=('Segoe UI', 11, 'bold')).pack(side='left', padx=(10, 4), pady=8)
            sh_mod_var = ctk.StringVar(value=sh_state['module']['name'])
            ctk.CTkOptionMenu(mod_frame, variable=sh_mod_var,
                              values=[m['name'] for m in state['modules']],
                              width=280, fg_color='#0d9488', button_color='#0f766e',
                              command=lambda v: sh_on_module(v)
                              ).pack(side='left', padx=4, pady=8)

            # scan value
            s_frame = ctk.CTkFrame(sh, fg_color='#17181b', corner_radius=8)
            s_frame.pack(fill='x', padx=20, pady=4)
            ctk.CTkLabel(s_frame, text='Scan for value:',
                         font=('Segoe UI', 11, 'bold')).pack(side='left', padx=(10, 4), pady=8)
            scan_e = ctk.CTkEntry(s_frame, width=120, height=28)
            scan_e.pack(side='left', padx=4, pady=8)
            scan_e.insert(0, '1.0')
            ctk.CTkButton(s_frame, text='🔍 Scan', width=110, height=28,
                          fg_color='#0891b2', hover_color='#0e7490',
                          command=lambda: do_scan()
                          ).pack(side='left', padx=4, pady=8)

            # freeze value
            f_frame = ctk.CTkFrame(sh, fg_color='#17181b', corner_radius=8)
            f_frame.pack(fill='x', padx=20, pady=4)
            ctk.CTkLabel(f_frame, text='Freeze to value:',
                         font=('Segoe UI', 11, 'bold')).pack(side='left', padx=(10, 4), pady=8)
            freeze_e = ctk.CTkEntry(f_frame, width=120, height=28)
            freeze_e.pack(side='left', padx=4, pady=8)
            freeze_e.insert(0, '2.0')
            ctk.CTkButton(f_frame, text='✅ Apply+Freeze', width=140, height=28,
                          fg_color='#2b8a3e', hover_color='#216e31',
                          command=lambda: do_apply()
                          ).pack(side='left', padx=4, pady=8)

            info = ctk.CTkLabel(sh, text='Klik Scan dulu untuk cari kandidat.',
                                font=('Consolas', 10), text_color='#94a3b8',
                                wraplength=460)
            info.pack(pady=6)

            def sh_on_module(v):
                for m in state['modules']:
                    if m['name'] == v:
                        sh_state['module'] = m
                        sh_state['found'] = []
                        info.configure(text=f'Module: {v} — Scan ulang untuk refresh.',
                                       text_color='#f59e0b')
                        return

            def do_scan():
                try:
                    target = float(scan_e.get())
                except ValueError:
                    messagebox.showerror('Speed Hack', 'Scan value harus angka float.', parent=sh)
                    return
                sh_state['scan_value'] = target
                needle = struct.pack('<f', target)
                m = sh_state['module']
                handle = state['handle']
                info.configure(text='Scanning...', text_color='#f59e0b')
                def worker():
                    addrs = []
                    try:
                        regions = get_readable_regions(handle, m['base'], m['size'])
                        for base, size in regions:
                            if state['handle'] != handle:
                                return
                            data = read_region_chunked(handle, base, size)
                            if data:
                                i = 0
                                while True:
                                    i = data.find(needle, i)
                                    if i < 0:
                                        break
                                    addrs.append(base + i)
                                    i += 1
                                    if len(addrs) >= 100000:
                                        break
                            if len(addrs) >= 100000:
                                break
                        sh_state['found'] = addrs
                        msg = (f'Ditemukan {len(addrs)} kandidat {target} di {m["name"]}.'
                               if addrs else
                               f'Tidak ditemukan float {target}. Coba nilai lain '
                               f'(mis. 1.0 atau 0.016).')
                        color = '#22c55e' if addrs else '#ef4444'
                        safe_after(0, lambda: info.configure(text=msg, text_color=color))
                    except Exception as e:
                        safe_after(0, lambda err=str(e):
                                   info.configure(text=f'Error: {err}', text_color='#ef4444'))
                threading.Thread(target=worker, daemon=True).start()

            def do_apply():
                if not sh_state['found']:
                    messagebox.showwarning('Speed Hack',
                        'Scan dulu untuk cari kandidat.', parent=sh)
                    return
                try:
                    fv = float(freeze_e.get())
                except ValueError:
                    messagebox.showerror('Speed Hack',
                        'Freeze value harus angka float.', parent=sh)
                    return
                sh_state['freeze_value'] = fv
                needle = struct.pack('<f', fv)
                handle = state['handle']
                applied = []
                for a in sh_state['found']:
                    if write_memory(handle, a, needle):
                        state['frozen'][a] = needle
                        applied.append(a)
                sh_state['applied'] = applied
                ensure_freeze_thread()
                info.configure(
                    text=f'Freeze {len(applied)}/{len(sh_state["found"])} addr '
                         f'@ {fv} (berjalan di background).',
                    text_color='#22c55e')
                log(f'[⚡] Speed Hack freeze {len(applied)} addr @ {fv}')
                render_results()

            def do_reset():
                # tulis balik scan_value (baseline semula)
                needle = struct.pack('<f', sh_state['scan_value'])
                reset = 0
                handle = state['handle']
                for a in list(state['frozen'].keys()):
                    if write_memory(handle, a, needle):
                        state['frozen'].pop(a, None)
                        reset += 1
                info.configure(
                    text=f'Reset {reset} addr ke {sh_state["scan_value"]} (normal).',
                    text_color='#22c55e')
                log(f'[⚡] Speed Hack reset {reset} addr → {sh_state["scan_value"]}')
                render_results()

            ctk.CTkButton(sh, text='↺ Reset (baseline)', width=200, height=30,
                          fg_color='#a16207', hover_color='#854d0e',
                          command=do_reset).pack(pady=(10, 4))
            ctk.CTkButton(sh, text='← Tutup', width=120, height=28,
                          fg_color='#991B1B', hover_color='#7f1d1d',
                          command=sh.destroy).pack(pady=(4, 14))

        # ---------- hotkeys ----------
        def bind_hotkeys():
            def wrap(fn):
                def h(event):
                    try:
                        w = event.widget
                        while w is not None:
                            if w == win:
                                fn()
                                return 'break'
                            w = getattr(w, 'master', None)
                    except Exception:
                        pass
                    return None
                return h
            for seq, fn in [
                ('<Control-s>', next_scan), ('<Control-S>', next_scan),
                ('<Control-g>', first_scan), ('<Control-G>', first_scan),
                ('<Control-e>', edit_selected), ('<Control-E>', edit_selected),
                ('<Control-f>', lambda: freeze_selected(True)),
                ('<Control-F>', lambda: freeze_selected(True)),
                ('<Control-d>', delete_selected), ('<Control-D>', delete_selected),
            ]:
                try:
                    win.bind_all(seq, wrap(fn))
                except Exception:
                    pass

        tree.bind('<Double-1>', lambda e: edit_selected())

        def close_win():
            state['stop_flag'] = True
            freeze_ctl['flag'] = False
            try:
                for seq in ('<Control-s>', '<Control-S>', '<Control-g>', '<Control-G>',
                            '<Control-e>', '<Control-E>', '<Control-f>', '<Control-F>',
                            '<Control-d>', '<Control-D>'):
                    win.unbind_all(seq)
            except Exception:
                pass
            if state['handle']:
                kernel32.CloseHandle(state['handle'])
                state['handle'] = None
            win.destroy()
            if parent.winfo_exists():
                parent.deiconify()
                parent.lift()

        win.protocol('WM_DELETE_WINDOW', close_win)
        bind_hotkeys()
        refresh_procs()
        log('JKSY Mods v2.1 ready.')
        log('Hotkeys: Ctrl+G First • Ctrl+S Next • Ctrl+E Edit • Ctrl+F Freeze • Ctrl+D Delete')
        log('Tip: Scope "Module" setelah Attach = scan 10-100× lebih cepat.')
        return win