"""JKSY Nawala v2 — Internet Positif (Trust+Positif Komdigi) checker.

Free tier: 20 domain. Auth Key: 100000 domain.
Metode berlapis:
  1. API resmi Trust+Positif: trustpositif.komdigi.go.id/api/check
  2. DNS multi-ISP: Nawala, IndiHome, Telkomsel, Biznet, First Media, MyRepublic
     - Deteksi CNAME redirect ke internetpositif.id / internetsehatku.com
     - Deteksi sinkhole IP (36.86.63.x, 103.155.26.29, 0.0.0.0, dll.)
  3. HTTP redirect fallback ke halaman blokir

Catatan: DNS Nawala hanya memblokir saat diakses dari IP Indonesia.
Tool akan memberi peringatan jika dijalankan dari luar Indonesia.
"""
import hashlib
import hmac
import ipaddress
import json
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from tkinter import filedialog, messagebox, ttk
from urllib.parse import urlparse

import customtkinter as ctk

try:
    import requests
except ImportError:
    requests = None

try:
    import dns.resolver as dns_resolver
except ImportError:
    dns_resolver = None

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

FREE_LIMIT = 20
PREMIUM_LIMIT = 100000

# --- Auth key (sama dengan launcher aplikasi.py) ---
_AUTH_SALT = bytes.fromhex('a51477c90d6283b4e932bc1465f6ae82')
_AUTH_EXPECTED = bytes.fromhex('761d7544d567650461f340dfaa7ad7b6d72d65e48ac8eff9924c71b84b9dce56')

# --- Trust+Positif API resmi ---
TRUSTPOSITIF_API = 'https://trustpositif.komdigi.go.id/api/check'

# --- DNS resolver per ISP ---
ISP_RESOLVERS = {
    'Nawala':     '180.131.144.144',
    'IndiHome':   '118.98.44.10',
    'Telkomsel':  '198.0.0.1',
    'Biznet':     '180.131.144.144',  # Nawala = Biznet default
    'FirstMedia': '103.12.160.2',
    'MyRepublic': '202.152.2.2',
}
# Resolver sekunder Nawala
BLOCK_SECONDARY = '180.131.145.145'

# --- CNAME / IP indikator blokir ---
BLOCK_CNAME_KEYWORDS = (
    'internetpositif.id',
    'internetsehatku.com',
    'trustpositif.komdigi.go.id',
    'nawala',
)
BLOCK_IPS = {
    '0.0.0.0', '127.0.0.1',
    '36.86.63.182',    # IndiHome block page[reference:7]
    '36.86.63.186',
    '103.155.26.29',   # Komdigi sinkhole[reference:8]
}


def _verify_key(candidate):
    try:
        actual = hashlib.pbkdf2_hmac('sha256', candidate.encode('utf-8'),
                                     _AUTH_SALT, 240000)
        return hmac.compare_digest(actual, _AUTH_EXPECTED)
    except Exception:
        return False


def _normalize(text):
    """Convert URL/domain input to bare hostname. Return None if invalid."""
    text = text.strip().lower()
    if not text or text.startswith('#'):
        return None
    if '://' in text:
        text = urlparse(text).netloc or text
    elif '/' in text:
        text = text.split('/', 1)[0]
    if ':' in text and not text.startswith('['):
        text = text.split(':', 1)[0]
    text = text.strip('.').strip()
    if not text or '.' not in text or ' ' in text:
        return None
    return text


# ---------------------------------------------------------------- checkers
def _check_trustpositif(domain, session):
    """API resmi Trust+Positif. Return (status, detail) atau None jika gagal."""
    if not session:
        return None
    try:
        r = session.get(
            TRUSTPOSITIF_API,
            params={'domain': domain},
            timeout=6,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) JKSY-Nawala/2.0'},
            verify=False,
        )
        if r.status_code != 200:
            return ('ERROR', f'Trust+Positif HTTP {r.status_code}')
        try:
            data = r.json()
        except Exception:
            return ('ERROR', 'Trust+Positif response bukan JSON')
        status = str(data.get('status', '')).strip().lower()
        if status == 'blocked':
            return ('BLOCKED', 'Trust+Positif DB: blocked')
        if data.get('blocked') is True:
            return ('BLOCKED', 'Trust+Positif DB: blocked (bool)')
        # selain blocked dianggap clear[reference:9]
        return ('CLEAR', f'Trust+Positif DB: {status or "clear"}')
    except Exception as e:
        return ('ERROR', f'Trust+Positif error: {str(e)[:50]}')


def _query_dns(domain, nameserver, timeout=3):
    """Query A record via specific nameserver, deteksi CNAME/IP blokir."""
    if not dns_resolver:
        return ('ERROR', 'dnspython tidak tersedia')
    try:
        resolver = dns_resolver.Resolver(configure=False)
        resolver.nameservers = [nameserver]
        resolver.timeout = timeout
        resolver.lifetime = timeout
        ans = resolver.resolve(domain, 'A', raise_on_no_answer=False)
        if ans.rrset is None and ans.canonical_name is None:
            return ('NOT FOUND', 'Tidak ada A/CNAME record')
        # kumpulkan semua record text (termasuk CNAME di answer section)
        parts = []
        try:
            for rrset in ans.response.answer:
                parts.append(str(rrset))
        except Exception:
            if ans.rrset is not None:
                parts.append(str(ans.rrset))
        parts.append(str(ans.canonical_name))
        combined = ' '.join(parts).lower()
        for kw in BLOCK_CNAME_KEYWORDS:
            if kw in combined:
                return ('BLOCKED', f'DNS redirect → {kw}')
        ips = [str(r) for r in ans.rrset] if ans.rrset is not None else []
        for ip in ips:
            if ip in BLOCK_IPS:
                return ('BLOCKED', f'Sinkhole IP {ip}')
        if ips:
            return ('CLEAR', f'DNS OK → {ips[0]}')
        return ('CLEAR', 'DNS resolved tanpa A record')
    except dns_resolver.NXDOMAIN:
        return ('NOT FOUND', 'Domain tidak terdaftar di DNS')
    except dns_resolver.NoNameservers:
        return ('ERROR', 'Nameserver menolak query')
    except Exception:
        return ('ERROR', 'DNS timeout / unreachable')


def _check_http(domain, session):
    """Fallback: HTTP redirect ke halaman blokir."""
    if not session:
        return None
    try:
        r = session.get(f'http://{domain}', timeout=8, allow_redirects=True,
                        headers={'User-Agent': 'Mozilla/5.0'})
        final = (r.url or '').lower()
        if 'internetpositif' in final or 'trustpositif' in final:
            return ('BLOCKED', 'HTTP redirect → halaman blokir')
        snippet = (r.text or '')[:3000].lower()
        if 'internet positif' in snippet or 'situs yang anda' in snippet:
            return ('BLOCKED', 'Konten halaman blokir terdeteksi')
        if r.status_code < 500:
            return ('CLEAR', f'HTTP {r.status_code}')
        return ('ERROR', f'HTTP {r.status_code}')
    except Exception:
        return None


def _check_one(domain):
    """Urutan: Trust+Positif → DNS Nawala → DNS ISP lain → HTTP."""
    session = requests.Session() if requests else None
    try:
        # 1. Trust+Positif API
        tp = _check_trustpositif(domain, session)
        if tp and tp[0] == 'BLOCKED':
            return (domain, 'BLOCKED', 'Trust+Positif: BLOCKED (DB resmi)',
                    {'TrustPositif': tp[0]})

        # 2. DNS Nawala + ISP lain
        dns_results = {}
        block_source = None
        clear_source = None
        for isp, ns in ISP_RESOLVERS.items():
            st, detail = _query_dns(domain, ns)
            dns_results[isp] = st
            if st == 'BLOCKED' and block_source is None:
                block_source = f'{isp}: {detail}'
            elif st == 'CLEAR' and clear_source is None:
                clear_source = f'{isp}: {detail}'

        if block_source:
            return (domain, 'BLOCKED', f'DNS blocked → {block_source}', dns_results)

        # 3. HTTP fallback (jika DNS tidak memberi jawaban jelas)
        if not clear_source:
            http = _check_http(domain, session)
            if http and http[0] == 'BLOCKED':
                return (domain, 'BLOCKED', http[1], dns_results)
            if http and http[0] == 'CLEAR':
                clear_source = f'HTTP: {http[1]}'

        if clear_source:
            return (domain, 'CLEAR', clear_source, dns_results)

        # 4. Semua gagal
        return (domain, 'ERROR', 'Semua metode gagal / timeout', dns_results)
    finally:
        if session:
            try:
                session.close()
            except Exception:
                pass


def _detect_country():
    """Cek negara IP publik. Return countryCode (mis. 'ID') atau '' jika gagal."""
    try:
        req = urllib.request.Request(
            'http://ip-api.com/json/?fields=countryCode',
            headers={'User-Agent': 'JKSY-Nawala/2.0'})
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read().decode('utf-8'))
            return data.get('countryCode', '').upper()
    except Exception:
        return ''


# ---------------------------------------------------------------- main UI
def open_window(parent, unlocked=False):
    win = ctk.CTkToplevel(parent)
    win.title('JKSY • Nawala v2 — Bot Checker')
    win.geometry('980x780')
    win.minsize(940, 720)
    win.configure(fg_color='#0f1012')
    win.transient(parent)

    state = {
        'unlocked': bool(unlocked),
        'busy': False,
        'results': [],
        'country': '',
    }

    # ---------- header ----------
    header = ctk.CTkFrame(win, fg_color='#17181b', corner_radius=10)
    header.pack(fill='x', padx=12, pady=(10, 6))
    ctk.CTkLabel(header, text='🚫 JKSY BLOCK v2 — Bot Checker',
                 font=('Segoe UI', 18, 'bold'), text_color='#ef4444'
                 ).pack(anchor='w', padx=14, pady=(10, 2))
    ctk.CTkLabel(header,
        text='Sumber: JKSY AI API + DNS multi-ISP '
             '(Botnet). '
             'Free: 20 domain • Auth Key: 100000 domain.',
        font=('Segoe UI', 10), text_color='#94a3b8',
        wraplength=940, justify='left'
        ).pack(anchor='w', padx=14, pady=(0, 4))

    # warning IP non-Indonesia
    warning_var = ctk.StringVar(value='')
    warning_label = ctk.CTkLabel(header, textvariable=warning_var,
                                  font=('Segoe UI', 10, 'bold'),
                                  text_color='#f59e0b', wraplength=940,
                                  justify='left')

    # ---------- input ----------
    input_frame = ctk.CTkFrame(win, fg_color='#17181b', corner_radius=10)
    input_frame.pack(fill='x', padx=12, pady=(0, 6))
    row1 = ctk.CTkFrame(input_frame, fg_color='transparent')
    row1.pack(fill='x', padx=10, pady=(8, 4))
    ctk.CTkLabel(row1, text='Domain / URL (1 per baris):',
                 font=('Segoe UI', 11, 'bold')).pack(side='left')
    counter_var = ctk.StringVar(value='0 / 20')
    counter_label = ctk.CTkLabel(row1, textvariable=counter_var,
                                  font=('Consolas', 11, 'bold'),
                                  text_color='#22c55e')
    counter_label.pack(side='right')
    text_input = ctk.CTkTextbox(input_frame, height=130, font=('Consolas', 11),
                                 fg_color='#000000', text_color='#e5e7eb')
    text_input.pack(fill='x', padx=10, pady=(0, 8))

    auth_row = ctk.CTkFrame(input_frame, fg_color='transparent')
    auth_row.pack(fill='x', padx=10, pady=(0, 8))
    auth_btn = ctk.CTkButton(auth_row, text='🔒 Auth Key (unlock 100000)',
                             width=200, height=28, fg_color='#7c3aed',
                             hover_color='#6d28d9')
    auth_btn.pack(side='left')
    auth_status = ctk.CTkLabel(auth_row,
                                text=('Status: PREMIUM (max 100000)'
                                      if state['unlocked'] else 'Status: FREE (max 20)'),
                                font=('Segoe UI', 11),
                                text_color=('#22c55e' if state['unlocked']
                                            else '#f59e0b'))
    auth_status.pack(side='left', padx=10)
    check_btn = ctk.CTkButton(auth_row, text='🔍 Check Now', width=140,
                              height=28, fg_color='#2b8a3e', hover_color='#216e31')
    check_btn.pack(side='right')
    export_btn = ctk.CTkButton(auth_row, text='💾 Export', width=100,
                                height=28, fg_color='#1f538d',
                                hover_color='#143c68', state='disabled')
    export_btn.pack(side='right', padx=(0, 6))

    if state['unlocked']:
        auth_btn.configure(text='🔓 Unlocked', fg_color='#2b8a3e')

    # ---------- progress ----------
    progress = ctk.CTkProgressBar(win, height=10, progress_color='#ef4444')
    progress.pack(fill='x', padx=12, pady=(0, 3))
    progress.set(0)
    progress_label = ctk.CTkLabel(win, text='Ready.', font=('Consolas', 10),
                                   text_color='#94a3b8')
    progress_label.pack(anchor='w', padx=14, pady=(0, 4))

    # ---------- results tree ----------
    table_frame = ctk.CTkFrame(win, fg_color='#0b0c0e', corner_radius=8)
    table_frame.pack(fill='both', expand=True, padx=12, pady=(0, 6))
    style = ttk.Style()
    try:
        style.theme_use('clam')
    except Exception:
        pass
    style.configure('Nawala.Treeview', background='#0b0c0e',
                    foreground='#e5e7eb', fieldbackground='#0b0c0e',
                    rowheight=24, font=('Consolas', 10))
    style.configure('Nawala.Treeview.Heading', background='#17181b',
                    foreground='#ef4444', font=('Segoe UI', 10, 'bold'))
    style.map('Nawala.Treeview', background=[('selected', '#1f538d')])
    tree = ttk.Treeview(table_frame, columns=('domain', 'status', 'detail'),
                        show='headings', style='Nawala.Treeview', height=15)
    tree.heading('domain', text='Domain')
    tree.heading('status', text='Status')
    tree.heading('detail', text='Detail')
    tree.column('domain', width=260, anchor='w')
    tree.column('status', width=110, anchor='center')
    tree.column('detail', width=560, anchor='w')
    tree.tag_configure('blocked', foreground='#ef4444')
    tree.tag_configure('clear', foreground='#22c55e')
    tree.tag_configure('error', foreground='#f59e0b')
    tree.pack(side='left', fill='both', expand=True, padx=4, pady=4)
    scroll = ttk.Scrollbar(table_frame, orient='vertical', command=tree.yview)
    scroll.pack(side='right', fill='y', pady=4, padx=(0, 4))
    tree.configure(yscrollcommand=scroll.set)

    # ---------- summary ----------
    summary = ctk.CTkLabel(win, text='Belum ada pemeriksaan.',
                            font=('Segoe UI', 11, 'bold'),
                            text_color='#94a3b8')
    summary.pack(fill='x', padx=14, pady=(0, 4))

    # ---------- footer ----------
    bottom = ctk.CTkFrame(win, fg_color='transparent')
    bottom.pack(fill='x', padx=12, pady=(0, 10))
    ctk.CTkButton(bottom, text='← Kembali', width=120, height=28,
                  fg_color='#991B1B', hover_color='#7f1d1d',
                  command=lambda: close_win()).pack(side='right')

    # ---------- helpers ----------
    def parse_domains():
        text = text_input.get('1.0', 'end-1c')
        domains, seen = [], set()
        for line in text.splitlines():
            d = _normalize(line)
            if d and d not in seen:
                seen.add(d)
                domains.append(d)
        return domains

    def update_counter(*_args):
        try:
            domains = parse_domains()
            limit = PREMIUM_LIMIT if state['unlocked'] else FREE_LIMIT
            counter_var.set(f'{len(domains)} / {limit}')
            counter_label.configure(
                text_color='#22c55e' if len(domains) <= limit else '#ef4444')
        except Exception:
            pass

    text_input.bind('<KeyRelease>', update_counter)
    text_input.bind('<FocusOut>', update_counter)
    try:
        text_input.bind('<<Paste>>', lambda e: win.after(60, update_counter))
    except Exception:
        pass

    def country_worker():
        code = _detect_country()
        state['country'] = code
        def apply():
            try:
                if not win.winfo_exists():
                    return
                if code and code != 'ID':
                    warning_var.set(
                        f'⚠️ Koneksi Anda terdeteksi dari luar Indonesia (negara: {code}). '
                        'DNS Nawala/ISP Indonesia hanya memblokir saat diakses dari IP Indonesia — '
                        'hasil CLEAR bisa false-negative. Gunakan koneksi ISP Indonesia untuk akurasi.')
                    warning_label.pack(fill='x', padx=14, pady=(0, 8))
                elif not code:
                    warning_var.set(
                        '⚠️ Tidak dapat mendeteksi negara IP publik. '
                        'Pastikan Anda menggunakan koneksi ISP Indonesia untuk hasil akurat.')
                    warning_label.pack(fill='x', padx=14, pady=(0, 8))
            except Exception:
                pass
        win.after(0, apply)

    threading.Thread(target=country_worker, daemon=True).start()

    def open_auth():
        if state['unlocked']:
            messagebox.showinfo('Nawala', 'Auth Key sudah aktif (max 100000).',
                                parent=win)
            return
        dlg = ctk.CTkToplevel(win)
        dlg.title('Auth Key')
        dlg.geometry('390x220')
        dlg.transient(win)
        dlg.grab_set()
        dlg.attributes('-topmost', True)
        ctk.CTkLabel(dlg, text='🔒 Masukkan Auth Key',
                     font=('Segoe UI', 15, 'bold')).pack(pady=(18, 8))
        ctk.CTkLabel(dlg,
            text='Kunci ini membuka kapasitas hingga 100000 domain.',
            font=('Segoe UI', 10), text_color='#94a3b8').pack(pady=(0, 10))
        entry = ctk.CTkEntry(dlg, width=300, height=34, show='●',
                              placeholder_text='Input Auth Key')
        entry.pack(pady=4)
        feedback = ctk.CTkLabel(dlg, text='', text_color='#ef4444',
                                 font=('Segoe UI', 10))
        feedback.pack(pady=2)

        def verify():
            if _verify_key(entry.get()):
                state['unlocked'] = True
                auth_status.configure(text='Status: PREMIUM (max 100000)',
                                       text_color='#22c55e')
                auth_btn.configure(text='🔓 Unlocked', fg_color='#2b8a3e')
                dlg.destroy()
                update_counter()
            else:
                feedback.configure(text='Auth Key salah.')
                entry.delete(0, 'end')

        ctk.CTkButton(dlg, text='Verify', width=140, height=30,
                      fg_color='#2b8a3e', command=verify).pack(pady=8)
        entry.bind('<Return>', lambda e: verify())
        entry.focus_set()

    auth_btn.configure(command=open_auth)

    def run_check():
        if state['busy']:
            return
        domains = parse_domains()
        if not domains:
            messagebox.showwarning('Nawala',
                'Masukkan minimal 1 domain/URL.', parent=win)
            return
        limit = PREMIUM_LIMIT if state['unlocked'] else FREE_LIMIT
        if len(domains) > limit:
            messagebox.showwarning('Nawala',
                f'Maksimal {limit} domain pada mode ini.\n'
                'Klik 🔒 Auth Key untuk membuka hingga 100000 domain.',
                parent=win)
            return
        if not requests and not dns_resolver:
            messagebox.showerror('Nawala',
                'Modul requests/dnspython tidak tersedia.\n'
                'Install via: pip install requests dnspython',
                parent=win)
            return

        state['busy'] = True
        state['results'] = []
        check_btn.configure(state='disabled')
        export_btn.configure(state='disabled')
        for i in tree.get_children():
            tree.delete(i)
        progress.set(0)
        progress_label.configure(text=f'Checking {len(domains)} domain...')
        summary.configure(text='Running...', text_color='#f59e0b')

        def worker():
            completed = 0
            with ThreadPoolExecutor(max_workers=5) as ex:
                futures = {ex.submit(_check_one, d): d for d in domains}
                for fut in as_completed(futures):
                    try:
                        result = fut.result()
                    except Exception as e:
                        result = (futures[fut], 'ERROR', str(e)[:100000], {})
                    state['results'].append(result)
                    completed += 1
                    try:
                        win.after(0, lambda c=completed, n=len(domains):
                                  set_progress(c / n, f'{c}/{n} selesai'))
                        win.after(0, lambda r=result: render_row(r))
                    except Exception:
                        pass
            try:
                win.after(0, on_done)
            except Exception:
                pass

        threading.Thread(target=worker, daemon=True).start()

    def set_progress(pct, msg=None):
        try:
            progress.set(min(1.0, max(0.0, pct)))
            if msg is not None:
                progress_label.configure(text=msg)
        except Exception:
            pass

    def render_row(result):
        try:
            if not win.winfo_exists():
                return
            domain, status, detail, dns_map = result
            tag = ('blocked' if status == 'BLOCKED'
                   else 'clear' if status == 'CLEAR' else 'error')
            # ringkas detail per-ISP
            if dns_map:
                isp_summary = ', '.join(f'{k}={v}' for k, v in dns_map.items())
                full_detail = f'{detail}  |  {isp_summary}'
            else:
                full_detail = detail
            display_detail = full_detail if len(full_detail) <= 300 else full_detail[:297] + '...'
            tree.insert('', 'end', values=(domain, status, display_detail),
                        tags=(tag,))
        except Exception:
            pass

    def on_done():
        try:
            if not win.winfo_exists():
                return
            state['busy'] = False
            check_btn.configure(state='normal')
            blocked = sum(1 for r in state['results'] if r[1] == 'BLOCKED')
            clear = sum(1 for r in state['results'] if r[1] == 'CLEAR')
            errors = len(state['results']) - blocked - clear
            summary.configure(
                text=f'Selesai  •  Blocked: {blocked}  •  Clear: {clear}  •  '
                     f'Error/NotFound: {errors}',
                text_color='#22c55e' if blocked == 0 else '#ef4444')
            export_btn.configure(
                state='normal' if state['results'] else 'disabled')
        except Exception:
            pass

    def export_results():
        if not state['results']:
            return
        path = filedialog.asksaveasfilename(
            parent=win, defaultextension='.txt',
            filetypes=[('Text Files', '*.txt')],
            initialfile='nawala-check-v2.txt',
            title='Simpan hasil pemeriksaan')
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write('JKSY Nawala v2 — Internet Positif Check\n')
                f.write(f'Country detected: {state["country"] or "unknown"}\n')
                f.write('=' * 70 + '\n\n')
                f.write(f'Total: {len(state["results"])}\n\n')
                for domain, status, detail, dns_map in sorted(state['results'],
                                                               key=lambda r: r[0]):
                    f.write(f'{domain}\t{status}\n')
                    f.write(f'  detail: {detail}\n')
                    if dns_map:
                        f.write('  per-ISP: ' + ', '.join(
                            f'{k}={v}' for k, v in dns_map.items()) + '\n')
                    f.write('\n')
            messagebox.showinfo('Nawala',
                f'Hasil tersimpan:\n{path}', parent=win)
        except Exception as e:
            messagebox.showerror('Nawala',
                f'Gagal menyimpan: {e}', parent=win)

    check_btn.configure(command=run_check)
    export_btn.configure(command=export_results)

    def close_win():
        if state['busy']:
            if not messagebox.askyesno('Nawala',
                'Pemeriksaan masih berjalan. Tutup paksa?', parent=win):
                return
        win.destroy()
        if parent.winfo_exists():
            parent.deiconify()
            parent.lift()

    win.protocol('WM_DELETE_WINDOW', close_win)
    update_counter()
    return win