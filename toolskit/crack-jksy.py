"""JKSY Crack v2 — Offline Hash Cracker + Generator.

ETHICAL USE ONLY:
- Password recovery untuk hash MILIK SENDIRI
- CTF competitions
- Security audit sistem sendiri
- Educational research

Menggunakan tool ini untuk crack hash milik orang lain tanpa izin = ILLEGAL.
Anda bertanggung jawab penuh atas penggunaan.

Supported: MD5, SHA1, SHA224, SHA256, SHA384, SHA512, NTLM
Modes: Dictionary / Rules / Mask / Hybrid / Generator
"""
import hashlib
import hmac
import itertools
import os
import re
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from tkinter import filedialog, messagebox, ttk
import customtkinter as ctk

FREE_LIMIT = 20
PREMIUM_LIMIT = 500

_AUTH_SALT = bytes.fromhex('a51477c90d6283b4e932bc1465f6ae82')
_AUTH_EXPECTED = bytes.fromhex('761d7544d567650461f340dfaa7ad7b6d72d65e48ac8eff9924c71b84b9dce56')


# ===================== pure-python MD4 (untuk NTLM) =====================
def _md4(data):
    ml = len(data) * 8
    msg = data + b'\x80'
    msg += b'\x00' * ((56 - len(msg) % 64) % 64)
    msg += struct.pack('<Q', ml)

    h0, h1, h2, h3 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    M = 0xFFFFFFFF

    for i in range(0, len(msg), 64):
        X = struct.unpack('<16I', msg[i:i+64])
        a, b, c, d = h0, h1, h2, h3

        def r(v, n):
            return ((v << n) | (v >> (32 - n))) & M

        # Round 1
        for j in range(16):
            k = j
            s = [3, 7, 11, 19][j % 4]
            if j % 4 == 0:
                a = r((a + ((b & c) | (~b & d)) + X[k]) & M, s)
            elif j % 4 == 1:
                d = r((d + ((a & b) | (~a & c)) + X[k]) & M, s)
            elif j % 4 == 2:
                c = r((c + ((d & a) | (~d & b)) + X[k]) & M, s)
            else:
                b = r((b + ((c & d) | (~c & a)) + X[k]) & M, s)

        # Round 2
        order2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        for j in range(16):
            k = order2[j]
            s = [3, 5, 9, 13][j % 4]
            if j % 4 == 0:
                a = r((a + ((b & c) | (b & d) | (c & d)) + X[k] + 0x5A827999) & M, s)
            elif j % 4 == 1:
                d = r((d + ((a & b) | (a & c) | (b & c)) + X[k] + 0x5A827999) & M, s)
            elif j % 4 == 2:
                c = r((c + ((d & a) | (d & b) | (a & b)) + X[k] + 0x5A827999) & M, s)
            else:
                b = r((b + ((c & d) | (c & a) | (d & a)) + X[k] + 0x5A827999) & M, s)

        # Round 3
        order3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for j in range(16):
            k = order3[j]
            s = [3, 9, 11, 15][j % 4]
            if j % 4 == 0:
                a = r((a + (b ^ c ^ d) + X[k] + 0x6ED9EBA1) & M, s)
            elif j % 4 == 1:
                d = r((d + (a ^ b ^ c) + X[k] + 0x6ED9EBA1) & M, s)
            elif j % 4 == 2:
                c = r((c + (d ^ a ^ b) + X[k] + 0x6ED9EBA1) & M, s)
            else:
                b = r((b + (c ^ d ^ a) + X[k] + 0x6ED9EBA1) & M, s)

        h0 = (h0 + a) & M
        h1 = (h1 + b) & M
        h2 = (h2 + c) & M
        h3 = (h3 + d) & M

    return struct.pack('<4I', h0, h1, h2, h3)


def _md4_selftest():
    try:
        return _md4(b"").hex() == "31d6cfe0d16ae931b73c59d7e0c089c0"
    except Exception:
        return False


_MD4_OK = _md4_selftest()


def _ntlm(s):
    try:
        return _md4(s.encode('utf-16-le')).hex()
    except Exception:
        return ''


# ===================== hash functions =====================
def _h_md5(s):
    return hashlib.md5(s.encode('utf-8', 'ignore')).hexdigest()


def _h_sha1(s):
    return hashlib.sha1(s.encode('utf-8', 'ignore')).hexdigest()


def _h_sha224(s):
    return hashlib.sha224(s.encode('utf-8', 'ignore')).hexdigest()


def _h_sha256(s):
    return hashlib.sha256(s.encode('utf-8', 'ignore')).hexdigest()


def _h_sha384(s):
    return hashlib.sha384(s.encode('utf-8', 'ignore')).hexdigest()


def _h_sha512(s):
    return hashlib.sha512(s.encode('utf-8', 'ignore')).hexdigest()


HASH_FUNCS = {
    'MD5': _h_md5,
    'SHA1': _h_sha1,
    'SHA224': _h_sha224,
    'SHA256': _h_sha256,
    'SHA384': _h_sha384,
    'SHA512': _h_sha512,
}
if _MD4_OK:
    HASH_FUNCS['NTLM'] = _ntlm

HASH_LENGTHS = {
    'MD5': 32, 'SHA1': 40, 'SHA224': 56, 'SHA256': 64,
    'SHA384': 96, 'SHA512': 128, 'NTLM': 32,
}


def detect_hash_types(h):
    lengths = {
        32: ['MD5'] + (['NTLM'] if _MD4_OK else []),
        40: ['SHA1'], 56: ['SHA224'], 64: ['SHA256'],
        96: ['SHA384'], 128: ['SHA512'],
    }
    return lengths.get(len(h), [])


# ===================== mask parsing =====================
CHARSETS = {
    '?l': 'abcdefghijklmnopqrstuvwxyz',
    '?u': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    '?d': '0123456789',
    '?s': '!@#$%^&*()-_=+[]{};:,.<>/?',
    '?a': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*',
}


def _parse_mask(mask):
    out, i = [], 0
    while i < len(mask):
        if mask[i] == '?' and i + 1 < len(mask):
            two = mask[i:i+2]
            if two in CHARSETS:
                out.append(CHARSETS[two])
                i += 2
                continue
            if two == '??':
                out.append('?')
                i += 2
                continue
        out.append(mask[i])
        i += 1
    return out


def _estimate_mask_size(mask):
    size = 1
    for cs in _parse_mask(mask):
        size *= len(cs)
    return size


# ===================== rules engine =====================
def apply_rules_basic(word):
    """~15 mutations per word — case + append digits/symbols."""
    if not word:
        return
    seen = set()
    variants = [
        word, word.lower(), word.upper(), word.capitalize(),
        word + '1', word + '12', word + '123', word + '1234',
        word + '!', word + '!!', word + '@',
        word.capitalize() + '1', word.capitalize() + '123',
        word.capitalize() + '!',
    ]
    for v in variants:
        if v and v not in seen:
            seen.add(v)
            yield v


def apply_rules_extended(word):
    """~30 mutations per word — + leet + years + reverse + double."""
    base = set(apply_rules_basic(word))
    # Leet speak
    leet = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7', 'g': '9', 'b': '8'}
    leeted = ''.join(leet.get(c.lower(), c) for c in word)
    if leeted and leeted != word:
        base.add(leeted)
        base.add(leeted.capitalize())
        base.add(leeted + '1')
        base.add(leeted + '123')
    # Reverse
    base.add(word[::-1])
    # Doubled
    base.add(word + word)
    # Years
    for year in ('1990', '1995', '2000', '2001', '2002', '2003', '2004', '2005',
                 '2010', '2015', '2020', '2021', '2022', '2023', '2024', '2025', '2026'):
        base.add(word + year)
    for v in base:
        yield v


# ===================== wordlist generator =====================
def generate_profile_wordlist(names, dates, keywords):
    """Generate candidate passwords from profile hints."""
    candidates = set()
    years = ['2020', '2021', '2022', '2023', '2024', '2025', '2026']
    symbols = ['', '1', '12', '123', '!', '@', '!!']
    for name in names:
        name = name.strip()
        if not name:
            continue
        base = name.lower()
        variants = {name, base, name.capitalize(), name.upper()}
        for v in variants:
            candidates.add(v)
            for sym in symbols:
                candidates.add(v + sym)
            for y in years:
                candidates.add(v + y)
        for kw in keywords:
            kw = kw.strip()
            if not kw:
                continue
            kwl = kw.lower()
            candidates.add(base + kwl)
            candidates.add(kwl + base)
            candidates.add(name.capitalize() + kw.capitalize())
            candidates.add(base + '_' + kwl)
        for d in dates:
            d = re.sub(r'[^0-9]', '', d.strip())
            if not d:
                continue
            candidates.add(base + d)
            candidates.add(d + base)
            candidates.add(name.capitalize() + d)
    # filter reasonable lengths
    return [c for c in candidates if 3 <= len(c) <= 32]


# ===================== built-in wordlist =====================
COMMON_PASSWORDS = """
123456 password 12345678 qwerty 123456789 12345 1234 111111 1234567 dragon
123123 baseball abc123 football monkey letmein 696969 shadow master 666666
qwertyuiop 123321 mustang 1234567890 michael 654321 superman 1qaz2wsx
7777777 fuckyou 121212 000000 qazwsx 123qwe killer trustno1 jordan jennifer
zxcvbnm asdfgh hunter buster soccer harley batman andrew tigger sunshine
iloveyou fuckme 2000 charlie robert thomas hockey ranger daniel starwars
klaster 112233 george computer michelle jessica pepper 1111 zxcvbn
555555 11111111 131313 freedom 777777 pass maggie 159753
aaaaaa ginger princess joshua cheese amanda summer love ashley nicole
chelsea biteme matthew access yankees 987654321 dallas austin thunder taylor
welcome admin admin123 root test guest demo
letmein1 pass123 password1 password123 passw0rd p@ssword p@ssw0rd
qwerty123 1q2w3e4r 1q2w3e 987654 123abc abcdef qazwsxedc
qwe123 asd123 zxc123 asdfghjkl zxcvbnm1
""".split()


# ===================== auth check =====================
def _verify_key(candidate):
    try:
        actual = hashlib.pbkdf2_hmac('sha256', candidate.encode('utf-8'),
                                     _AUTH_SALT, 240000)
        return hmac.compare_digest(actual, _AUTH_EXPECTED)
    except Exception:
        return False


# ===================== crackers =====================
def _crack_dictionary(targets, hash_func, wordlist, workers, stop_evt,
                      progress_cb, found_cb):
    found = {}
    lock = threading.Lock()
    counter = [0]
    total = len(wordlist)

    def process(chunk):
        for candidate in chunk:
            if stop_evt.is_set():
                return
            try:
                h = hash_func(candidate)
            except Exception:
                continue
            with lock:
                counter[0] += 1
                if h in targets:
                    targets.discard(h)
                    found[h] = candidate
                    found_cb(h, candidate)
                if counter[0] % 5000 == 0:
                    progress_cb(counter[0], total)
            if not targets:
                stop_evt.set()
                return

    with ThreadPoolExecutor(max_workers=workers) as ex:
        chunk_size = max(1000, min(5000, len(wordlist) // (workers * 4) if wordlist else 1000))
        for i in range(0, len(wordlist), chunk_size):
            if stop_evt.is_set():
                break
            ex.submit(process, wordlist[i:i+chunk_size])
    progress_cb(counter[0], total)
    return found


def _crack_rules(targets, hash_func, wordlist, workers, stop_evt,
                 progress_cb, found_cb, extended=False):
    rules_fn = apply_rules_extended if extended else apply_rules_basic
    multiplier = 30 if extended else 15
    found = {}
    lock = threading.Lock()
    counter = [0]
    total = len(wordlist) * multiplier

    def process(chunk):
        for word in chunk:
            if stop_evt.is_set():
                return
            for candidate in rules_fn(word):
                try:
                    h = hash_func(candidate)
                except Exception:
                    continue
                with lock:
                    counter[0] += 1
                    if h in targets:
                        targets.discard(h)
                        found[h] = candidate
                        found_cb(h, candidate)
                    if counter[0] % 5000 == 0:
                        progress_cb(counter[0], total)
                if not targets:
                    stop_evt.set()
                    return

    with ThreadPoolExecutor(max_workers=workers) as ex:
        chunk_size = max(500, min(2000, len(wordlist) // (workers * 4) if wordlist else 500))
        for i in range(0, len(wordlist), chunk_size):
            if stop_evt.is_set():
                break
            ex.submit(process, wordlist[i:i+chunk_size])
    progress_cb(counter[0], total)
    return found


def _crack_mask(targets, hash_func, mask, workers, stop_evt,
                progress_cb, found_cb):
    charsets = _parse_mask(mask)
    total = 1
    for cs in charsets:
        total *= len(cs)

    found = {}
    lock = threading.Lock()
    counter = [0]

    def process(chunk):
        for combo in chunk:
            if stop_evt.is_set():
                return
            candidate = ''.join(combo)
            try:
                h = hash_func(candidate)
            except Exception:
                continue
            with lock:
                counter[0] += 1
                if h in targets:
                    targets.discard(h)
                    found[h] = candidate
                    found_cb(h, candidate)
                if counter[0] % 5000 == 0:
                    progress_cb(counter[0], total)
            if not targets:
                stop_evt.set()
                return

    def chunk_gen():
        chunk = []
        for combo in itertools.product(*charsets):
            if stop_evt.is_set():
                return
            chunk.append(combo)
            if len(chunk) >= 5000:
                yield chunk
                chunk = []
        if chunk:
            yield chunk

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = []
        for chunk in chunk_gen():
            if stop_evt.is_set():
                break
            futures.append(ex.submit(process, chunk))
            if len(futures) >= workers * 2:
                for f in futures:
                    f.result()
                futures = []
        for f in futures:
            f.result()
    progress_cb(counter[0], total)
    return found


def _crack_hybrid(targets, hash_func, wordlist, workers, stop_evt,
                  progress_cb, found_cb):
    """Wordlist + mutations (extended rules)."""
    return _crack_rules(targets, hash_func, wordlist, workers, stop_evt,
                        progress_cb, found_cb, extended=True)


# ===================== main UI =====================
def open_window(parent, unlocked=False):
    win = ctk.CTkToplevel(parent)
    win.title('JKSY • Crack v2 — Offline Hash Cracker')
    win.geometry('880x680')
    win.minsize(860, 650)
    win.configure(fg_color='#0f1012')
    win.transient(parent)

    state = {
        'unlocked': bool(unlocked),
        'busy': False,
        'stop_evt': threading.Event(),
        'found': {},
        'target_hashes': set(),
        'total_hashes': 0,
        'wordlist_loaded': [],
        'start_time': 0,
        'generated_wordlist': [],
    }

    # ---------- header ----------
    header = ctk.CTkFrame(win, fg_color='#17181b', corner_radius=10)
    header.pack(fill='x', padx=12, pady=(10, 6))
    ctk.CTkLabel(header, text='🔓 JKSY CRACK v2 — MULTI-ALGORITHM HASH CRACKER',
                 font=('Segoe UI', 18, 'bold'), text_color='#f97316'
                 ).pack(anchor='w', padx=14, pady=(10, 2))
    ctk.CTkLabel(header,
        text='Password recovery MILIK SENDIRI / CTF / security audit. '
             'Menggunakan hash milik orang lain = ILLEGAL. '
             'MD5 • SHA1/224/256/384/512 • NTLM • Dictionary • Rules • Mask • Hybrid • Generator.',
        font=('Segoe UI', 10), text_color='#f59e0b',
        wraplength=1000, justify='left'
        ).pack(anchor='w', padx=14, pady=(0, 10))

    # ---------- input ----------
    input_frame = ctk.CTkFrame(win, fg_color='#17181b', corner_radius=10)
    input_frame.pack(fill='x', padx=12, pady=(0, 6))
    row = ctk.CTkFrame(input_frame, fg_color='transparent')
    row.pack(fill='x', padx=10, pady=(8, 4))
    ctk.CTkLabel(row, text='Hashes (1 per baris):',
                 font=('Segoe UI', 11, 'bold')).pack(side='left')
    counter_var = ctk.StringVar(value=f'0 / {FREE_LIMIT}')
    counter_label = ctk.CTkLabel(row, textvariable=counter_var,
                                  font=('Consolas', 11, 'bold'),
                                  text_color='#22c55e')
    counter_label.pack(side='right')
    hash_input = ctk.CTkTextbox(input_frame, height=100, font=('Consolas', 11),
                                 fg_color='#000000', text_color='#e5e7eb')
    hash_input.pack(fill='x', padx=10, pady=(0, 8))

    # ---------- config ----------
    cfg = ctk.CTkFrame(win, fg_color='#17181b', corner_radius=10)
    cfg.pack(fill='x', padx=12, pady=(0, 6))
    r1 = ctk.CTkFrame(cfg, fg_color='transparent')
    r1.pack(fill='x', padx=10, pady=(8, 4))
    ctk.CTkLabel(r1, text='Hash type:', width=85, anchor='w',
                 font=('Segoe UI', 11, 'bold')).pack(side='left')
    hash_type_var = ctk.StringVar(value='Auto')
    type_choices = ['Auto'] + list(HASH_FUNCS.keys())
    ctk.CTkOptionMenu(r1, variable=hash_type_var, values=type_choices,
                      width=120, fg_color='#1f538d', button_color='#143c68'
                      ).pack(side='left', padx=(0, 14))
    ctk.CTkLabel(r1, text='Mode:', width=55, anchor='w',
                 font=('Segoe UI', 11, 'bold')).pack(side='left')
    mode_var = ctk.StringVar(value='Dictionary')
    mode_menu = ctk.CTkOptionMenu(r1, variable=mode_var,
                                   values=['Dictionary', 'Rules', 'Mask', 'Hybrid', 'Generator'],
                                   width=140, fg_color='#7c3aed',
                                   button_color='#6d28d9')
    mode_menu.pack(side='left', padx=(0, 14))
    ctk.CTkLabel(r1, text='Workers:', width=65, anchor='w',
                 font=('Segoe UI', 11, 'bold')).pack(side='left')
    workers_var = ctk.StringVar(value='8')
    ctk.CTkOptionMenu(r1, variable=workers_var,
                      values=['2', '4', '8', '16', '32'], width=75,
                      fg_color='#0891b2', button_color='#0e7490'
                      ).pack(side='left')

    # ---------- attack input ----------
    attack = ctk.CTkFrame(win, fg_color='#17181b', corner_radius=10)
    attack.pack(fill='x', padx=12, pady=(0, 6))

    dict_frame = ctk.CTkFrame(attack, fg_color='transparent')
    ctk.CTkLabel(dict_frame, text='Wordlist:', width=90, anchor='w',
                 font=('Segoe UI', 11, 'bold')).pack(side='left')
    wordlist_var = ctk.StringVar(value='Built-in top passwords (small)')
    ctk.CTkLabel(dict_frame, textvariable=wordlist_var, anchor='w',
                 font=('Consolas', 10), text_color='#94a3b8'
                 ).pack(side='left', padx=6, fill='x', expand=True)

    def browse_wordlist():
        path = filedialog.askopenfilename(
            parent=win, title='Pilih Wordlist',
            filetypes=[('Text Files', '*.txt'), ('All Files', '*.*')])
        if not path:
            return
        try:
            words = []
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    w = line.rstrip('\r\n')
                    if w:
                        words.append(w)
            state['wordlist_loaded'] = words
            wordlist_var.set(f'{os.path.basename(path)} ({len(words):,} words)')
        except Exception as e:
            messagebox.showerror('Crack', f'Gagal load: {e}', parent=win)

    ctk.CTkButton(dict_frame, text='📂 Browse', width=90, height=28,
                  fg_color='#1f538d', hover_color='#143c68',
                  command=browse_wordlist).pack(side='right', padx=4)

    mask_frame = ctk.CTkFrame(attack, fg_color='transparent')
    ctk.CTkLabel(mask_frame, text='Mask:', width=90, anchor='w',
                 font=('Segoe UI', 11, 'bold')).pack(side='left')
    mask_entry = ctk.CTkEntry(mask_frame, width=260, height=28,
                               placeholder_text='contoh: ?l?l?l?d?d')
    mask_entry.pack(side='left', padx=6)
    ctk.CTkLabel(mask_frame,
                 text='?l ?u ?d ?s ?a (lower/upper/digit/symbol/all)',
                 font=('Segoe UI', 9), text_color='#94a3b8').pack(side='left')

    gen_frame = ctk.CTkFrame(attack, fg_color='transparent')
    ctk.CTkLabel(gen_frame, text='Generator —',
                 font=('Segoe UI', 11, 'bold')).pack(side='left', padx=(0, 8))
    ctk.CTkButton(gen_frame, text='👤 Profile → Wordlist', width=200, height=28,
                  fg_color='#0891b2', hover_color='#0e7490',
                  command=lambda: open_generator()).pack(side='left', padx=4)
    gen_count_var = ctk.StringVar(value='')
    ctk.CTkLabel(gen_frame, textvariable=gen_count_var, font=('Consolas', 10),
                 text_color='#22c55e').pack(side='left', padx=8)

    def show_attack_input(*_):
        for f in (dict_frame, mask_frame, gen_frame):
            f.pack_forget()
        m = mode_var.get()
        if m == 'Mask':
            mask_frame.pack(fill='x', padx=10, pady=(8, 4))
        elif m == 'Generator':
            gen_frame.pack(fill='x', padx=10, pady=(8, 4))
        else:
            dict_frame.pack(fill='x', padx=10, pady=(8, 4))
    mode_menu.configure(command=show_attack_input)

    # ---------- status ----------
    status = ctk.CTkFrame(win, fg_color='transparent')
    status.pack(fill='x', padx=12, pady=(4, 4))
    auth_btn = ctk.CTkButton(status, text='🔒 Auth Key (unlock full)',
                              width=200, height=28, fg_color='#7c3aed',
                              hover_color='#6d28d9')
    auth_btn.pack(side='left')
    auth_status = ctk.CTkLabel(status,
                                text=(f'PREMIUM (max {PREMIUM_LIMIT})'
                                      if state['unlocked']
                                      else f'FREE (max {FREE_LIMIT})'),
                                font=('Segoe UI', 11, 'bold'),
                                text_color=('#22c55e' if state['unlocked']
                                            else '#f59e0b'))
    auth_status.pack(side='left', padx=10)
    start_btn = ctk.CTkButton(status, text='▶ Start Crack', width=140,
                               height=28, fg_color='#2b8a3e', hover_color='#216e31')
    start_btn.pack(side='right')
    stop_btn = ctk.CTkButton(status, text='⏹ Stop', width=100, height=28,
                              fg_color='#991B1B', hover_color='#7f1d1d',
                              state='disabled')
    stop_btn.pack(side='right', padx=(0, 6))
    export_btn = ctk.CTkButton(status, text='💾 Export', width=100, height=28,
                                fg_color='#1f538d', hover_color='#143c68',
                                state='disabled')
    export_btn.pack(side='right', padx=(0, 6))

    if state['unlocked']:
        auth_btn.configure(text='🔓 Unlocked', fg_color='#2b8a3e')

    # ---------- progress ----------
    progress = ctk.CTkProgressBar(win, height=10, progress_color='#f97316')
    progress.pack(fill='x', padx=12, pady=(0, 3))
    progress.set(0)
    progress_label = ctk.CTkLabel(win, text='Ready.', font=('Consolas', 10),
                                   text_color='#94a3b8')
    progress_label.pack(anchor='w', padx=14, pady=(0, 4))

    # ---------- results tree ----------
    table = ctk.CTkFrame(win, fg_color='#0b0c0e', corner_radius=8)
    table.pack(fill='both', expand=True, padx=12, pady=(0, 6))
    style = ttk.Style()
    try:
        style.theme_use('clam')
    except Exception:
        pass
    style.configure('Crack.Treeview', background='#0b0c0e', foreground='#e5e7eb',
                    fieldbackground='#0b0c0e', rowheight=24,
                    font=('Consolas', 10))
    style.configure('Crack.Treeview.Heading', background='#17181b',
                    foreground='#f97316', font=('Segoe UI', 10, 'bold'))
    style.map('Crack.Treeview', background=[('selected', '#1f538d')])
    tree = ttk.Treeview(table, columns=('hash', 'plain', 'type'),
                        show='headings', style='Crack.Treeview', height=9)
    tree.heading('hash', text='Hash')
    tree.heading('plain', text='Plaintext')
    tree.heading('type', text='Type')
    tree.column('hash', width=520, anchor='w')
    tree.column('plain', width=280, anchor='w')
    tree.column('type', width=110, anchor='center')
    tree.tag_configure('found', foreground='#22c55e')
    tree.pack(side='left', fill='both', expand=True, padx=4, pady=4)
    scroll = ttk.Scrollbar(table, orient='vertical', command=tree.yview)
    scroll.pack(side='right', fill='y', pady=4, padx=(0, 4))
    tree.configure(yscrollcommand=scroll.set)

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
            progress.set(min(1.0, max(0.0, pct)))
            if msg is not None:
                progress_label.configure(text=msg)
        except Exception:
            pass

    def parse_hashes():
        text = hash_input.get('1.0', 'end-1c')
        out, seen = [], set()
        for line in text.splitlines():
            h = line.strip().lower()
            if not h or h.startswith('#'):
                continue
            h = re.sub(r'[^a-f0-9]', '', h)
            if h and h not in seen:
                seen.add(h)
                out.append(h)
        return out

    def update_counter(*_):
        try:
            hashes = parse_hashes()
            limit = PREMIUM_LIMIT if state['unlocked'] else FREE_LIMIT
            unknown = 0
            if hash_type_var.get() == 'Auto':
                unknown = sum(1 for h in hashes if not detect_hash_types(h))
            else:
                exp_len = HASH_LENGTHS.get(hash_type_var.get(), 0)
                unknown = sum(1 for h in hashes if exp_len and len(h) != exp_len)
            text = f'{len(hashes)} / {limit}'
            if unknown:
                text += f'  ⚠ {unknown} unknown'
            counter_var.set(text)
            counter_label.configure(
                text_color=('#ef4444' if len(hashes) > limit
                            else '#f59e0b' if unknown
                            else '#22c55e'))
        except Exception:
            pass

    hash_input.bind('<KeyRelease>', update_counter)
    hash_input.bind('<FocusOut>', update_counter)
    try:
        hash_input.bind('<<Paste>>', lambda e: win.after(60, update_counter))
    except Exception:
        pass

    def open_auth():
        if state['unlocked']:
            messagebox.showinfo('Crack', 'Auth Key sudah aktif.', parent=win)
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
            text=f'Unlock: {PREMIUM_LIMIT} hash + Rules + Mask + Hybrid + Generator.',
            font=('Segoe UI', 10), text_color='#94a3b8').pack(pady=(0, 10))
        entry = ctk.CTkEntry(dlg, width=300, height=34, show='●',
                              placeholder_text='Input Auth Key')
        entry.pack(pady=4)
        fb = ctk.CTkLabel(dlg, text='', text_color='#ef4444',
                           font=('Segoe UI', 10))
        fb.pack(pady=2)

        def verify():
            if _verify_key(entry.get()):
                state['unlocked'] = True
                auth_status.configure(text=f'PREMIUM (max {PREMIUM_LIMIT})',
                                       text_color='#22c55e')
                auth_btn.configure(text='🔓 Unlocked', fg_color='#2b8a3e')
                dlg.destroy()
                update_counter()
            else:
                fb.configure(text='Auth Key salah.')
                entry.delete(0, 'end')

        ctk.CTkButton(dlg, text='Verify', width=140, height=30,
                      fg_color='#2b8a3e', command=verify).pack(pady=8)
        entry.bind('<Return>', lambda e: verify())
        entry.focus_set()

    auth_btn.configure(command=open_auth)

    # ---------- generator dialog ----------
    def open_generator():
        dlg = ctk.CTkToplevel(win)
        dlg.title('Wordlist Generator — Profile Based')
        dlg.geometry('520x420')
        dlg.transient(win)
        dlg.grab_set()
        dlg.configure(fg_color='#0f1012')
        dlg.attributes('-topmost', True)
        ctk.CTkLabel(dlg, text='👤 Generate Wordlist dari Profil',
                     font=('Segoe UI', 15, 'bold'),
                     text_color='#0891b2').pack(pady=(14, 6))
        ctk.CTkLabel(dlg,
            text='Masukkan hints (pisahkan dengan koma). Tool akan generate '
                 'kombinasi nama + tanggal + keyword + tahun + symbol.',
            font=('Segoe UI', 10), text_color='#94a3b8',
            wraplength=470).pack(pady=(0, 10))
        ctk.CTkLabel(dlg, text='Nama (contoh: andi, budi)',
                     anchor='w', font=('Segoe UI', 11)).pack(fill='x', padx=24)
        names_e = ctk.CTkEntry(dlg, width=470, height=28)
        names_e.pack(padx=24, pady=(2, 8))
        ctk.CTkLabel(dlg, text='Tanggal lahir / tanggal penting (DD-MM-YYYY)',
                     anchor='w', font=('Segoe UI', 11)).pack(fill='x', padx=24)
        dates_e = ctk.CTkEntry(dlg, width=470, height=28,
                                placeholder_text='contoh: 15-08-1995, 01-01-2020')
        dates_e.pack(padx=24, pady=(2, 8))
        ctk.CTkLabel(dlg, text='Keyword tambahan (hobi, hewan, dsb)',
                     anchor='w', font=('Segoe UI', 11)).pack(fill='x', padx=24)
        kw_e = ctk.CTkEntry(dlg, width=470, height=28,
                             placeholder_text='contoh: kucing, motor, gaming')
        kw_e.pack(padx=24, pady=(2, 12))

        def do_generate():
            names = [x.strip() for x in names_e.get().split(',') if x.strip()]
            dates = [x.strip() for x in dates_e.get().split(',') if x.strip()]
            kws = [x.strip() for x in kw_e.get().split(',') if x.strip()]
            if not names:
                messagebox.showwarning('Generator', 'Masukkan minimal 1 nama.', parent=dlg)
                return
            words = generate_profile_wordlist(names, dates, kws)
            state['generated_wordlist'] = words
            gen_count_var.set(f'{len(words)} generated')
            wordlist_var.set(f'Generated ({len(words)} words)')
            log(f'[+] Generated {len(words)} candidates from profile')
            dlg.destroy()

        ctk.CTkButton(dlg, text='⚡ Generate', width=150, height=32,
                      fg_color='#0891b2', command=do_generate
                      ).pack(pady=4)
        names_e.focus_set()

    # ---------- run ----------
    def on_found(h, plaintext, htype):
        try:
            if not win.winfo_exists():
                return
            key = (h, htype)
            state['found'][key] = plaintext
            tree.insert('', 'end', values=(h, plaintext, htype),
                        tags=('found',))
            log(f'[✓] {htype} FOUND: "{plaintext}"')
        except Exception:
            pass

    def run_crack():
        if state['busy']:
            return
        hashes = parse_hashes()
        if not hashes:
            messagebox.showwarning('Crack', 'Masukkan minimal 1 hash.', parent=win)
            return
        limit = PREMIUM_LIMIT if state['unlocked'] else FREE_LIMIT
        if len(hashes) > limit:
            messagebox.showwarning('Crack',
                f'Maksimal {limit} hash. Klik 🔒 Auth Key untuk lebih banyak.',
                parent=win)
            return

        htype_mode = hash_type_var.get()
        mode = mode_var.get()
        if not state['unlocked'] and (mode in ('Rules', 'Mask', 'Hybrid', 'Generator')
                                       or htype_mode == 'Auto'):
            messagebox.showwarning('Crack',
                'Mode Rules/Mask/Hybrid/Generator dan Auto-detect memerlukan Auth Key.\n'
                'Free tier: 1 algoritma, Dictionary only.',
                parent=win)
            return

        # Prepare wordlist/mask
        if mode == 'Mask':
            mask = mask_entry.get().strip()
            if not mask:
                messagebox.showwarning('Crack', 'Masukkan mask.', parent=win)
                return
            try:
                size = _estimate_mask_size(mask)
                if size > 500_000_000:
                    messagebox.showwarning('Crack',
                        f'Mask terlalu besar ({size:,}). Perkecil pattern.', parent=win)
                    return
                if not messagebox.askyesno('Crack',
                    f'Akan mencoba {size:,} kombinasi. Lanjut?', parent=win):
                    return
            except Exception as e:
                messagebox.showerror('Crack', f'Mask invalid: {e}', parent=win)
                return
            input_data = mask
        else:
            if mode == 'Generator' and state['generated_wordlist']:
                wordlist = list(state['generated_wordlist'])
            elif state['wordlist_loaded']:
                wordlist = list(state['wordlist_loaded'])
            else:
                wordlist = list(COMMON_PASSWORDS)
            if not wordlist:
                messagebox.showwarning('Crack', 'Wordlist kosong.', parent=win)
                return
            input_data = wordlist

        try:
            workers = int(workers_var.get())
        except Exception:
            workers = 8

        # Group hashes by type
        groups = {}
        if htype_mode == 'Auto':
            for h in hashes:
                types = detect_hash_types(h)
                if not types:
                    log(f'[!] Skip hash panjang tak dikenali: {h[:16]}...')
                    continue
                for t in types:
                    groups.setdefault(t, set()).add(h)
        else:
            if htype_mode not in HASH_FUNCS:
                messagebox.showerror('Crack',
                    f'Hash type {htype_mode} tidak tersedia '
                    f'({"MD4/NTLM self-test failed" if htype_mode == "NTLM" else "unknown"}).',
                    parent=win)
                return
            groups[htype_mode] = set(hashes)

        if not groups:
            messagebox.showwarning('Crack',
                'Tidak ada hash valid untuk algoritma yang tersedia.', parent=win)
            return

        # Reset state
        state['busy'] = True
        state['stop_evt'].clear()
        state['found'] = {}
        state['target_hashes'] = set(hashes)
        state['total_hashes'] = len(hashes)
        state['start_time'] = time.time()
        start_btn.configure(state='disabled')
        stop_btn.configure(state='normal')
        export_btn.configure(state='disabled')
        for i in tree.get_children():
            tree.delete(i)
        progress.set(0)
        log(f'[*] {mode} attack • workers={workers} • '
            f'{len(hashes)} hash • types: {", ".join(groups.keys())}')

        stop_evt = state['stop_evt']

        def progress_cb(count, total):
            try:
                if not win.winfo_exists():
                    return
                elapsed = time.time() - state['start_time']
                speed = count / elapsed if elapsed > 0 else 0
                pct = (count / total) if total > 0 else 0
                if total > 0 and speed > 0:
                    eta = (total - count) / speed
                    eta_str = f'{int(eta // 60):02d}:{int(eta % 60):02d}'
                else:
                    eta_str = '--:--'
                msg = (f'{count:,} / {total:,}  •  {speed:,.0f} H/s  •  '
                       f'ETA {eta_str}  •  Found: {len(state["found"])}')
                win.after(0, lambda p=pct, m=msg: set_progress(p, m))
            except Exception:
                pass

        def worker():
            try:
                for htype, targets in groups.items():
                    if stop_evt.is_set() or not targets:
                        break
                    hash_func = HASH_FUNCS[htype]
                    def cb(h, p, t=htype):
                        on_found(h, p, t)
                    log(f'[*] Cracking {len(targets)} {htype} hash(es)...')
                    if mode == 'Dictionary':
                        _crack_dictionary(targets, hash_func, input_data,
                                          workers, stop_evt, progress_cb, cb)
                    elif mode == 'Rules':
                        _crack_rules(targets, hash_func, input_data,
                                     workers, stop_evt, progress_cb, cb,
                                     extended=False)
                    elif mode == 'Hybrid':
                        _crack_hybrid(targets, hash_func, input_data,
                                      workers, stop_evt, progress_cb, cb)
                    elif mode == 'Mask':
                        _crack_mask(targets, hash_func, input_data,
                                    workers, stop_evt, progress_cb, cb)
                    elif mode == 'Generator':
                        _crack_dictionary(targets, hash_func, input_data,
                                          workers, stop_evt, progress_cb, cb)
            except Exception as e:
                win.after(0, lambda err=str(e): log(f'[!] Error: {err}'))
            finally:
                win.after(0, on_done)

        threading.Thread(target=worker, daemon=True).start()

    def on_done():
        try:
            if not win.winfo_exists():
                return
            state['busy'] = False
            start_btn.configure(state='normal')
            stop_btn.configure(state='disabled')
            fc = len(state['found'])
            nf = state['total_hashes'] - fc
            elapsed = time.time() - state['start_time']
            log(f'[*] Selesai. Found: {fc} / {state["total_hashes"]}  '
                f'({elapsed:.1f}s)')
            set_progress(1.0, f'Done. Found {fc} / {state["total_hashes"]}.')
            if fc > 0:
                export_btn.configure(state='normal')
        except Exception:
            pass

    def stop_crack():
        state['stop_evt'].set()
        log('[*] Stop requested...')

    def export_results():
        if not state['found']:
            return
        path = filedialog.asksaveasfilename(
            parent=win, defaultextension='.txt',
            filetypes=[('Text Files', '*.txt')],
            initialfile='crack-results.txt',
            title='Simpan hasil crack')
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write('JKSY Crack v2 — Hash Cracking Results\n')
                f.write('=' * 60 + '\n\n')
                for (h, t), p in sorted(state['found'].items()):
                    f.write(f'{h}\t{p}\t{t}\n')
            messagebox.showinfo('Crack', f'Hasil tersimpan:\n{path}', parent=win)
        except Exception as e:
            messagebox.showerror('Crack', f'Gagal simpan: {e}', parent=win)

    start_btn.configure(command=run_crack)
    stop_btn.configure(command=stop_crack)
    export_btn.configure(command=export_results)

    def close_win():
        if state['busy']:
            if not messagebox.askyesno('Crack',
                'Proses masih berjalan. Hentikan dan tutup?', parent=win):
                return
            state['stop_evt'].set()
        win.destroy()
        if parent.winfo_exists():
            parent.deiconify()
            parent.lift()

    win.protocol('WM_DELETE_WINDOW', close_win)
    show_attack_input()
    update_counter()

    if not _MD4_OK:
        log('[!] MD4 self-test GAGAL — NTLM dinonaktifkan. Hash lain tetap bekerja.')
    return win