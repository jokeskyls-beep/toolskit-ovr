"""JKSY Wa API — WhatsApp Cloud API (Meta) client.

Kirim pesan teks/gambar/dokumen ke nomor WhatsApp melalui API RESMI Meta.
Bukan scraping WhatsApp Web — 100% legal & tidak akan banned.

Setup (~15 menit, gratis):
1. Buka https://developers.facebook.com/apps/
2. Create App → Business → WhatsApp
3. Salin "Phone Number ID" dari dashboard
4. Salin "Temporary Access Token" (24 jam) atau setup Permanent Token
5. Untuk testing: tambahkan nomor Anda di "To" recipient list

Free tier: 1 nomor tujuan + 100 pesan/hari
Auth Key: unlimited nomor tujuan + 1000 pesan/hari
"""
import json
import os
import threading
import time
import urllib.error
import urllib.request
from tkinter import filedialog, messagebox
import customtkinter as ctk

FREE_DEST_LIMIT = 1
PREMIUM_DEST_LIMIT = 50
FREE_MSG_LIMIT = 100
PREMIUM_MSG_LIMIT = 1000

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            'waapi_config.json')

_AUTH_SALT = bytes.fromhex('a51477c90d6283b4e932bc1465f6ae82')
_AUTH_EXPECTED = bytes.fromhex('761d7544d567650461f340dfaa7ad7b6d72d65e48ac8eff9924c71b84b9dce56')

GRAPH_API_BASE = 'https://graph.facebook.com/v21.0'


def _verify_key(candidate):
    try:
        actual = hashlib.pbkdf2_hmac('sha256', candidate.encode('utf-8'),
                                     _AUTH_SALT, 240000)
        return hmac.compare_digest(actual, _AUTH_EXPECTED)
    except Exception:
        return False


import hashlib
import hmac


def _load_config():
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def _save_config(data):
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        try:
            os.chmod(CONFIG_FILE, 0o600)
        except Exception:
            pass
        return None
    except Exception as e:
        return str(e)


def _normalize_phone(text):
    """Return digits-only international format (no + prefix) or None."""
    if not text:
        return None
    digits = ''.join(c for c in text if c.isdigit())
    if not digits:
        return None
    if digits.startswith('0'):
        # assume Indonesia 08xxx → 628xxx
        digits = '62' + digits[1:]
    if 8 <= len(digits) <= 15:
        return digits
    return None


def _http_post_json(url, headers, payload):
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers=headers, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode()), None
    except urllib.error.HTTPError as e:
        try:
            err = json.loads(e.read().decode())
            msg = err.get('error', {}).get('message', f'HTTP {e.code}')
            return None, msg
        except Exception:
            return None, f'HTTP {e.code}: {e.reason}'
    except Exception as e:
        return None, str(e)


def _http_get_json(url, headers):
    req = urllib.request.Request(url, headers=headers, method='GET')
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode()), None
    except urllib.error.HTTPError as e:
        try:
            err = json.loads(e.read().decode())
            return None, err.get('error', {}).get('message', f'HTTP {e.code}')
        except Exception:
            return None, f'HTTP {e.code}: {e.reason}'
    except Exception as e:
        return None, str(e)


def open_window(parent, unlocked=False):
    win = ctk.CTkToplevel(parent)
    win.title('JKSY • Wa API — WhatsApp Cloud API Client')
    win.geometry('880x680')          # <-- Diperkecil dari 1000x800
    win.minsize(860, 650)            # <-- Diperkecil
    win.configure(fg_color='#0f1012')
    win.transient(parent)

    state = {
        'unlocked': bool(unlocked),
        'busy': False,
        'phone_id': '',
        'token': '',
        'sent_count': 0,
        'config': _load_config(),
    }
    if state['config'].get('phone_id'):
        state['phone_id'] = state['config']['phone_id']
    if state['config'].get('token'):
        state['token'] = state['config']['token']

    # ---------- header ----------
    header = ctk.CTkFrame(win, fg_color='#17181b', corner_radius=10)
    header.pack(fill='x', padx=12, pady=(10, 6))
    ctk.CTkLabel(header, text='📱 JKSY WA API — WHATSAPP CLOUD API',
                 font=('Segoe UI', 16, 'bold'), text_color='#22c55e'
                 ).pack(anchor='w', padx=14, pady=(8, 2))
    ctk.CTkLabel(header,
        text='Kirim pesan via API RESMI Meta. Free: 1 nomor • 100 msg. Auth Key: Unlimited.',
        font=('Segoe UI', 10), text_color='#f59e0b',
        wraplength=840, justify='left'
        ).pack(anchor='w', padx=14, pady=(0, 8))

    # ---------- config ----------
    cfg = ctk.CTkFrame(win, fg_color='#17181b', corner_radius=10)
    cfg.pack(fill='x', padx=12, pady=(0, 6))
    r1 = ctk.CTkFrame(cfg, fg_color='transparent')
    r1.pack(fill='x', padx=10, pady=(8, 4))
    ctk.CTkLabel(r1, text='Phone Number ID:', width=110, anchor='w',
                 font=('Segoe UI', 11, 'bold')).pack(side='left')
    phone_id_entry = ctk.CTkEntry(r1, width=250, height=28,
                                   placeholder_text='contoh: 123456789012345')
    phone_id_entry.pack(side='left', padx=4)
    phone_id_entry.insert(0, state['phone_id'])
    ctk.CTkButton(r1, text='🔗 Test', width=80, height=28,
                  fg_color='#0891b2', hover_color='#0e7490',
                  command=lambda: test_connection()).pack(side='left', padx=4)

    r2 = ctk.CTkFrame(cfg, fg_color='transparent')
    r2.pack(fill='x', padx=10, pady=(0, 8))
    ctk.CTkLabel(r2, text='Access Token:', width=110, anchor='w',
                 font=('Segoe UI', 11, 'bold')).pack(side='left')
    token_entry = ctk.CTkEntry(r2, width=590, height=28, show='●',
                                placeholder_text='EAAxxxx...')
    token_entry.pack(side='left', padx=4)
    token_entry.insert(0, state['token'])
    ctk.CTkButton(r2, text='💾 Save', width=80, height=28,
                  fg_color='#2b8a3e', hover_color='#216e31',
                  command=lambda: save_config()).pack(side='left', padx=4)

    # ---------- auth/status ----------
    status = ctk.CTkFrame(win, fg_color='transparent')
    status.pack(fill='x', padx=12, pady=(4, 4))
    auth_btn = ctk.CTkButton(status, text='🔒 Auth Key (unlock full)',
                              width=190, height=26, fg_color='#7c3aed',
                              hover_color='#6d28d9')
    auth_btn.pack(side='left')
    auth_status = ctk.CTkLabel(status,
                                text=(f'PREMIUM • unlimited dest • {PREMIUM_MSG_LIMIT} msg/day'
                                      if state['unlocked']
                                      else f'FREE • {FREE_DEST_LIMIT} dest • {FREE_MSG_LIMIT} msg/day'),
                                font=('Segoe UI', 10, 'bold'),
                                text_color=('#22c55e' if state['unlocked']
                                            else '#f59e0b'))
    auth_status.pack(side='left', padx=10)
    counter_label = ctk.CTkLabel(status, text='0 msg sent',
                                  font=('Consolas', 10, 'bold'),
                                  text_color='#22c55e')
    counter_label.pack(side='right')

    if state['unlocked']:
        auth_btn.configure(text='🔓 Unlocked', fg_color='#2b8a3e')

    # ---------- tabs (Height diperkecil) ----------
    tabs = ctk.CTkTabview(win, height=380, fg_color='#0f1012',  # <-- Diperkecil dari 470
                           segmented_button_selected_color='#22c55e',
                           segmented_button_unselected_color='#334155')
    tabs.pack(fill='both', expand=True, padx=12, pady=(0, 6))

    tab_text = tabs.add('📝 Text Message')
    tab_template = tabs.add('📋 Template')
    tab_media = tabs.add('🖼 Media')

    # ---- Text Message tab ----
    t_inner = ctk.CTkFrame(tab_text, fg_color='transparent')
    t_inner.pack(fill='both', expand=True, padx=8, pady=8)
    ctk.CTkLabel(t_inner, text='Recipients (nomor WA, 1 per baris):',
                 anchor='w', font=('Segoe UI', 10, 'bold')).pack(fill='x')
    ctk.CTkLabel(t_inner,
                 text='Format: 628123456789 (auto-convert 08xxx → 628xxx)',
                 font=('Segoe UI', 9), text_color='#94a3b8',
                 anchor='w').pack(fill='x', pady=(0, 2))
    recipients = ctk.CTkTextbox(t_inner, height=70, font=('Consolas', 11),  # <-- Diperkecil dari 110
                                  fg_color='#000000', text_color='#e5e7eb')
    recipients.pack(fill='x', pady=(0, 6))
    ctk.CTkLabel(t_inner, text='Message text:',
                 anchor='w', font=('Segoe UI', 10, 'bold')).pack(fill='x')
    msg_text = ctk.CTkTextbox(t_inner, height=100, font=('Segoe UI', 11),  # <-- Diperkecil dari 130
                                fg_color='#000000', text_color='#e5e7eb')
    msg_text.pack(fill='both', expand=True, pady=(0, 6))

    # ---- Template tab ----
    tpl_inner = ctk.CTkFrame(tab_template, fg_color='transparent')
    tpl_inner.pack(fill='both', expand=True, padx=8, pady=8)
    ctk.CTkLabel(tpl_inner,
        text='Template adalah pesan yang sudah disetujui Meta. Wajib untuk memulai percakapan.',
        font=('Segoe UI', 9), text_color='#f59e0b',
        wraplength=800, justify='left').pack(fill='x', pady=(0, 6))
    ctk.CTkLabel(tpl_inner, text='Recipients:',
                 anchor='w', font=('Segoe UI', 10, 'bold')).pack(fill='x')
    tpl_recipients = ctk.CTkTextbox(tpl_inner, height=60, font=('Consolas', 11),  # <-- Diperkecil
                                     fg_color='#000000', text_color='#e5e7eb')
    tpl_recipients.pack(fill='x', pady=(2, 6))
    r_tpl = ctk.CTkFrame(tpl_inner, fg_color='transparent')
    r_tpl.pack(fill='x', pady=(0, 4))
    ctk.CTkLabel(r_tpl, text='Template name:', width=100, anchor='w',
                 font=('Segoe UI', 10, 'bold')).pack(side='left')
    tpl_name = ctk.CTkEntry(r_tpl, width=180, height=26,
                             placeholder_text='hello_world')
    tpl_name.pack(side='left', padx=4)
    ctk.CTkLabel(r_tpl, text='Language:', width=65, anchor='w',
                 font=('Segoe UI', 10, 'bold')).pack(side='left', padx=(20, 4))
    tpl_lang = ctk.CTkEntry(r_tpl, width=70, height=26, placeholder_text='en_US')
    tpl_lang.pack(side='left', padx=4)
    tpl_lang.insert(0, 'en_US')
    ctk.CTkLabel(tpl_inner,
        text='Template body parameters (JSON array):',
        anchor='w', font=('Segoe UI', 10, 'bold')).pack(fill='x', pady=(6, 2))
    tpl_params = ctk.CTkEntry(tpl_inner, width=800, height=26,
                               placeholder_text='["value1", "value2"]')
    tpl_params.pack(fill='x', pady=(0, 4))

    # ---- Media tab ----
    med_inner = ctk.CTkFrame(tab_media, fg_color='transparent')
    med_inner.pack(fill='both', expand=True, padx=8, pady=8)
    ctk.CTkLabel(med_inner, text='Recipients:',
                 anchor='w', font=('Segoe UI', 10, 'bold')).pack(fill='x')
    med_recipients = ctk.CTkTextbox(med_inner, height=60, font=('Consolas', 11),  # <-- Diperkecil
                                     fg_color='#000000', text_color='#e5e7eb')
    med_recipients.pack(fill='x', pady=(2, 6))
    r_med = ctk.CTkFrame(med_inner, fg_color='transparent')
    r_med.pack(fill='x', pady=(0, 4))
    ctk.CTkLabel(r_med, text='Media URL:', width=80, anchor='w',
                 font=('Segoe UI', 10, 'bold')).pack(side='left')
    med_url = ctk.CTkEntry(r_med, width=600, height=26,
                            placeholder_text='https://example.com/image.jpg')
    med_url.pack(side='left', padx=4)
    r_type = ctk.CTkFrame(med_inner, fg_color='transparent')
    r_type.pack(fill='x', pady=(0, 4))
    ctk.CTkLabel(r_type, text='Media type:', width=80, anchor='w',
                 font=('Segoe UI', 10, 'bold')).pack(side='left')
    med_type_var = ctk.StringVar(value='image')
    ctk.CTkOptionMenu(r_type, variable=med_type_var,
                      values=['image', 'video', 'document'], width=130,
                      fg_color='#1f538d', button_color='#143c68'
                      ).pack(side='left', padx=4)
    ctk.CTkLabel(r_type, text='Caption:', width=60, anchor='w',
                 font=('Segoe UI', 10, 'bold')).pack(side='left', padx=(15, 4))
    med_caption = ctk.CTkEntry(r_type, width=350, height=26,
                                placeholder_text='Optional caption')
    med_caption.pack(side='left', padx=4)

    # ---------- action bar ----------
    action = ctk.CTkFrame(win, fg_color='transparent')
    action.pack(fill='x', padx=12, pady=(0, 4))
    send_btn = ctk.CTkButton(action, text='📤 Send', width=130, height=30,
                              fg_color='#2b8a3e', hover_color='#216e31')
    send_btn.pack(side='right')
    clear_btn = ctk.CTkButton(action, text='🗑 Clear Log', width=100, height=30,
                               fg_color='#334155', hover_color='#475569')
    clear_btn.pack(side='right', padx=(0, 6))

    # ---------- progress ----------
    progress = ctk.CTkProgressBar(win, height=8, progress_color='#22c55e')
    progress.pack(fill='x', padx=12, pady=(0, 2))
    progress.set(0)
    progress_label = ctk.CTkLabel(win, text='Ready.', font=('Consolas', 9),
                                   text_color='#94a3b8')
    progress_label.pack(anchor='w', padx=14, pady=(0, 2))

    # ---------- log ----------
    log_box = ctk.CTkTextbox(win, height=100, font=('Consolas', 9),  # <-- Diperkecil
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

    # ---------- config actions ----------
    def save_config():
        pid = phone_id_entry.get().strip()
        tok = token_entry.get().strip()
        if not pid or not tok:
            messagebox.showwarning('Wa API',
                'Phone Number ID dan Access Token wajib diisi.', parent=win)
            return
        cfg_data = {'phone_id': pid, 'token': tok}
        err = _save_config(cfg_data)
        if err:
            messagebox.showerror('Wa API',
                f'Gagal simpan config:\n{err}\n\nPastikan folder toolskit/ writable.',
                parent=win)
            return
        state['phone_id'] = pid
        state['token'] = tok
        state['config'] = cfg_data
        log('[💾] Config disimpan ke waapi_config.json')

    def test_connection():
        pid = phone_id_entry.get().strip()
        tok = token_entry.get().strip()
        if not pid or not tok:
            messagebox.showwarning('Wa API',
                'Isi Phone Number ID dan Access Token dulu.', parent=win)
            return
        log(f'[*] Test: GET /{pid} ...')

        def worker():
            url = f'{GRAPH_API_BASE}/{pid}?fields=display_phone_number,verified_name,quality_rating'
            headers = {'Authorization': f'Bearer {tok}'}
            data, err = _http_get_json(url, headers)
            if err:
                win.after(0, lambda e=err: log(f'[❌] Test GAGAL: {e}'))
            else:
                num = data.get('display_phone_number', '?')
                name = data.get('verified_name', '?')
                quality = data.get('quality_rating', '?')
                win.after(0, lambda: log(
                    f'[✅] Connected!\n  Number: {num}\n'
                    f'  Name: {name}\n  Quality: {quality}'))
        threading.Thread(target=worker, daemon=True).start()

    # ---------- auth ----------
    def open_auth():
        if state['unlocked']:
            messagebox.showinfo('Wa API', 'Auth Key sudah aktif.', parent=win)
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
            text=f'Unlock: unlimited recipients + {PREMIUM_MSG_LIMIT} msg/day.',
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
                update_auth_status()
                log('[🔓] Auth Key verified. Premium features unlocked.')
                dlg.destroy()
            else:
                fb.configure(text='Auth Key salah.')
                entry.delete(0, 'end')

        ctk.CTkButton(dlg, text='Verify', width=140, height=30,
                      fg_color='#2b8a3e', command=verify).pack(pady=8)
        entry.bind('<Return>', lambda e: verify())
        entry.focus_set()

    auth_btn.configure(command=open_auth)

    # ---------- send helpers ----------
    def validate_recipients(recipients_text):
        lines = [l.strip() for l in recipients_text.splitlines() if l.strip()]
        nums, seen = [], set()
        for line in lines:
            n = _normalize_phone(line)
            if n and n not in seen:
                seen.add(n)
                nums.append(n)
        return nums

    def check_limits(recipients):
        if not recipients:
            messagebox.showwarning('Wa API', 'Tidak ada nomor valid.',
                                    parent=win)
            return False
        dest_limit = (PREMIUM_DEST_LIMIT if state['unlocked']
                      else FREE_DEST_LIMIT)
        if len(recipients) > dest_limit:
            messagebox.showwarning('Wa API',
                f'Maksimal {dest_limit} nomor pada mode ini.\n'
                'Klik 🔒 Auth Key untuk unlimited recipients.',
                parent=win)
            return False
        msg_limit = PREMIUM_MSG_LIMIT if state['unlocked'] else FREE_MSG_LIMIT
        if state['sent_count'] + len(recipients) > msg_limit:
            messagebox.showwarning('Wa API',
                f'Batas pesan harian tercapai ({state["sent_count"]}/{msg_limit}).',
                parent=win)
            return False
        return True

    def ensure_credentials():
        pid = phone_id_entry.get().strip()
        tok = token_entry.get().strip()
        if not pid or not tok:
            messagebox.showwarning('Wa API',
                'Phone Number ID dan Access Token wajib diisi.', parent=win)
            return None
        state['phone_id'] = pid
        state['token'] = tok
        return tok

    def send_batch(recipients, payload_fn, label):
        if state['busy']:
            return
        token = ensure_credentials()
        if not token or not check_limits(recipients):
            return
        state['busy'] = True
        send_btn.configure(state='disabled')
        total = len(recipients)
        progress.set(0)
        log(f'\n[*] Sending {label} to {total} recipient(s)...')

        def worker():
            ok, fail = 0, 0
            for i, phone in enumerate(recipients, 1):
                url = f'{GRAPH_API_BASE}/{state["phone_id"]}/messages'
                headers = {
                    'Authorization': f'Bearer {token}',
                    'Content-Type': 'application/json',
                }
                payload = payload_fn(phone)
                data, err = _http_post_json(url, headers, payload)
                if err:
                    fail += 1
                    win.after(0, lambda p=phone, e=err:
                              log(f'  [❌] {p}: {e}'))
                else:
                    ok += 1
                    mid = data.get('messages', [{}])[0].get('id', '?')
                    win.after(0, lambda p=phone, m=mid:
                              log(f'  [✅] {p}: msg_id={m[:16]}...'))
                state['sent_count'] += 1 if not err else 0
                win.after(0, lambda pc=i/total: progress.set(pc))
                win.after(0, update_counter)
                time.sleep(0.2)  # rate-limit safety

            def done():
                state['busy'] = False
                send_btn.configure(state='normal')
                set_progress(1.0, f'Done. OK: {ok} • Fail: {fail}')
                log(f'[✓] Selesai. OK: {ok}  •  Fail: {fail}')
            win.after(0, done)
        threading.Thread(target=worker, daemon=True).start()

    # ---------- send: text ----------
    def send_text():
        recipients = validate_recipients(
            recipients.get('1.0', 'end-1c'))
        text = msg_text.get('1.0', 'end-1c').strip()
        if not text:
            messagebox.showwarning('Wa API', 'Message text kosong.', parent=win)
            return
        def build(phone):
            return {
                'messaging_product': 'whatsapp',
                'to': phone,
                'type': 'text',
                'text': {'preview_url': False, 'body': text},
            }
        send_batch(recipients, build, 'text')

    # ---------- send: template ----------
    def send_template():
        recipients = validate_recipients(
            tpl_recipients.get('1.0', 'end-1c'))
        name = tpl_name.get().strip()
        lang = tpl_lang.get().strip() or 'en_US'
        if not name:
            messagebox.showwarning('Wa API', 'Template name wajib diisi.', parent=win)
            return
        params_raw = tpl_params.get().strip()
        params = None
        if params_raw:
            try:
                params = json.loads(params_raw)
                if not isinstance(params, list):
                    raise ValueError('Harus berupa array JSON')
            except Exception as e:
                messagebox.showerror('Wa API',
                    f'Params JSON invalid: {e}', parent=win)
                return

        def build(phone):
            components = []
            if params:
                components.append({
                    'type': 'body',
                    'parameters': [{'type': 'text', 'text': str(p)}
                                    for p in params],
                })
            payload = {
                'messaging_product': 'whatsapp',
                'to': phone,
                'type': 'template',
                'template': {
                    'name': name,
                    'language': {'code': lang},
                },
            }
            if components:
                payload['template']['components'] = components
            return payload
        send_batch(recipients, build, 'template')

    # ---------- send: media ----------
    def send_media():
        recipients = validate_recipients(
            med_recipients.get('1.0', 'end-1c'))
        url = med_url.get().strip()
        if not url:
            messagebox.showwarning('Wa API', 'Media URL kosong.', parent=win)
            return
        mtype = med_type_var.get()
        caption = med_caption.get().strip()

        def build(phone):
            media_obj = {'link': url}
            if caption and mtype in ('image', 'video', 'document'):
                media_obj['caption'] = caption
            if mtype == 'document' and caption:
                media_obj['filename'] = caption
            return {
                'messaging_product': 'whatsapp',
                'to': phone,
                'type': mtype,
                mtype: media_obj,
            }
        send_batch(recipients, build, mtype)

    send_btn.configure(command=lambda: send_text()
                       if tabs.get() == '📝 Text Message'
                       else send_template() if tabs.get() == '📋 Template'
                       else send_media())

    def clear_log():
        log_box.configure(state='normal')
        log_box.delete('1.0', 'end')
        log_box.configure(state='disabled')
    clear_btn.configure(command=clear_log)

    def close_win():
        if state['busy']:
            if not messagebox.askyesno('Wa API',
                'Proses masih berjalan. Hentikan dan tutup?', parent=win):
                return
        win.destroy()
        if parent.winfo_exists():
            parent.deiconify()
            parent.lift()

    win.protocol('WM_DELETE_WINDOW', close_win)

    # initial log
    log('JKSY Wa API ready.')
    log('Setup guide: https://developers.facebook.com/docs/whatsapp/cloud-api/get-started')
    log('1. Isi Phone Number ID + Access Token di atas')
    log('2. Klik 🔗 Test untuk verifikasi koneksi')
    log('3. Tambahkan nomor Anda di dashboard Meta → API Setup → To')
    log('4. Kirim pesan test dari tab Text Message')

    if not state['phone_id'] or not state['token']:
        log('\n[!] Belum ada config tersimpan. Isi form di atas lalu Save.')

    return win