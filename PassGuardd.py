import tkinter as tk
from tkinter import ttk, messagebox
import string
import math
import re
import random
import os
import sys
import threading
import gzip

# -------------------- CONFIG / DATA --------------------
# Common substrings (to change later(database or high risk hits.))
COMMON_PATTERNS = {
    "1234","12345","123456","1234567","12345678","123456789","1234567890",
    "0000","1111","2222","3333","4444","5555","6666","7777","8888","9999",
    "abcd","abc123","qwerty","qwertyuiop","asdf","zxcv","letmein","iloveyou",
    "admin","root","welcome","password","pass","monkey","poland","france"
}
# Small built-in dictionary (expand as needed)
DICTIONARY = {
    "hello","world","love","secret","tunisia","poland","agh","silesia","poznan",
    "student","engineer","security","electric","telecom","computer","science",
    "school","university","teacher","family","mobile","number","email","name",
    "keyboard","password","welcome","football","dragon","monkey"
}
# Leet mapping for normalized checks
LEET_MAP = str.maketrans({
    "0":"o","1":"l","3":"e","4":"a","5":"s","7":"t","8":"b","9":"g","@":"a","$":"s","!":"i"
})
# Keyboard rows for walking detection
KEYBOARD_ROWS = [
    "1234567890",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm"
]
# UI performance guard
MAX_LEN_FOR_ANALYSIS = 1024  # analyze first N chars to keep UI responsive
# RockYou integration settings
ROCKYOU_PATH = os.environ.get("ROCKYOU_PATH", "rockyou.txt")  # set to rockyou.txt or rockyou.txt.gz
ROCKYOU_ENABLED_DEFAULT = True
ROCKYOU_MAX_LINES = int(os.environ.get("ROCKYOU_MAX_LINES", "2000000"))  # cap load to keep memory reasonable
ROCKYOU_MIN_LEN = 4  # ignore trivially short entries
# -------------------- HELPERS --------------------
def is_emoji(ch: str) -> bool:
    cp = ord(ch)
    return (0x1F300 <= cp <= 0x1FAFF) or (0x2600 <= cp <= 0x27BF) or (0x1F1E6 <= cp <= 0x1F1FF)
def classify_charset(password: str):
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any((not c.isalnum()) and not is_emoji(c) for c in password)
    has_emoji  = any(is_emoji(c) for c in password)
    has_non_ascii_letter = any(c.isalpha() and c not in string.ascii_letters for c in password)
    return has_lower, has_upper, has_digit, has_symbol, has_emoji, has_non_ascii_letter
def estimated_pool_size(password: str) -> int:
    has_lower, has_upper, has_digit, has_symbol, has_emoji, has_non_ascii_letter = classify_charset(password)
    pool = 0
    if has_lower: pool += 26
    if has_upper: pool += 26
    if has_digit: pool += 10
    if has_symbol: pool += 32
    if has_non_ascii_letter: pool += 400
    if has_emoji: pool += 3000
    return pool
# -------------------- PATTERN DETECTION --------------------
def detect_full_repeat(password: str):
    """If the entire password is repetition like 'abcdabcd', return base unit."""
    if not password:
        return None
    m = re.fullmatch(r"(.+?)\1+", password.lower())
    return m.group(1) if m else None
def has_common_substring(password: str):
    low = password.lower()
    for pat in COMMON_PATTERNS:
        if pat in low:
            return pat
    return None
def detect_sequences(password: str, min_run=4):
    low = password.lower()
    for i in range(len(low) - min_run + 1):
        chunk = low[i:i+min_run]
        # only letters/digits make sense for sequence check
        if not all(c.isalnum() for c in chunk):
            continue
        asc = all(ord(chunk[j+1]) - ord(chunk[j]) == 1 for j in range(len(chunk)-1))
        desc = all(ord(chunk[j]) - ord(chunk[j+1]) == 1 for j in range(len(chunk)-1))
        if asc or desc:
            return chunk
    return None
def detect_keyboard_walk(password: str, min_run=4):
    low = password.lower()
    for r in KEYBOARD_ROWS:
        for i in range(len(r) - min_run + 1):
            walk = r[i:i+min_run]
            if walk in low or walk[::-1] in low:
                return walk
    return None
def detect_dates(password: str):
    # detect years like 1980, 1999, 2000; detect YYYYMMDD or DDMMYYYY loosely
    if re.search(r"(19|20)\d{2}", password):
        if re.search(r"(19|20)\d{2}[-_/]?\d{2}[-_/]?\d{2}", password) or re.search(r"\b\d{2}[-_/]?\d{2}[-_/]?(19|20)\d{2}\b", password):
            return "date"
        return "year"
    return None
def leet_normalize(s: str) -> str:
    return s.translate(LEET_MAP)
def contains_dictionary_word(password: str):
    low = password.lower()
    low_lean = leet_normalize(low)
    for w in DICTIONARY:
        if len(w) >= 4 and (w in low or w in low_lean):
            return w
    return None
# -------------------- ROCKYOU INTEGRATION --------------------
_rockyou_loaded_count = 0
_rockyou_total_seen = 0
_rockyou_set = None
_rockyou_enabled_flag = ROCKYOU_ENABLED_DEFAULT
_rockyou_status_text = "RockYou: not loaded"
def _open_maybe_gzip(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="ignore")
    return open(path, "r", encoding="utf-8", errors="ignore")
def load_rockyou_async():
    """
    Only runs once safe if file not present.
    """
    global _rockyou_set, _rockyou_loaded_count, _rockyou_total_seen, _rockyou_status_text
    if _rockyou_set is not None:
        return
    _rockyou_set = set()
    path = ROCKYOU_PATH
    if not os.path.exists(path):
        _rockyou_status_text = f"RockYou: file not found ({path})"
        return
    try:
        seen = 0
        loaded = 0
        with _open_maybe_gzip(path) as fh:
            for line in fh:
                seen += 1
                if loaded >= ROCKYOU_MAX_LINES:
                    # Stop after cap to protect memory/boot time
                    break
                pw = line.strip()
                if len(pw) >= ROCKYOU_MIN_LEN:
                    _rockyou_set.add(pw.lower())
                    loaded += 1
        _rockyou_loaded_count = loaded
        _rockyou_total_seen = seen
        if loaded >= ROCKYOU_MAX_LINES:
            _rockyou_status_text = f"RockYou: loaded {loaded:,}/{seen:,}+ (capped)"
        else:
            _rockyou_status_text = f"RockYou: loaded {loaded:,}/{seen:,}"
    except Exception as e:
        _rockyou_set = None
        _rockyou_status_text = f"RockYou: load error: {e}"

def rockyou_contains(password: str) -> bool:
    """
    Check if password is present in loaded RockYou set.
    Leet-normalized alternative also checked for extra coverage.
    """
    global _rockyou_set
    if not _rockyou_enabled_flag or _rockyou_set is None or not password:
        return False
    low = password.lower()
    if low in _rockyou_set:
        return True
    normalized = leet_normalize(low)
    return normalized in _rockyou_set
# Start loading on import (so Tk or Flask gets it soon)
threading.Thread(target=load_rockyou_async, daemon=True).start()
# -------------------- PATTERN DETECTION (with RockYou) ---------------------
def detect_patterns(password: str):
    findings = {}
    if not password:
        return findings
    full = detect_full_repeat(password)
    if full: findings['full_repeat'] = full
    cs = has_common_substring(password)
    if cs: findings['common'] = cs
    seq = detect_sequences(password)
    if seq: findings['sequence'] = seq
    kb = detect_keyboard_walk(password)
    if kb: findings['keyboard'] = kb
    dt = detect_dates(password)
    if dt: findings['date'] = dt
    dw = contains_dictionary_word(password)
    if dw: findings['dict'] = dw
    try:
        if rockyou_contains(password):
            findings['rockyou'] = True
    except Exception:
        pass
    return findings

# ---------------------- ENTROPY CALCULATION --------------------
def effective_entropy(password: str):
    """
    Baseline entropy from char pool, with penalties for patterns.
    Full repeats -> very low entropy (almost instant).
    Partial patterns reduce entropy by factors.
    RockYou presence -> severe penalty.
    """
    if not password:
        return 0.0
    p = password[:MAX_LEN_FOR_ANALYSIS]
    pool = estimated_pool_size(p)
    if pool <= 0:
        return 0.0
    base_entropy = len(p) * math.log2(pool)

    findings = detect_patterns(p)

    # Full repeat => tiny entropy
    if 'full_repeat' in findings:
        return 8.0

    # Apply multiplicative penalties for findings (less severe)
    penalty = 1.0
    if 'dict' in findings:      penalty *= 0.55
    if 'common' in findings:    penalty *= 0.70
    if 'sequence' in findings:  penalty *= 0.78
    if 'keyboard' in findings:  penalty *= 0.80
    if 'date' in findings:      penalty *= 0.88
    if 'rockyou' in findings:   penalty *= 0.15  # being in RockYou is a huge red flag

    entropy = base_entropy * penalty
    # floor to reasonable minimum (except full_repeat handled above)
    entropy = max(entropy, 12.0)
    return entropy
# ------------------- ANALYSIS --------------------
def analyze_password_core(password: str):
    """
    Returns: strength_label, color, tips(list), entropy(bits), findings(dict)
    """
    tips = []
    findings = detect_patterns(password)
    H = effective_entropy(password)
    has_lower, has_upper, has_digit, has_symbol, has_emoji, has_non_ascii_letter = classify_charset(password)
    #composition tips
    if len(password) < 8:
        tips.append("Use at least 8 characters.")
    if len(password) < 12:
        tips.append("Prefer 12+ characters for better safety.")
    if not has_lower: tips.append("Add lowercase letters.")
    if not has_upper: tips.append("Add uppercase letters.")
    if not has_digit: tips.append("Add numbers.")
    if not (has_symbol or has_emoji): tips.append("Add symbols or emojis for extra entropy.")
    if len(password) > MAX_LEN_FOR_ANALYSIS:
        tips.append(f"Only the first {MAX_LEN_FOR_ANALYSIS} chars analyzed for speed.")

    # pattern-specific tips
    if 'full_repeat' in findings:
        tips.append(f"Password is a repetition of '{findings['full_repeat']}' — avoid full repeats.")
    if 'dict' in findings:
        tips.append(f"Contains dictionary word '{findings['dict']}' — avoid common words.")
    if 'common' in findings:
        tips.append(f"Contains common chunk '{findings['common']}' — avoid predictable parts.")
    if 'sequence' in findings:
        tips.append(f"Contains sequence '{findings['sequence']}' — break sequences.")
    if 'keyboard' in findings:
        tips.append(f"Contains keyboard walk '{findings['keyboard']}' — avoid adjacent keys.")
    if 'date' in findings:
        tips.append("Looks like a date or year — avoid personal dates.")
    if 'rockyou' in findings:
        tips.append("Appears in the RockYou breach list — choose a completely different password.")
    # strength buckets
    if 'full_repeat' in findings:
        strength, color = "Very Weak", "red"
    elif H < 28:
        strength, color = "Weak", "red"
    elif H < 40:
        strength, color = "Fair", "orange"
    elif H < 60:
        strength, color = "Strong", "blue"
    else:
        strength, color = "Very Strong", "green"
    # if patterns present and labeled Very Strong, downgrade slightly
    if any(k in findings for k in ('dict','common','sequence','keyboard','date','rockyou')) and strength == "Very Strong":
        strength, color = "Strong*", "blue"
    # Extra visible downgrade for RockYou
    if 'rockyou' in findings and strength in ("Strong", "Strong*"):
        strength, color = "Fair*", "orange"
    return strength, color, tips, H, findings
# -------------------- PASSWORD GENERATOR --------------------
SYMBOLS = "!@#$%^&*()-_=+[]{};:,<.>/?~"
def generate_password(length=16, use_lower=True, use_upper=True, use_digits=True, use_symbols=True):
    pools = []
    if use_lower: pools.append(string.ascii_lowercase)
    if use_upper: pools.append(string.ascii_uppercase)
    if use_digits: pools.append(string.digits)
    if use_symbols: pools.append(SYMBOLS)

    if not pools:
        pools = [string.ascii_letters + string.digits]
    all_chars = "".join(pools)
    #ensure at least one from each selected
    must = []
    if use_lower: must.append(random.choice(string.ascii_lowercase))
    if use_upper: must.append(random.choice(string.ascii_uppercase))
    if use_digits: must.append(random.choice(string.digits))
    if use_symbols: must.append(random.choice(SYMBOLS))
    remaining = max(length - len(must), 0)
    body = [random.choice(all_chars) for _ in range(remaining)]
    candidate = must + body
    random.shuffle(candidate)
    candidate = "".join(candidate)
    # Avoid obvious pattern/bad dictionary results
    findings = detect_patterns(candidate)
    if 'full_repeat' in findings or 'common' in findings or 'dict' in findings:
        return generate_password(length, use_lower, use_upper, use_digits, use_symbols)
    return candidate
# -------------------- UI -------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Advanced Password Strength Checker")
        self.geometry("700x700")
        self.resizable(False, False)
        top = ttk.Frame(self)
        top.pack(pady=8, fill="x")
        ttk.Label(top, text="Enter Password:", font=("Arial", 12)).pack(side="left", padx=6)
        self.password_var = tk.StringVar()
        self.entry = ttk.Entry(top, show="*", textvariable=self.password_var, width=44, font=("Arial", 12))
        self.entry.pack(side="left", padx=6)
        self.entry.bind("<KeyRelease>", lambda e: self.on_change())
        self.show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Show", variable=self.show_var, command=self.toggle_show).pack(side="left", padx=6)
        ttk.Button(top, text="Copy", command=self.copy_password).pack(side="left", padx=6)
        # Strength & bar
        self.str_label = ttk.Label(self, text="", font=("Arial", 14, "bold"))
        self.str_label.pack(pady=6)
        self.bar = tk.Canvas(self, width=420, height=20, bg="#e8e8e8", highlightthickness=0)
        self.bar.pack()
        self.bar.create_rectangle(0,0,0,20, fill="green", tags="bar")
        # Options
        opt = ttk.Frame(self); opt.pack(pady=8, fill="x")
        self.show_entropy = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt, text="Show Entropy", variable=self.show_entropy, command=self.on_change).pack(side="left", padx=8)
        #RockYou status line and toggle
        status_frame = ttk.Frame(self)
        status_frame.pack(pady=(0,6), fill="x")
        self.rockyou_label = ttk.Label(status_frame, text=_rockyou_status_text, font=("Arial", 9))
        self.rockyou_label.pack(side="left", padx=8)
        self.rockyou_var = tk.BooleanVar(value=_rockyou_enabled_flag)
        self.rockyou_check = ttk.Checkbutton(status_frame, text="Use RockYou blacklist", variable=self.rockyou_var, command=self._toggle_rockyou)
        self.rockyou_check.pack(side="right", padx=8)
        # Entropy label
        self.entropy_label = ttk.Label(self, text="", font=("Arial", 10))
        self.entropy_label.pack(pady=2)
        # Tips
        ttk.Label(self, text="Tips to Improve Password:", font=("Arial", 10, "bold")).pack(pady=(10,2))
        self.tips_label = tk.Label(self, text="", font=("Arial",10), fg="gray25", justify="left", wraplength=680, anchor="w")
        self.tips_label.pack(padx=10, pady=(0,8), fill="x")
        # Generator frame
        gen = ttk.LabelFrame(self, text="Generate Strong Password")
        gen.pack(padx=10, pady=6, fill="x")
        self.len_var = tk.IntVar(value=16)
        ttk.Label(gen, text="Length:").grid(row=0, column=0, padx=6, pady=4, sticky="w")
        ttk.Spinbox(gen, from_=8, to=128, textvariable=self.len_var, width=6).grid(row=0, column=1, padx=6, pady=4)
        self.g_lower = tk.BooleanVar(value=True)
        self.g_upper = tk.BooleanVar(value=True)
        self.g_digits = tk.BooleanVar(value=True)
        self.g_symbols = tk.BooleanVar(value=True)
        ttk.Checkbutton(gen, text="Lower", variable=self.g_lower).grid(row=0, column=2, padx=6, pady=4)
        ttk.Checkbutton(gen, text="Upper", variable=self.g_upper).grid(row=0, column=3, padx=6, pady=4)
        ttk.Checkbutton(gen, text="Digits", variable=self.g_digits).grid(row=0, column=4, padx=6, pady=4)
        ttk.Checkbutton(gen, text="Symbols", variable=self.g_symbols).grid(row=0, column=5, padx=6, pady=4)
        ttk.Button(gen, text="Generate", command=self.generate_new).grid(row=0, column=6, padx=8, pady=4)
        disclaimer = (
            "Note: This is an estimation based on password entropy and common patterns. "
            "Real-world safety depends on the target system's hashing and storage methods."
        )
        ttk.Label(self, text=disclaimer, wraplength=680, foreground="gray25", font=("Arial",9)).pack(pady=(6,8), padx=10)
        # Periodically refresh RockYou load status
        self.after(500, self._refresh_rockyou_status)
        # initial update
        self.on_change()
    def toggle_show(self):
        self.entry.config(show="" if self.show_var.get() else "*")
    def copy_password(self):
        pwd = self.password_var.get()
        if not pwd:
            messagebox.showwarning("Warning", "No password to copy!")
            return
        self.clipboard_clear(); self.clipboard_append(pwd)
        messagebox.showinfo("Copied", "Password copied to clipboard!")
    def generate_new(self):
        length = max(8, min(int(self.len_var.get()), 128))
        pwd = generate_password(
            length=length,
            use_lower=self.g_lower.get(),
            use_upper=self.g_upper.get(),
            use_digits=self.g_digits.get(),
            use_symbols=self.g_symbols.get()
        )
        self.password_var.set(pwd)
        self.entry.icursor("end")
        self.on_change()
    def on_change(self, *_):
        pwd = self.password_var.get()
        strength, color, tips, H, findings = analyze_password_core(pwd)

        self.str_label.config(text=f"Strength: {strength}", foreground=color)
        bar_len = int(min(max(H,0), 80) / 80 * 420)
        self.bar.coords("bar", 0, 0, bar_len, 20)
        self.bar.itemconfig("bar", fill=color)

        self.tips_label.config(text=("\n".join(tips) if tips else "No obvious weaknesses detected."))

        if self.show_entropy.get():
            self.entropy_label.config(text=f"Entropy: {H:.2f} bits")
        else:
            self.entropy_label.config(text="")      
    def _refresh_rockyou_status(self):
        global _rockyou_status_text
        self.rockyou_label.config(text=_rockyou_status_text)
        # keep refreshing a few times at startup
        self.after(1000, self._refresh_rockyou_status)  
    def _toggle_rockyou(self):
        global _rockyou_enabled_flag
        _rockyou_enabled_flag = bool(self.rockyou_var.get())
        self.on_change()
if __name__ == "__main__":
    app = App()
    app.mainloop()