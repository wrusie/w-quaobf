# QUAOBF — Educational EXE Protector with Anti-Analysis Capabilities

> 🔐 **For ethical research, software protection education, and authorized red-teaming only.**  
> QUAOBF demonstrates layered binary protection techniques including encryption, obfuscation, and runtime environment validation. **Do not use for malicious purposes.**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-Apache%202.0-blue?logo=apache)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)

---

## 🧠 What Is QUAOBF?

QUAOBF is a **proof-of-concept tool** that wraps a Windows `.exe` file in multiple defensive layers:
- **AES-256-CBC encryption** with random key & IV
- **Custom XOR obfuscation** with bit rotation and masking
- **File padding** to arbitrary size (e.g., 100 MB) to hinder static analysis
- **Runtime anti-VM / anti-sandbox checks** (processes, drivers, MAC, CPU, IP, timing)
- **Self-decrypting loader** compiled into a single-file EXE via PyInstaller

If a suspicious environment is detected, the payload **is never executed**—only a harmless GUI counter appears before exit.

This project is **strictly for educational use** to help developers and researchers understand:
- Binary protection fundamentals
- Evasion detection logic
- Secure loader design

---

## ⚠️ Important Disclaimers

- **Antivirus Alerts Are Expected**: Packed, self-decrypting binaries with anti-analysis logic will trigger heuristic detections. This is normal and **not a bug**.
- **Not for Malware**: Using QUAOBF to hide malicious payloads violates GitHub’s policies and may be illegal.
- **No Warranty**: Use at your own risk. The authors assume no liability for misuse or damage.

---

## 📦 Installation

### Prerequisites
- Windows 10/11 (anti-VM features are Windows-specific)
- Python 3.8 or newer
- `pip` installed
