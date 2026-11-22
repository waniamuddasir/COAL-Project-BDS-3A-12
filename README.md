# COAL-Project-BDS-3A-12
# 🛡️ CyberShield
### Password Security & Login Protection System

**A 32-bit Windows desktop application developed in x86 Assembly Language (MASM) using the Win32 API.**

CyberShield is an educational security application designed to demonstrate password-strength analysis, login protection, temporary session lockout, and security event logging through a custom graphical user interface.

---

## ✨ Features

### 1. Password Strength Analyzer
- Analyzes passwords against six conditions:
  - Minimum 8 characters
  - At least one uppercase letter
  - At least one lowercase letter
  - At least one digit
  - At least one special character
  - Bonus for 12 or more characters
- Displays satisfied rules and missing requirements.
- Classifies password strength as Weak, Medium, Strong, or Very Strong.
- Provides a visual, segmented strength indicator.
- Includes Show/Hide password functionality.

### 2. Login Protection System
- Demo authentication using username and password.
- Loads credentials from an external text file.
- Tracks consecutive failed login attempts.
- Locks the login session after **3 incorrect attempts**.
- Implements a **30-second temporary lockout** with a live countdown.
- Automatically re-enables login after the lockout expires.

### 3. Session Activity Logging
- Records password checks and login activities.
- Tracks successful and unsuccessful login attempts.
- Records lockout and unlock events.
- Displays events in a colour-coded session log.
- Supports saving activity logs to a text file and viewing previously saved logs.

### 4. Graphical User Interface
- Custom dark-themed Windows interface.
- Main menu with module navigation.
- Rounded cards and input panels.
- Custom buttons, fonts, and colour indicators.
- Segmented password-strength meter.
- Colour-coded activity log.

---

## 🖥️ Application Modules

| Module | Description |
|---|---|
| Main Menu | Navigation between application features |
| Password Analyzer | Evaluates password complexity |
| Demo Login | Verifies credentials and manages lockout |
| Session Log | Displays and manages security events |

---

## 🛠️ Technologies Used

- **Language:** x86 Assembly Language
- **Assembler:** MASM (Microsoft Macro Assembler)
- **Platform:** 32-bit Windows
- **IDE:** Microsoft Visual Studio
- **GUI:** Win32 API
- **Graphics:** Windows GDI
- **File Handling:** Win32 File I/O functions

### Windows Libraries
- `kernel32.lib`
- `user32.lib`
- `gdi32.lib`
- `dwmapi.lib`
- `uxtheme.lib`

---

## ⚙️ Assembly Language Concepts Demonstrated

This project demonstrates practical implementation of:

- Procedures and modular programming (`PROC`, `ENDP`)
- Registers and register management
- Stack operations (`PUSH`, `POP`, `CALL`, `RET`)
- Loops and conditional jumps
- Arrays and indexed addressing
- String comparison and manipulation
- ASCII character classification
- File input/output operations
- Win32 API function calls
- Windows message handling
- GDI-based graphical rendering

---

## 🚀 Setup and Execution

### Requirements
- Windows operating system
- Microsoft Visual Studio
- MASM support enabled in Visual Studio
- Windows SDK

### Running the Project

1. Open Visual Studio.
2. Create or open a 32-bit MASM project.
3. Add the CyberShield `.asm` source file.
4. Configure the project for **x86**.
5. Set the linker subsystem to **Windows (/SUBSYSTEM:WINDOWS)**.
6. Ensure the required Windows SDK libraries are available.
7. Build and run the project.

**Note:** CyberShield uses the Win32 API directly and does not require the Irvine32 library.

### Data Files

The application uses two external text files:

- `demo_credentials.txt` — Stores demo login credentials. If missing, the application creates it with default demo credentials.
- `cybershield_log.txt` — Stores saved session activity logs.

These files are created or accessed by the application during execution.

---

## ⚠️ Security Disclaimer

CyberShield is an educational demonstration developed for the Computer Organization and Assembly Language (COAL) Lab.

It demonstrates basic password complexity checks and login-attempt restrictions. It is **not intended for production authentication or real account protection**.

Credentials are stored in plain text, and the password analyzer does not perform cryptographic or password-breach checks. Real-world authentication requires secure password hashing and stronger credential-management mechanisms.

---

## 👥 Project Team

**Group BDS-3A-12**

| Member | Roll Number |
|---|---|
| Wania Muddasir | 25K-2516 |
| Deenah Rehman | 25K-2520 |
| Sukaina Virani | 25K-2526 |

**Course:** EL-2003 – Computer Organization and Assembly Language (COAL) Lab  
**Semester:** Fall 2026  
**University:** National University of Computer and Emerging Sciences, Karachi Campus

---

*Developed as a group project to explore low-level programming, Windows system calls, and fundamental security concepts using Assembly Language.*
