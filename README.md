# 🧬 Kernel Cloaking & Access Interception Driver

A stealth-focused **Windows kernel-mode driver** that filters or spoofs access to protected drivers, threads, processes, and files.  
Built for evasion, forensic resilience, and deep system control — with no static imports, dynamic salted-hash resolution, and runtime object manipulation.

---

## 📌 Core Features

### 🧭 IDT-Based Kernel Base Discovery

- Locates `ntoskrnl.exe` using the Interrupt Descriptor Table (IDT)
- Avoids detection-prone methods like `PsLoadedModuleList`

### 🧠 Runtime Function Resolution (No Static Imports)

- All kernel functions resolved via salted, case-insensitive hashes at runtime
- No suspicious IAT entries
- Functions like:
  - `ObReferenceObjectByName`
  - `IoGetCurrentProcess`
  - `ZwQuerySystemInformation`

---

## 🧬 Salted Hash-Based Filtering

Intercepts access to:

- Processes  
- Threads  
- Drivers  
- Files  
- Symbolic links  
- Object directories  

**How filtering works:**

1. Extracts basename from object (e.g., `bad.exe`)
2. Lowercases and salts it
3. Hashes with a custom case-insensitive algorithm
4. Compares to in-memory blacklist or whitelist

---

## 🔧 Deep Object Type Hooking

Hooks inside `OBJECT_TYPE_INITIALIZER` for real-time filtering.

| Object Type                | Hooked Routines                          | Purpose                          |
|----------------------------|------------------------------------------|----------------------------------|
| `PsProcessType`            | `OpenProcedure`                          | Block process handle access      |
| `PsThreadType`             | `OpenProcedure`                          | Block thread handle access       |
| `IoFileObjectType`         | `OpenProcedure`                          | Cloak or block file access       |
| `IoDriverObjectType`       | `OpenProcedure`, `ParseProcedureEx`      | Hide or spoof drivers            |
| `IoDeviceObjectType`       | `OpenProcedure`                          | Hide device interfaces           |
| `ObDirectoryObjectType`    | `OpenProcedure`                          | Block access to directory paths  |
| `ObSymbolicLinkObjectType` | `OpenProcedure`                          | Block symbolic link traversal    |

Returns clean codes like `STATUS_OBJECT_NAME_NOT_FOUND`.

---

## 🛡️ Inline Hook & Syscall Integrity Check

Performs runtime checks to detect syscall entrypoint hooks.

**Detection logic:**

- Reads `MSR_LSTAR` to get expected `syscall` handler
- Compares leaked vs expected pointer
- Checks first few opcodes for:
  - `0xE9` (JMP rel32)
  - `0xCC` (INT3)
  - `0x48 0xB8` (mov rax, imm64)

Aborts if tampering is detected.

---

## 🧩 ParseProcedureEx Interception

Intercepts `IoDriverObjectType::ParseProcedureEx`.

**Inspects:**
- `ObjectName`, `RemainingName`
- `AccessState`, `DesiredAccess`

**Then:**
- Hashes basename
- Filters if blacklisted
- Returns clean failure if blocked

---

## 🧮 Metadata Cloaking

- Allocates and prepares a shadow copy of kernel objects
- Temporarily replaces references for duration of inspection
- Restores originals post-query
- Leaves no trace after restoration

---

## 🧪 New: User-Mode Loader via Vulnerable Driver

Bypasses DSE and loads unsigned kernel drivers at runtime.

**Flow:**

1. Load vulnerable signed driver (e.g., `gdrv.sys`)
2. Overwrite `ci!CiValidateImageHeader` callback
3. Load unsigned cloaking driver
4. Restore original callback

**Benefits:**

- No bootkits
- No test signing
- No PatchGuard tampering
- No persistent system changes

## 🧪 Alternate Syscall Support (WIP)

Planned support for bypassing traditional NT/Zw layers:
- UM-kernel syscall bridges with selective filtering

---

## 🖼️ Architecture Overview

![Driver Object Cloaking Diagram](https://cdn.discordapp.com/attachments/1217690516804866172/1382611615052206120/image.png?ex=684bc8e8&is=684a7768&hm=3c0c579db1d2b009fe497b1ae2b58c289ebf6e1a3d1b2c8a22f3396c2fb41a1f&)

---

## 🚫 Disclaimer

This project is provided strictly for **educational and research purposes**.  
Unauthorized use, malicious deployment, or evasion of lawful protections is **strictly prohibited**.  
The author assumes **no liability** for misuse or illegal application of the contents herein.

---🧩References
https://revers.engineering/
https://www.vergiliusproject.com/
https://v1k1ngfr.github.io/
https://www.powerofcommunity.net/poc2012/mj0011.pdf
https://community.osr.com/
http://www.rohitab.com/discuss/tags/forums/DKOM/
https://www.unknowncheats.me/forum/general-programming-and-reversing/235220-load-unsigned-drivers.html


## 👤 Author Notes
WIP
