# 🧬 Kernel Cloaking & Access Interception Driver

A Windows **kernel-mode cloaking driver** engineered for stealth, control, and forensic resilience.  
It intercepts and sanitizes access at the object level using runtime API resolution, salted-hash signature filtering, and direct metadata manipulation to selectively block or spoof visibility to protected drivers, files, threads, and processes.

Built for AV-evasion and forensic resistance, the driver avoids static imports, hooks deep kernel internals, and resolves critical functions dynamically.

---

## 📌 Core Features

### 🧭 IDT-Based Kernel Base Discovery

- Locates `ntoskrnl.exe` base using the Interrupt Descriptor Table (IDT)
- Avoids flagged techniques like `PsLoadedModuleList` traversal

### 🧠 Runtime Function Table

- Dynamically resolves internal routines (e.g., `ObReferenceObjectByName`, `IoGetCurrentProcess`)
- All resolution is done via salted-hash of export names — no static imports

### 🧬 Salted Hash-Based Access Filtering

Intercepts and conditionally blocks:

- Process  
- Thread  
- File  
- Driver  
- Directory  
- Symbolic Link  

Hash checks are performed in real time using a case-insensitive, salted algorithm.  
Comparison is done against a precomputed whitelist or blacklist.

---

## 🛡️ Inline Hook & Syscall Integrity Checks

Performs runtime inspection of syscall entrypoint to detect hijacked handlers.

### ✔ Technique

- Reads `MSR_LSTAR` to obtain expected `syscall` handler
- Leaks actual handler pointer via indirect method
- Compares leaked address with expected value

### 🔬 Opcode-Based Hook Detection

Scans first bytes of handler for common hook patterns:

- `0xE9` → `JMP rel32`
- `0xCC` → `INT3`
- `0x48 0xB8` → `mov rax, imm64`

Early termination is triggered if hooks are detected.

---

## 🔧 Deep Object Type Hooking

Hooks specific routines within `OBJECT_TYPE_INITIALIZER` to filter object access.

| Object Type                | Intercepted Routine(s)           | Purpose                                      |
|----------------------------|---------------------------------|----------------------------------------------|
| `PsProcessType`            | `OpenProcedure`                 | Filter process handle requests               |
| `PsThreadType`             | `OpenProcedure`                 | Intercept thread access                       |
| `IoFileObjectType`         | `OpenProcedure`                 | Block access to cloaked file paths           |
| `IoDriverObjectType`       | `OpenProcedure`, `ParseProcedureEx` | Obfuscate presence of protected drivers |
| `IoDeviceObjectType`       | `OpenProcedure`                 | Hide device interfaces tied to drivers       |
| `ObDirectoryObjectType`    | `OpenProcedure`                 | Filter directory enumeration                  |
| `ObSymbolicLinkObjectType` | `OpenProcedure`                 | Block symlink traversal                       |

Each hook inspects access context and can return clean failure codes like `STATUS_OBJECT_NAME_NOT_FOUND`.

---

## 📦 Driver Object Cloaking

Fabricates decoy `DRIVER_OBJECT`s by cloning trusted drivers like `\Driver\spaceport`.

- Copies dispatch table, driver name, and type metadata  
- Returns spoofed structure during queries or IRP dispatch  
- Evades detection during routine inspections

---

## 🧮 Salted Hash Filtering Logic

1. Extract base name (e.g., `\Device\HarddiskVolumeX\Windows\System32\bad.exe` → `bad.exe`)  
2. Lowercase and salt  
3. Hash with custom case-insensitive function  
4. Compare against in-memory whitelist or blacklist  

Filtering is fast, opaque, and avoids storing raw names in memory.

---

## 🧩 ParseProcedureEx Interception

Intercepts deep object resolution via `IoDriverObjectType::ParseProcedureEx`.

### Context Inspected

- `ObjectName`, `RemainingName`  
- `AccessState`, `DesiredAccess`, `AuditInfo`  

### Filtering Strategy

- Hash driver name from parse context  
- Block access cleanly without crashing  
- Silently filter blacklisted drivers from resolution path

---

## 🔬 Metadata Cloaking & Restoration

- Allocates full clone of target object (e.g., `DRIVER_OBJECT`)  
- Copies internal metadata, dispatch routines, and list entries  
- Temporarily replaces references during inspection  
- Restores original object with integrity validation  

Ensures stealth under AV, EDR, or forensic tools that query kernel objects directly.

---

## 🧪 Alternate Syscall Support (WIP)

Planned support for bypassing traditional NT/Zw layers:

- SSDT remapping and low-level syscall variants  
- Wrapping of `syscall` instructions via internal redirection  
- UM-kernel syscall bridges with selective filtering

---

## 🖼️ Architecture Overview

![Driver Object Cloaking Diagram](https://cdn.discordapp.com/attachments/1217690516804866172/1378294258519244841/image.png?ex=683c140e&is=683ac28e&hm=e1dad0a26eded13d80587433b3c7e24f90f2230e33a05eae4db2112d67ac4fc6&)

---

## 🚫 Disclaimer

This project is provided strictly for **educational and research purposes**.  
Unauthorized use, malicious deployment, or evasion of lawful protections is **strictly prohibited**.  
The author assumes **no liability** for misuse or illegal application of the contents herein.

---

## 👤 Author Notes
