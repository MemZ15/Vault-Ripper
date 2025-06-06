# 🧬 Kernel Cloaking & Access Interception Driver

A Windows **kernel-mode cloaking driver** engineered for stealth, control, and forensic resilience. Designed to intercept and sanitize access at the object level, it employs runtime API resolution, salted-hash signature filtering, and metadata manipulation to selectively block or spoof visibility to protected drivers, files, threads, and processes.

This driver bypasses conventional AV heuristics, evades common forensic tooling, and leaves minimal footprint by directly intercepting kernel object routines and resolving sensitive structures without relying on public symbols or imports.

---

## 📌 Core Features

### 🧭 IDT-Based Kernel Base Discovery  
Locates the base of `ntoskrnl.exe` using the Interrupt Descriptor Table (IDT), avoiding standard methods like `PsLoadedModuleList` that are easily flagged by AV/EDR solutions.

### 🧠 Runtime Function Table  
Builds a secure runtime table of internal kernel routines (e.g., `ObReferenceObjectByName`, `IoGetCurrentProcess`) to eliminate static imports and reduce attack surface.

### 🧬 Salted Hash-Based Access Filtering  
Intercepts and conditionally blocks handle creation, duplication, and open requests to critical object types based on case-insensitive, salted hash lookups.  
Targeted object types include:
- Process
- Thread
- File
- Driver
- Directory
- Symbolic Link

Hash checks are evaluated in real time using a static or runtime-injected whitelist/blacklist.

### 📦 Driver Object Cloaking  
Clones a valid `DRIVER_OBJECT` (e.g., `\Driver\spaceport`) to fabricate a safe decoy:
- Copies all valid metadata and pointers
- Preserves dispatch routines
- Passes as structurally valid to IRP requests and inspection tools

This technique prevents detection of sensitive or malicious drivers by misdirecting parsing and query routines.

### 🛡️ Hook Lifecycle Management  
Hooks are deployed at runtime with safe installation and removal logic.  
Post-initialization, a delay mechanism ensures system stability before potential self-unload. Upon unload, memory is wiped, and hooks are reverted, minimizing forensic residue.

---

## 🔧 Deep Object Type Hooking

The driver modifies the following `OBJECT_TYPE_INITIALIZER` routines:

| Object Type              | Intercepted Routine(s)     | Purpose                                          |
|--------------------------|----------------------------|--------------------------------------------------|
| `PsProcessType`          | `OpenProcedure`            | Filter process handle requests                   |
| `PsThreadType`           | `OpenProcedure`            | Intercept thread access and manipulation         |
| `IoFileObjectType`       | `OpenProcedure`            | Block access to cloaked file paths               |
| `IoDriverObjectType`     | `OpenProcedure`, `ParseProcedureEx` | Obfuscate presence of protected drivers     |
| `IoDeviceObjectType`     | `OpenProcedure`            | Hide device interfaces tied to hidden drivers    |
| `ObDirectoryObjectType`  | `OpenProcedure`            | Filter enumeration of object directories         |
| `ObSymbolicLinkObjectType` | `OpenProcedure`          | Prevent detection through symlink traversal      |

Each handler inspects access requests and denies unauthorized attempts using clean NTSTATUS codes (e.g., `STATUS_OBJECT_NAME_NOT_FOUND`), ensuring stealth without causing alerts.

---

## 🧮 Salted Hash Filtering Logic

Instead of string comparisons, the driver uses a secure hashing pipeline:
- Extracts image or object name (via `SeLocateProcessImageName`, `DriverObject->DriverName`, etc.)
- Isolates the base filename
- Lowercases and hashes using a **case-insensitive salted algorithm**
- Compares against a whitelist/blacklist of precomputed hashes

This ensures low-latency, high-resilience filtering that avoids exposing protected names to memory scanners or AV heuristics.

---

## 🧩 ParseProcedureEx Interception

By hooking the `ParseProcedureEx` routine in `IoDriverObjectType`, the driver intercepts deep resolution paths used by `ObOpenObjectByName` and similar calls.

### Context Inspected:
- `ObjectName` and `RemainingName`
- `AccessState`, `DesiredAccess`, and audit fields
- Extended parse parameters, if present

### Filtering Strategy:
- Extracts and hashes the driver name
- Rejects unauthorized requests using clean denial codes
- Masks the existence of protected drivers without crashing or alerting

---

## 🧪 Alternate Syscall Support (WIP)

Planned support for alternative, undocumented system calls that bypass traditional `Nt/Zw` syscall paths:
- SSDT scanning for low-level syscall variants
- Redirection/wrapping of object access via alternate paths
- Early detection and filtering of direct `syscall` invocations

---

## 🔬 Metadata Cloaking and Restoration

The driver replicates legitimate kernel objects and replaces references temporarily:
- Allocates clone of `DRIVER_OBJECT` or other targets
- Copies all internal metadata, dispatch tables, and list links
- Serves as a decoy during inspection
- Restores original references with integrity checks after use

This technique avoids detection by AV/EDR tools and ensures consistent behavior under legitimate system probes.

---

## 🖼️ Architecture Overview

![Driver Object Cloaking Diagram](https://cdn.discordapp.com/attachments/1217690516804866172/1378294258519244841/image.png?ex=683c140e&is=683ac28e&hm=e1dad0a26eded13d80587433b3c7e24f90f2230e33a05eae4db2112d67ac4fc6&)

---

## 🚫 Disclaimer

This project is provided strictly for **educational and research purposes**.  
It must not be used for unauthorized access, malicious deployment, or evasion of lawful protections. The author assumes **no responsibility** for misuse of this tool in violation of ethical, legal, or operational boundaries.

---

## 👤 Author Notes

This project is a work in progress.  
Future additions may include:
- SSDT shadow mapping
- Encrypted remote hash list injection
- Configurable user-mode interface (UM-to-KM)

All feedback, ideas, and technical contributions are welcome via issues or pull requests.

---
