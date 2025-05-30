# 🧬 VRF (sys.rootkit.vault-ripper) (VR)

A precision-focused Windows kernel manipulation framework designed for controlled environments, red team operations, or research into EDR evasion, kernel API resolution, and security subsystem disruption.

> ⚠️ This project is provided for educational and research purposes only. Running or deploying this on systems without explicit authorization violates laws and ethical guidelines.

---

## 🚀 Overview

VRF leverages low-level techniques to interact with and manipulate core kernel components without relying on standard (and often monitored) API calls. The framework supports:

- Kernel base resolution via IDT (no module enumeration)
- Export table parsing and AOB scanning
- Runtime pointer resolution
- `DRIVER_OBJECT` spoofing for EDR decoys
- Temporary object initializer table hooking to disable AV/runtime callbacks

---

## 🧠 Features & Modules

### 🔹 IDT-Based NTOSKRNL Base Discovery

- **Function**: `modules::throw_idt_exception`
- Leverages `sidt` instruction, and an exception trap to resolve `ntoskrnl.exe` base
- Does not rely on `PsLoadedModuleList` or `ZwQuerySystemInformation`
- Bypasses common AV heuristics

---

### 📦 Export Table Parsing & AOB Scanning

- **Function**: `hooks::hook_win_API`
- Extracts addresses of both exported and internal (non-exported) kernel functions
- Supports pattern-based resolution (with wildcards) for stealth or undocumented targets
- Saves resolved pointers to `func_pointer_table` for fast dynamic access

---

### 🧿 Legitimate Driver Object Cloning

- **Function**: `modules::get_driver_object`
- Finds and references a known Windows driver (e.g., `spaceport.sys`)
- Pulls real metadata to spoof a new `DRIVER_OBJECT`

---

### Decoy `DRIVER_OBJECT` Allocation

- **Function**: `modules::AllocateFakeDriverObject`
- Allocates a kernel-resident dummy `DRIVER_OBJECT` with copied internals
- Used to spoof AV / EDR integrity checks
- Supports safe deallocation (`DeallocateFakeDriverObject`)

---

### ⚔️ Object Initializer Table Hooking

- **Function**: `hooks::capture_initalizer_table`
- Hooks internal kernel routines responsible for object creation:
  - `PsProcessType`
  - `PsThreadType`
  - `IoDriverObjectType`
- Intercepts AV callbacks tied to policy enforcement
- Used temporarily during a specific window to suppress or redirect runtime behavior

---

## ⚠️ Disclaimer

This project is **not** intended for malicious use. It exists to:

- Educate on Windows kernel internals
- Explore advanced detection and mitigation strategies
- Provide tooling for responsible researchers and red teams in isolated lab environments

Always test in VMs. Never deploy to production machines or networks you do not own or have explicit permission to test.

---

## 🧪 Author Notes

WIP
