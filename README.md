# 🧬 Kernel Cloaking & Access Interception Driver

A stealthy Windows kernel-mode driver that leverages low-level operating system internals to selectively block access to processes and drivers based on salted-hash signatures. Built with AV-evasion and forensic resilience in mind, it uses runtime resolution, memory-safe metadata cloning, and targeted object hook interception to minimize footprint and detection surface.

---

## 📌 Features

- **IDT-Based Kernel Base Resolution**  
  Locates the `ntoskrnl.exe` base using the Interrupt Descriptor Table (IDT), avoiding traditional enumeration methods prone to AV detection.

- **Dynamic Function Pointer Table**  
  Builds a secure runtime pointer table to internal kernel routines (`SeLocateProcessImageName`, memory allocation APIs, etc.), removing compile-time link dependencies.

- **Selective Access Interception**  
  Hooks key object types at the kernel level:
  - `Process`
  - `Thread`
  - `File`
  - `Driver`  
  Enables rejection of handle creations/duplications/opens based on verified, salted hash lookups.

- **Hash-Based Process & Driver Evaluation**  
  Image names are hashed using a case-insensitive salted hashing mechanism. These are compared against a hardcoded hash list (`AV_Hashes`) to allow or deny access operations in real time.

- **Driver Object Spoofing**  
  Allocates a dummy `DRIVER_OBJECT` by cloning from a legitimate driver (e.g., `\Driver\spaceport`). This object is structurally valid, mountable, and safely used to redirect or camouflage inspection attempts.

- **Safe Runtime Deactivation**  
  Hooks can be installed and removed gracefully. Execution delay is used post-load to allow system stabilization before unloading, ensuring a forensic-safe cleanup with minimal kernel residue.


---

### 🧷 Object Type Hooking

The driver intercepts the following object initializers by modifying their type-specific `OpenProcedure` handlers:

- `PsProcessType`
- `PsThreadType`
- `IoFileObjectType`
- `IoDriverObjectType`

This allows precise filtering of handle requests during creation, duplication, or opening phases, based on the calling context and target hash match.

---

### 🧮 Salted Hashing Logic

Process, thread, file, and driver image names are extracted using `SeLocateProcessImageName` or direct driver name parsing. Filenames are isolated, then hashed using a case-insensitive salted function to generate a unique identifier. The system avoids raw string comparisons entirely.

---

### 🧬 Metadata Cloaking

Metadata activity:
- A known driver object is cloned into memory.
- List pointers are copied.
- Dispatch table, size, and name are preserved.
- Original metadata is restored post-use.

The cloned object behaves identically to the original without affecting system stability.

---


## 🚫 Disclaimer

This project is intended for **educational and research purposes only**. It is not designed or supported for production use, malicious deployment, or use in circumventing protections in unauthorized ways.

---

## 👤 Author Notes

WIP
