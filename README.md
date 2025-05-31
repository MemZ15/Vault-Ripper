# 🧬 Kernel Cloaking & Access Control Driver

This kernel-mode driver implements low-level manipulation of the Windows object manager to enforce selective access denial and cloak kernel objects from inspection. It leverages runtime kernel introspection, salted hash matching, and object table hijacking to dynamically control visibility and access at the OS level.

---

## 🛠️ Functional Summary

- 🔍 **Dynamic Kernel Base Resolution**  
  Resolves the base of `ntoskrnl.exe` at runtime via IDT traversal.

- 🧱 **Object Type Hooking**  
  Intercepts access to processes and drivers by patching `OBJECT_TYPE` handlers.

- 🧬 **Driver Object Decoying**  
  Creates synthetic driver objects from real metadata to confuse scanners.

- 🧠 **Salted Hash Matching**  
  Obscures detection logic by relying on non-reversible, stable hashes.

- 🧹 **Self-Cleaning Lifecycle**  
  Fully restores kernel structures and frees all allocations on exit.

---

## 🧩 Technical Highlights

### ⚡ IDT-Based Kernel Base Resolution

   - Resolves kernel base address without relying on `PsLoadedModuleList` or export parsing.  
   - Utilizes Interrupt Descriptor Table introspection for stealth and reliability.  
   - Allows precise pointer resolution for internal kernel functions.

### 🔐 Handle Creation Interception

   - Hooks `OpenProcedure` in `OBJECT_TYPE` entries for `PsProcessType`, `IoDriverObjectType`.  
   - Intercepts handle requests and extracts the target's image name.  
   - Applies a salted, case-insensitive hashing mechanism.  
   - Compares against an internal blacklist (e.g., known AV or EDR modules).  
   - Denies access silently using `STATUS_ACCESS_DISABLED_BY_POLICY_DEFAULT`.

### 🧊 Driver Cloaking via Metadata Reuse

   - Selects a legitimate driver object (e.g., `\Driver\spaceport`) as a metadata donor.  
   - Duplicates its structure to create a valid, fake `DRIVER_OBJECT`.  
   - Ensures dispatch tables, section sizes, and list entries are consistent.  
   - Can be registered and exposed to mislead scanners or hide actual components.

### 🧬 Hash-Based Identity Masking

   - Replaces direct string comparisons with salted hashes of image names.  
   - All hashes are normalized (case-insensitive, trimmed to filename).  
   - Resistant to user-mode detection or brute-force enumeration.  
   - Supports fast matching for runtime policy enforcement.

### ♻️ Clean Teardown

   - Restores all hooked procedures and frees decoy objects.  
   - Prevents residual state in object manager or kernel memory.  
   - Ensures stability and safety across repeated load/unload cycles.

---

## ⚠️ Disclaimer

This project is provided **strictly for educational and research purposes**.

It demonstrates advanced kernel-level concepts such as:

   - Object manager tampering  
   - Handle access mediation  
   - Metadata spoofing  
   - Runtime stealth tactics  

**Do not use this for malicious purposes.** Unauthorized interference with third-party software or evasion of endpoint protections is unethical and may be illegal.

🧠 Use responsibly. Operate only in controlled environments. Respect local laws and system integrity.

---

## ✍️ Author Notes
WIP
