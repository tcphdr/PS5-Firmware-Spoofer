# ⚠️ **WARNING: HARDCODED OFFSETS** ⚠️
**This payload currently relies on hardcoded kernel offsets specific to Firmware 11.20. Running this unmodified on any other firmware version will NOT WORK. Since there is no real gain from doing this, there will be no more updates or continued support.**

---

# Description

Payload that leverages the GPU's Direct Memory Access (DMA) engine to bypass hypervisor memory protections. By utilizing the GPU to perform arbitrary writes to the kernel's `.data` section, this payload successfully spoofs system firmware and SDK versions without tripping CPU-level execution traps.

## Technical Specifications

| Component | Target/Value |
| :--- | :--- |
| **Tested Firmware** | 11.20 *(Offsets must be modified for other versions)* |
| **Execution Vector** | GPU DMA (`/dev/gc`) |
| **Spoofed Version** | `0x99999999` (99.99) |
| **Target Sysctls** | `kern.ps4_sdk_version`, `kern.sdk_version`, `machdep.upd_version` |

## How It Works

Instead of attempting a direct CPU write to read-only or protected kernel memory, this payload:
1. **Resolves the DMAP Base:** Finds the Direct Map base via `pmap_store`.
2. **Maps Direct Memory:** Allocates shared CPU/GPU memory buffers (`transfer`, `victim`, `cmd`).
3. **Walks the GPU Page Tables:** Translates virtual addresses to physical addresses to locate the exact page table entries governing the target kernel variables.
4. **Executes the DMA Transfer:** Submits a command to the GPU pipeline (`ioctl(g_gc_fd, ...)`), instructing the GPU's DMA engine to write the `0x99999999` payload directly into the physical memory backing the sysctl variables. 

## Usage

1. Verify your console is running **FW 11.20** (or update the macros `PMAP_STORE_OFF`, `ALLPROC_OFF`, and `GVMSPACE_BASE_OFF` for your target firmware).
2. Compile the payload using your PS5 toolchain.
3. Inject the payload using your preferred execution method.
4. Check the on-screen notification to verify the version strings have successfully shifted from their original hex values to `0x99999999`.

## Known Issues
* Modifying these sysctl variables is likely to cause payload loading from the ELF loader to stop working, this is unavoidable if you choose to modify more than the PS4 SDK variable.

## Future Plans
* Specification of firmware version to modify
* Cleanup & optimizations to codebase.
* Firmware agnosticizing

---

## Credits
* **Author:** darkness
* **Base Concept & Inspiration:** Illusionyy (https://github.com/illusionyy/ps5-fw-spoof)
