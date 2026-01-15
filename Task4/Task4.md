# Task 4 - Unpacking Insight - (Malware Analysis)
### Date started: October 12, 2025
### Date completed: October 23, 2025
## Provided Materials
- Obfuscated file (suspicious)
## Objective
Analyze the provided obfuscated malware sample and determine the file path used by the malware to write an output file.
## Analysis
### Stage 1: The Unpacker
I identified the malware sample as an ELF executable and began analysis using Ghidra. The program was written in C and relies primarily on standard `libc` functions. No debug symbols were provided, so analysis proceeded from the default entry point and into the `main` function.

Initial inspection revealed that the malware contained heavily obfuscated code. A significant portion of the program consists of decoy logic, redundant computations, and multiple anti-debugging checks designed to complicate both static and dynamic analysis. These checks cause the program to terminate early or alter execution flow if a debugger is detected. 

At its core, the program acts as a loader that extracts an embedded ELF payload from its own executable, maps it into memory with appropriate runtime permissions, and transfers execution to the payload’s entry point. Once executed, the unpacked payload becomes the primary runtime component of the malware.

Several debugger detection routines were identified throughout the loader. Each routine enforces an early exit or crash upon detection. To proceed in the analysis, these checks were bypassed by patching the corresponding assembly instructions in Ghidra. Conditional branches such as `JNE` and `JNZ` were modified to always continue execution, and in some cases instructions were replaced with `NOP`s. In total, four anti‑debugging checks were identified and patched out to successfully transfer execution to the payload.

Once the unpacked payload was executed, I placed a breakpoint at its entry point to observe runtime behavior. The payload wrote an additional executable to an anonymous in-memory file using a `memfd`, preventing the file from being directly visible on the filesystem.

To extract this file for analysis, I accessed the process’s open file descriptors via `/proc/[PID]/fd/`. The in‑memory file was accessible through file descriptor `3`, which I copied to disk for isolated analysis.
### Stage 2: The Payload
With the payload extracted, I identified it as an ELF shared object (`.so`) compiled from C++ source. Analysis in Ghidra showed that the unpacker invoked a function named `run`, which serves as the payload’s entry point with the signature `void run(void)`. While much of the payload retained useful debug symbols, the functions directly referenced by `run` had their symbols stripped.

Through iterative analysis of the `run` method and its supporting functions, I was able to recover its functional behavior. The reconstructed logic is shown below:
```cpp
void run() {
  uint8_t rc4_state[264];
  init_RC4_state((long)rc4_state, 0x10a147, 7);
  
  if (does_file_exist(rc4_state) &&
      does_envvar_exist(rc4_state) &&
      is_year_2024() &&
      is_running_as_root() &&
      no_hypervisor_flag_set(rc4_state) &&
      no_virtualization_detected(rc4_state)) {
    connect_to_server(rc4_state);
  }
}
```

To prevent string recovery during static analysis, the payload first initializes an RC4 state using a hardcoded key (`"skibidi"`) located at address `0x10a147`. RC4 is a stream cipher that generates a pseudorandom byte stream from an internal state, which is XORed with encrypted data to produce plaintext, allowing strings to be decrypted incrementally at runtime. The RC4 implementation is custom and does not rely on any external cryptographic libraries. As subsequent functions are invoked, the initialized `rc4_state` is passed as an argument and used to decrypt each string’s ciphertext at runtime, with the plaintext stored in temporary C++ `std::string` objects.

The payload then performs six environment checks:
1. `does_file_exist(rc4_state)`
	- Returns true if the file `/opt/dafin/intel/ops_brief_redteam.pdf` exists on the client
2. `does_envvar_exist(rc4_state)`
	- Returns true if the environment variable `DAFIN_SEC_PROFILE` exists on the client
3. `is_year_2024()`
	- Returns true if the current year is 2024
4. `is_running_as_root()`
	- Returns true if the payload is running under the permissions of the `root` user
5. `no_hypervisor_flag_set(rc4_state)`
	- Reads the file `/proc/cpuinfo` line by line
	- In Linux, `/proc/cpuinfo` is a virtual, read-only text file containing information about the device's CPU
	- Returns true if the `hypervisor` flag is not present in the file
	- Used as an evasion technique in virtual machines
6. `no_virtualization_detected(rc4_state))`
	- Executes the command `systemd-detect-virt 2>/dev/null` to check for a virtualized environment
	- Returns true if no virtualization was detected

If all six checks return true, the payload attempts to connect to a hardcoded remote server at IP address `203.0.113.42` and download an additional file to the local system.

In practice, several of these checks—such as the hardcoded year validation—are designed to fail under normal analysis conditions. Rather than removing the checks entirely, which would disrupt the RC4-based string decryption logic shared across these functions, execution was forced forward by patching the conditional branch instructions to ignore return values. This ensured that the RC4 state remained consistent and allowed execution to continue into the `connect_to_server(rc4_state)` function.

Because no live command-and-control infrastructure was available for the challenge, these network operations would otherwise block or terminate execution. To allow execution to continue, I used the debugger gdb to set breakpoints on network-related functions such as `connect`, `send`, and `recv`, manually advancing the instruction pointer past each call to safely bypass network communication without destabilizing the process.
## Result
After reaching the code responsible for creating an empty file, I used the `lsof` command against the debugged process to identify the file path. The file path `/tmp/.vNiSdyNp1qkgX5oO` was identified and submitted as the solution for Task 4.