---
title: "Introduction to Beacon Object Files: Internals and Weaponizing Your First BOF"
date: 2026-11-14 20:00:00 +0530
categories: ["MalDev"]
tags: ["bof", "beacon-object-files", "cobalt-strike", "windows-internals", "red-teaming"]
---

## The Pre-BOF Era in Red Teaming

Before the widespread adoption of Beacon Object Files (BOFs), red team engagements and advanced threat actors relied heavily on traditional execution methods to achieve post-exploitation objectives.

The standard operational procedure often involved spawning child processes, such as `cmd.exe` or `powershell.exe`, to run native commands or custom scripts. While effective, this approach generated substantial telemetry. Process creation events, command-line arguments, and PowerShell script block logging provided defenders with clear, easily analyzable traces of malicious activity.

When operators sought to avoid process spawning, they frequently turned to reflective DLL injection. This technique allowed for the execution of custom code entirely in memory without touching the disk. However, reflective loaders typically required allocating large, suspicious Read-Write-Execute memory regions and creating anomalous threads within the host process.

These high-footprint behaviors made traditional post-exploitation a prime target for Endpoint Detection and Response (EDR) systems. Red teams and threat actors were constantly forced to play a game of cat-and-mouse, attempting to obfuscate their payloads while defenders continuously refined their heuristics to catch these noisy, easily identifiable patterns.

## The Paradigm Shift Introduced by BOFs

The introduction of Beacon Object Files fundamentally altered this operational landscape. BOFs allowed operators to execute post-exploitation tasks directly within the existing Beacon agent process, entirely in memory, without spawning child processes or writing artifacts to disk.

By leveraging a lightweight, position-independent object file format, red teams could perform complex tasks with a fraction of the memory footprint and telemetry generation of traditional Portable Executable files. This paradigm shift moved the focus from running a standalone binary to executing a targeted, isolated function.

This evolution drastically reduced the observable attack surface. It forced defenders to look deeper into process memory, API call patterns, and thread behavior, rather than relying solely on process creation events. This marked a new era of in-memory post-exploitation that required a more sophisticated approach to detection engineering.

## Understanding BOFs and COFF Internals

To truly understand how a BOF operates, one must first understand the Common Object File Format (COFF). In Windows development, when a C or C++ source file is compiled, it is not immediately turned into a standalone executable. Instead, it is compiled into an object file using the COFF format.

A COFF file contains a header, section headers, and relocation tables. The section headers define areas such as the `.text` section for executable code, the `.data` section for initialized variables, and the `.bss` section for uninitialized data. The relocation tables tell the linker how to adjust memory addresses once the final memory layout is determined.

Normally, a linker combines these object files and resolves all dependencies to create a final Portable Executable (PE) binary. A Beacon Object File, however, is a specialized COFF object file designed to be loaded by a compatible COFF loader. The Beacon agent includes a built-in COFF loader that parses the BOF header, allocates the necessary memory, resolves relocations, and invokes the entry-point function, conventionally named `go`.

### PE vs COFF (BOF)

| Feature | Portable Executable (PE) | Common Object File Format (COFF / BOF) |
|---|---|---|
| Primary Purpose | Standalone executable or DLL | Intermediate compiled object file |
| Execution Method | Loaded by Windows OS Loader | Loaded by a compatible custom COFF loader |
| Dependencies | Resolved at link time or load time | Resolved by the loader at runtime |
| Disk Footprint | Contains executable headers, imports, resources, and other metadata | Contains object code, data, symbols, and relocations |
| Execution Context | Can run as a separate process or be loaded as a module | Can execute within an existing process context |
| Telemetry | May generate process creation and module-loading events | Does not inherently require a new process, but can still generate memory and behavioral telemetry |

## Windows APIs and Beacon Argument Parsing

Windows APIs are the fundamental building blocks for interacting with the operating system. Take, for example, the `CreateFile` API, which is used to create or open files, named pipes, or devices. In a standard C program, `CreateFile` is called with multiple explicit parameters, including the file path, desired access, share mode, security attributes, creation disposition, and flags.

A BOF cannot rely on the standard C runtime or conventional `argc` and `argv` argument passing, as it is not a standalone executable with a `main` function. Instead, arguments are packed by the operator on the team server into a contiguous binary buffer.

When the BOF is executed, its `go` function is invoked, receiving a pointer to this buffer and its total length. To parse this raw data, the BOF utilizes the Beacon Data Parser API.

It first calls `BeaconDataParse` to initialize a parser state. From there, it sequentially extracts the arguments using specific extraction functions.

For instance, to call `CreateFile`, the BOF would extract a string for the file path and an integer for the access mask from the parsed buffer, and then pass those resolved variables directly to the Windows API.

## BOF Data Types and Parser Operations

The seamless parsing of arguments relies on a strict agreement between the team server packing logic and the BOF unpacking logic. This is defined by specific BOF data types. When arguments are packed via scripting frameworks, they are serialized into the buffer in a predictable order.

The corresponding BOF operations use the Data Parser API to read them back in the exact same order. This ensures that the BOF can accurately reconstruct complex arguments from a raw byte stream without relying on standard C parsing mechanisms or null-terminated string assumptions.

### BOF Data Types

| Packed Data Type | Description | Beacon Parser Function |
|---|---|---|
| `z` | Null-terminated string (UTF-8) | `BeaconDataExtract` |
| `w` | Null-terminated wide string (UTF-16) | `BeaconDataExtract` |
| `i` | 4-byte signed integer | `BeaconDataInt` |
| `s` | 2-byte signed short integer | `BeaconDataShort` |
| `b` | Binary data with a 4-byte length prefix | `BeaconDataExtract` |
| `$` | Remaining unparsed data in the buffer | `BeaconDataPtr` |

## Getting the Hands Dirty: The Hello Beacon BOF

Creating a basic BOF is straightforward and serves as an excellent foundational exercise. Below is a minimal C program designed to print a simple message to the operator console. It includes the `beacon.h` header, which declares the necessary internal APIs, and defines the mandatory `go` function.

### Hello Beacon - C Source Code

```c
#include "beacon.h"

void go(char *args, int alen) {
    BeaconPrintf(CALLBACK_OUTPUT, "Hello Beacon\n");
}
```

### Compiling the BOF

To compile this into a COFF object file on a Kali Linux system, one must use a cross-compiler targeting Windows, such as MinGW-w64. The compilation command is structured to optimize for size and prevent the creation of a full executable.

```bash
x86_64-w64-mingw32-gcc -Os -c hello.c -o hello.o
```

The `-Os` flag optimizes the binary for size, while the `-c` flag ensures the compiler stops after the compilation stage, outputting an unlinked object file rather than a full Portable Executable.

The resulting `hello.o` file is a COFF object file. Its compatibility with a particular Beacon loader depends on the architecture, symbols, relocations, and Beacon API requirements.

### Integrating BOFs with Modern C2: AxScript and Adaptix

While compiling a BOF is the first step, executing it efficiently requires integration with a Command and Control framework. Adaptix is a highly modular, open-source post-exploitation and adversarial emulation framework designed for authorized penetration testing. To extend its capabilities, Adaptix utilizes AxScript, a built-in scripting language based on the Qt JavaScript engine.

AxScript is essential for Adaptix because it bridges the gap between high-level operator commands and low-level BOF execution. Instead of manually typing out long execution paths or architecture-specific file names, operators can use AxScript to create custom commands that automatically handle argument packing, architecture detection, and BOF routing. Here is an example of an AxScript designed to load and execute the Hello Beacon BOF we compiled earlier:

```axs
var metadata = {
    name: "HelloBOF",
    description: "Runs Hello Beacon BOF",
    store: true
};

var cmd_hello = ax.create_command("hello_bof", "Runs the Hello Beacon BOF", "hello_bof");

cmd_hello.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "hellobof." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "Task: Hello BOF");
});

var group_hello = ax.create_commands_group("HelloBOF", [cmd_hello]);
ax.register_commands_group(group_hello, ["beacon"], ["windows"], []);
```

The metadata object defines the script identity, providing a name and description that the Adaptix client uses to catalog and display the extension to the operator.
The ax.create_command function initializes a new command named hello_bof. This is the exact command the operator will type into the Adaptix console to trigger the action.

The setPreHook function is the core of the automation. Before the command is sent to the agent, this hook intercepts the execution. It dynamically constructs the correct file path by combining the script directory with the base name and the target agent architecture, retrieved via ax.arch(id). 

This ensures that if the agent is x64 or x86, the correct compiled object file is selected automatically. It then uses ax.execute_alias to silently translate the operator simple hello_bof command into the framework native execute bof command, appending the resolved file path.

Finally, the script groups the command using ax.create_commands_group and registers it specifically for beacon agents running on Windows platforms. This ensures the command only appears in the operator interface when it is contextually relevant and supported by the target environment.

### Execution

With the AxScript written and the BOF compiled, the final step is to integrate and execute the payload within the Adaptix environment. To begin this process, open the Adaptix Console and navigate to the Script Manager feature. This interface allows operators to dynamically load and manage custom extensions without restarting the framework. By importing the newly created AxScript file, the framework parses the metadata and registers the custom commands defined within the script.

![Script Manager](https://github.com/AthisSN/athissn.github.io/blob/main/assets/posts/introduction-to-beacon-object-files/Script-Manager.png)

Assuming a beacon session has already been established within your local lab environment, the next objective is to verify that the extension was loaded correctly. Within the Adaptix console, you can utilize the native help command to list all available commands for the active session. 

![BOF Confirmation](https://github.com/AthisSN/athissn.github.io/blob/main/assets/posts/introduction-to-beacon-object-files/Hello-BOF-Confirmation.png)

Scrolling through the output, you will see the hello_bof command listed alongside its description, confirming that the script was successfully parsed and the command is now available for execution.

With the command verified, you can now execute it by simply typing hello_bof into the console. The Adaptix client will intercept the command, trigger the pre-hook we defined earlier, dynamically resolve the correct architecture-specific object file, and pass the execution task to the beacon. If the compilation and scripting were performed correctly, the console will immediately display the output, successfully printing the Hello Beacon message directly from the agent process.

![Execution](https://github.com/AthisSN/athissn.github.io/blob/main/assets/posts/introduction-to-beacon-object-files/BOF-Execution-Successful.png)

This successful execution validates the entire pipeline, from writing the C code and compiling the COFF object file to scripting the automation layer and executing it in memory. While this serves as a highly simplistic and foundational example of a custom BOF, it demonstrates the core mechanics of in-memory execution. In the upcoming articles, we will deep dive into writing more complex and custom BOFs, exploring advanced situational awareness techniques, and detailing how to perform various offensive operations while maintaining a minimal footprint.

## Situational Awareness and the TrustedSec Repository

The true power of BOFs is realized in community-driven repositories that provide ready-to-use, lightweight capabilities. Situational awareness is the critical post-exploitation phase where an operator gathers information about the system, users, processes, and network to determine the next logical steps.

TrustedSec has been a pioneer in democratizing this capability through their open-source repositories. Their Situational Awareness BOF repository contains dozens of tools that replicate native command-line utilities, such as `whoami`, `tasklist`, `ipconfig`, `netstat`, `sc_enum`, and `ldapsearch`. Check out the [TrustedSec BOF Repository](https://github.com/trustedsec/CS-Situational-Awareness-BOF) for more information.

These tools execute through a COFF loader. This allows operators to gather rich telemetry about the environment, like enumerating filter drivers or querying Active Directory, without necessarily spawning a command shell or generating command-line logging associated with those utilities.

In the next article, we will build on this foundation and walk through writing our own custom situational awareness BOF from scratch, detailing the code, compilation, and execution process.

## Defensive Perspectives: Detection and Evasion Mechanics

From a defensive and educational perspective, understanding how BOFs are detected is crucial for building robust security controls. While BOFs avoid process creation telemetry, they are not entirely invisible. Modern EDRs may detect BOFs through memory scanning and behavioral analysis.

Defenders look for anomalous executable memory regions, such as Read-Write-Execute pages, or unusual call stacks that terminate in the BOF's `go` function rather than a legitimate, signed module. Additionally, security products may monitor for the specific memory allocation and modification patterns characteristic of a custom COFF loader.

To understand the theoretical bypasses discussed in advanced threat research, one must look at techniques like direct system calls. By invoking native NT APIs directly, operators may attempt to bypass user-mode EDR hooks placed in `ntdll.dll`. Other documented evasion methods include tampering with Event Tracing for Windows (ETW) or the Antimalware Scan Interface (AMSI) in memory to interfere with telemetry pipelines.

Furthermore, sophisticated BOF developers may avoid persistent RWX memory signatures by initially allocating memory as Read-Write, writing the payload, and then changing the permissions to Read-Execute before execution.

For defenders, mitigating these behaviors requires moving beyond simple signature-based detection. It demands the implementation of behavioral heuristics, such as:

- Monitoring unusual memory permission transitions.
- Validating the integrity of core system DLLs.
- Analyzing unusual API call sequences and call stacks.
- Correlating memory allocation, modification, and execution events.
- Monitoring suspicious behavior within otherwise legitimate processes.

Understanding these behaviors is essential for developing effective detection engineering strategies against modern in-memory execution techniques.

## Conclusion

Beacon Object Files represent an important evolution in post-exploitation tooling. By leveraging the COFF format and a custom loader, they provide a lightweight alternative to traditional standalone executables for extending the capabilities of an existing Beacon process.

Understanding their architecture, argument parsing mechanisms, compilation process, and defensive implications provides a strong foundation for further research into Windows internals and modern red team development.

In the next article, we will explore the development of a custom situational awareness BOF and examine its internal implementation.

## References

- [TrustedSec - Situational Awareness BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF)
- [Microsoft - PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Cobalt Strike Documentation](https://www.cobaltstrike.com/)
