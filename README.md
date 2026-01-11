# 💂 Sentinel

A stealthy system introspection and process manipulation tool for Windows, written in Rust. This tool is designed for security research and penetration testing purposes, using direct system calls to avoid detection by security software.

> **Disclaimer**: This tool is for educational purposes and authorized security testing only. Use only on systems you own or have explicit permission to test.

## Features

- **Direct Syscall Execution**: Bypasses user-mode API hooks by using raw system calls
- **Process Enumeration**: List all running processes via `NtQuerySystemInformation`
- **Process Termination**: Kill processes using `NtTerminateProcess`
- **Memory Reading**: Read arbitrary memory from processes with `NtReadVirtualMemory`
- **Anti-Debugging**: Basic debugger detection via PEB check
- **Minimal Footprint**: Small binary size with no external dependencies
- **Stealth-Focused**: Designed to avoid detection by EDR/AV solutions

## Architecture

Shadow Sentinel uses a unique combination of technologies:

1. **Pure Rust Implementation**: No external C dependencies or Windows DLL imports
2. **Inline Assembly**: Direct syscall invocation via `asm!` macro
3. **Forth-like Interpreter**: Custom stack-based command interface
4. **String Hashing**: Command obfuscation to avoid string-based detection

## Building

### Prerequisites

- Rust 1.70+ (stable)
- Windows 10/11 x64 development environment
- Visual Studio Build Tools (for MSVC target)

### Compilation

```bash
# Clone the repository
git clone https://github.com/yourusername/shadow-sentinel.git
cd shadow-sentinel

# Build in release mode
cargo build --release --target x86_64-pc-windows-msvc

# For maximum stealth (minimal binary size)
RUSTFLAGS="-C target-cpu=native -C opt-level=z -C panic=abort" \
cargo build --release --target x86_64-pc-windows-msvc
```

The binary will be available at `target/x86_64-pc-windows-msvc/release/sentinel.exe`.

## Usage

### Interactive Mode

```bash
.\sentinel.exe
```

Example session:
```
[+] Shadow Sentinel v3.0
[+] Type HELP for commands
>> SCAN
[+] Deep system scan initiated
[+] Active processes:
PID      | Name
---------------------------------------------
0        | System Idle
4        | System
...
>> 1234 KILL
[+] Process 1234 terminated
>> 0x400000 5678 PEEK
[Mem @ 400000] -> 7FFE0300
>> .S
Stack (1): [140737475125504]
>> HELP
Commands:
  SCAN             - List all processes
  <pid> KILL       - Terminate process by PID
  <addr> <pid> PEEK - Read memory from process
  .S               - Show stack
  HELP             - Show this help
  EXIT             - Exit
```

### Available Commands

| Command | Description | Example |
|---------|-------------|---------|
| `SCAN` | List all running processes | `SCAN` |
| `KILL` | Terminate a process | `1234 KILL` |
| `PEEK` | Read process memory | `0x400000 1234 PEEK` |
| `.S` | Show current stack | `.S` |
| `HELP` | Display help message | `HELP` |
| `EXIT` | Exit the program | `EXIT` |

## Technical Details

### Syscalls Used

The tool directly invokes the following Windows system calls:

| Syscall | Number | Purpose |
|---------|--------|---------|
| `NtOpenProcess` | 0x26 | Open a process handle |
| `NtTerminateProcess` | 0x2C | Terminate a process |
| `NtReadVirtualMemory` | 0x3F | Read from process memory |
| `NtQuerySystemInformation` | 0x36 | Query system information |

### Anti-Detection Features

1. **Direct Syscalls**: Avoids `ntdll.dll` hooks used by EDR solutions
2. **No API Imports**: Zero import address table entries for suspicious functions
3. **String Obfuscation**: Commands are hashed at compile time
4. **Debugger Detection**: Checks PEB for debugger presence
5. **Minimal Binary**: Small size reduces heuristic detection

### Limitations

- Only supports Windows 10/11 x64
- Syscall numbers are version-specific
- Limited error handling for stability reasons
- No network functionality in current version

## Security Considerations

### For Defenders

- Monitor for direct syscall invocation patterns
- Look for processes with minimal import tables
- Consider the tool's hash for threat intelligence
- Be aware of the stack-based command interpreter pattern

### For Researchers

- This tool is for authorized testing only
- Understand local laws regarding security tools
- Use in isolated environments when learning
- Consider the ethical implications of your actions

## Development

### Project Structure

```
src/
├── main.rs          # Main entry point and VM implementation
├── syscalls.rs      # Syscall wrapper functions (inline assembly)
└── structures.rs    # Windows structure definitions
```

### Adding Features

To extend the tool:

1. Add new command to `hash_str` match statement
2. Implement the functionality using direct syscalls
3. Update the help text
4. Test thoroughly in controlled environment

### Testing

```bash
# Run in debug mode (with anti-debug disabled)
cargo run --target x86_64-pc-windows-msvc

# Test specific functionality
cargo test
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by various security research and red team tools
- Thanks to the Rust community for excellent systems programming support
- Security researchers who pioneer stealth techniques

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this software. Always ensure you have proper authorization before testing any system.

---

**Note**: This tool is part of ongoing security research. Behavior may change between versions, and compatibility is not guaranteed.
