import re
import subprocess
import sys

def check_installed_shellcode(filepath):
    print(f"Checking {filepath}...")
    with open(filepath, 'r') as f:
        content = f.read()
    
    match = re.search(r'shellcode:\s*((?:db\s+[0-9a-fA-Fx, ]+\s*)+)', content, re.MULTILINE | re.DOTALL)
    if not match:
        print("Could not find shellcode block")
        sys.exit(1)
    
    db_lines = re.findall(r'db\s+(.+)', match.group(1))
    
    bytes_list = []
    for line in db_lines:
        parts = line.split(',')
        for p in parts:
            p = p.strip()
            if p:
                bytes_list.append(int(p, 16))
    
    # Check byte at index 6
    byte6 = bytes_list[6]
    print(f"Byte at offset 6: {hex(byte6)}")
    
    if byte6 == 0xbb:
        print("SUCCESS: Byte is 0xBB (Correct)")
    elif byte6 == 0xc0:
        print("FAILURE: Byte is 0xC0 (Broken)")
    else:
        print(f"WARNING: Byte is unexpected: {hex(byte6)}")

    # Write to bin for disassembly
    with open('current_shellcode.bin', 'wb') as f:
        f.write(bytes(bytes_list))
        
    print("\nDisassembly of start:")
    try:
        res = subprocess.run(['ndisasm', '-b', '64', 'current_shellcode.bin'], capture_output=True, text=True)
        lines = res.stdout.splitlines()
        for i, line in enumerate(lines):
            if i < 5:
                print(line)
            if '000000C5' in line:
                print("...")
                print(line)
    except Exception as e:
        print(e)

if __name__ == '__main__':
    check_installed_shellcode('examples/windows_debug.asm')
