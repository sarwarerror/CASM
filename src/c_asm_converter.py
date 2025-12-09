import re


class CAsmConverter:
    """
    Converts C files with NASM-style inline assembly to GCC inline assembly.
    
    Supports:
    - asm() blocks with NASM syntax
    - Direct assembly without wrapper
    - Variable mapping [var] syntax
    - Push/pop tracking
    - Local labels with loops
    - Complex array indexing [array + i * 8]
    - Auto-detection of x86_64 vs ARM64
    - Memory clobber detection
    - Function call handling with ABI support
    """
    
    # Class-level counter for unique asm block IDs
    _asm_block_counter = 0
    # Class-level registry for global labels
    _global_labels = {}
    
    def __init__(self, source, arch=None):
        self.source = source
        self.lines = source.split('\n')
        self.output_lines = []
        self.arch = arch  # Will be auto-detected if None
        
        # Reset global labels for each file conversion
        CAsmConverter._global_labels = {}
        CAsmConverter._asm_block_counter = 0
        
        # x86 Register mapping to sizes (for suffix determination)
        self.x86_registers = {
            # 64-bit
            'rax': 'q', 'rbx': 'q', 'rcx': 'q', 'rdx': 'q', 'rsi': 'q', 'rdi': 'q', 'rbp': 'q', 'rsp': 'q',
            'r8': 'q', 'r9': 'q', 'r10': 'q', 'r11': 'q', 'r12': 'q', 'r13': 'q', 'r14': 'q', 'r15': 'q',
            # 32-bit
            'eax': 'l', 'ebx': 'l', 'ecx': 'l', 'edx': 'l', 'esi': 'l', 'edi': 'l', 'ebp': 'l', 'esp': 'l',
            'r8d': 'l', 'r9d': 'l', 'r10d': 'l', 'r11d': 'l', 'r12d': 'l', 'r13d': 'l', 'r14d': 'l', 'r15d': 'l',
            # 16-bit
            'ax': 'w', 'bx': 'w', 'cx': 'w', 'dx': 'w', 'si': 'w', 'di': 'w', 'bp': 'w', 'sp': 'w',
            'r8w': 'w', 'r9w': 'w', 'r10w': 'w', 'r11w': 'w', 'r12w': 'w', 'r13w': 'w', 'r14w': 'w', 'r15w': 'w',
            # 8-bit
            'al': 'b', 'bl': 'b', 'cl': 'b', 'dl': 'b', 'ah': 'b', 'bh': 'b', 'ch': 'b', 'dh': 'b',
            'sil': 'b', 'dil': 'b', 'bpl': 'b', 'spl': 'b',
            'r8b': 'b', 'r9b': 'b', 'r10b': 'b', 'r11b': 'b', 'r12b': 'b', 'r13b': 'b', 'r14b': 'b', 'r15b': 'b',
            # Segment registers
            'cs': 'w', 'ds': 'w', 'es': 'w', 'fs': 'w', 'gs': 'w', 'ss': 'w',
            # SIMD registers
            'xmm0': 'x', 'xmm1': 'x', 'xmm2': 'x', 'xmm3': 'x', 'xmm4': 'x', 'xmm5': 'x', 'xmm6': 'x', 'xmm7': 'x',
            'xmm8': 'x', 'xmm9': 'x', 'xmm10': 'x', 'xmm11': 'x', 'xmm12': 'x', 'xmm13': 'x', 'xmm14': 'x', 'xmm15': 'x',
            'ymm0': 'y', 'ymm1': 'y', 'ymm2': 'y', 'ymm3': 'y', 'ymm4': 'y', 'ymm5': 'y', 'ymm6': 'y', 'ymm7': 'y',
            'ymm8': 'y', 'ymm9': 'y', 'ymm10': 'y', 'ymm11': 'y', 'ymm12': 'y', 'ymm13': 'y', 'ymm14': 'y', 'ymm15': 'y',
        }
        
        # ARM64 register mapping
        self.arm64_registers = {
            # General purpose (64-bit)
            'x0': '', 'x1': '', 'x2': '', 'x3': '', 'x4': '', 'x5': '', 'x6': '', 'x7': '',
            'x8': '', 'x9': '', 'x10': '', 'x11': '', 'x12': '', 'x13': '', 'x14': '', 'x15': '',
            'x16': '', 'x17': '', 'x18': '', 'x19': '', 'x20': '', 'x21': '', 'x22': '', 'x23': '',
            'x24': '', 'x25': '', 'x26': '', 'x27': '', 'x28': '', 'x29': '', 'x30': '', 'sp': '', 'xzr': '',
            # General purpose (32-bit)
            'w0': '', 'w1': '', 'w2': '', 'w3': '', 'w4': '', 'w5': '', 'w6': '', 'w7': '',
            'w8': '', 'w9': '', 'w10': '', 'w11': '', 'w12': '', 'w13': '', 'w14': '', 'w15': '',
            'w16': '', 'w17': '', 'w18': '', 'w19': '', 'w20': '', 'w21': '', 'w22': '', 'w23': '',
            'w24': '', 'w25': '', 'w26': '', 'w27': '', 'w28': '', 'w29': '', 'w30': '', 'wzr': '',
            # SIMD/FP registers
            'v0': '', 'v1': '', 'v2': '', 'v3': '', 'v4': '', 'v5': '', 'v6': '', 'v7': '',
            'd0': '', 'd1': '', 'd2': '', 'd3': '', 'd4': '', 'd5': '', 'd6': '', 'd7': '',
            's0': '', 's1': '', 's2': '', 's3': '', 's4': '', 's5': '', 's6': '', 's7': '',
        }

        # Instructions that write to the first operand (dest)
        self.write_ops = {
            'mov', 'add', 'sub', 'imul', 'idiv', 'inc', 'dec', 'neg', 'not', 
            'and', 'or', 'xor', 'shl', 'shr', 'sar', 'sal', 'rol', 'ror', 'lea', 'pop',
            'adc', 'sbb', 'movsx', 'movzx', 'movsxd', 'xchg', 'cmpxchg', 'xadd',
            'movaps', 'movups', 'movdqa', 'movdqu', 'movss', 'movsd',
            'addps', 'addpd', 'addss', 'addsd', 'subps', 'subpd', 'subss', 'subsd',
            'mulps', 'mulpd', 'mulss', 'mulsd', 'divps', 'divpd', 'divss', 'divsd',
            'xorps', 'xorpd', 'andps', 'andpd', 'orps', 'orpd',
            'sete', 'setne', 'setg', 'setge', 'setl', 'setle', 'seta', 'setae', 'setb', 'setbe',
            'setz', 'setnz', 'sets', 'setns', 'seto', 'setno', 'setp', 'setnp',
            'cmove', 'cmovne', 'cmovg', 'cmovge', 'cmovl', 'cmovle', 'cmova', 'cmovae', 'cmovb', 'cmovbe',
            'cmovz', 'cmovnz', 'cmovs', 'cmovns',
            'bswap', 'popcnt', 'lzcnt', 'tzcnt', 'bsf', 'bsr',
        }
        
        # Instructions that read-modify-write the first operand
        self.rmw_ops = {
            'add', 'sub', 'imul', 'inc', 'dec', 'neg', 'not', 
            'and', 'or', 'xor', 'shl', 'shr', 'sar', 'sal', 'rol', 'ror',
            'adc', 'sbb', 'xchg', 'cmpxchg', 'xadd',
            'addps', 'addpd', 'addss', 'addsd', 'subps', 'subpd', 'subss', 'subsd',
            'mulps', 'mulpd', 'mulss', 'mulsd', 'divps', 'divpd', 'divss', 'divsd',
        }
        
        # Instructions that only read
        self.read_ops = {
            'cmp', 'test', 'push', 'call', 'jmp',
            'je', 'jne', 'jg', 'jge', 'jl', 'jle', 'ja', 'jae', 'jb', 'jbe', 'jz', 'jnz',
            'jo', 'jno', 'js', 'jns', 'jp', 'jnp',
            'loop', 'loope', 'loopne',
            'ret', 'leave', 'nop', 'hlt', 'syscall', 'int',
        }
        
        # ARM64 mnemonics
        self.arm64_write_ops = {
            'mov', 'movz', 'movn', 'movk', 'add', 'sub', 'mul', 'sdiv', 'udiv',
            'and', 'orr', 'eor', 'lsl', 'lsr', 'asr', 'ror',
            'ldr', 'ldp', 'ldrb', 'ldrh', 'ldrsb', 'ldrsh', 'ldrsw',
            'adc', 'sbc', 'neg', 'mvn', 'bic', 'orn',
            'madd', 'msub', 'smull', 'umull',
            'csel', 'csinc', 'csinv', 'csneg', 'cset', 'csetm',
            'fmov', 'fadd', 'fsub', 'fmul', 'fdiv', 'fneg', 'fabs', 'fsqrt',
        }
        
        self.arm64_read_ops = {
            'cmp', 'cmn', 'tst', 'str', 'stp', 'strb', 'strh',
            'b', 'bl', 'br', 'blr', 'ret',
            'cbz', 'cbnz', 'tbz', 'tbnz',
            'b.eq', 'b.ne', 'b.lt', 'b.le', 'b.gt', 'b.ge', 'b.lo', 'b.hi', 'b.ls', 'b.hs',
            'svc', 'nop',
        }

        # Combined register set for backward compatibility
        self.registers = self.x86_registers

    def detect_arch(self, asm_lines):
        """Auto-detect architecture from assembly code."""
        x86_count = 0
        arm64_count = 0
        
        for line in asm_lines:
            stripped = line.strip().lower()
            if not stripped or stripped.startswith(';') or stripped.startswith('//'):
                continue
            
            # Check for x86 registers
            for reg in self.x86_registers:
                if re.search(rf'\b{reg}\b', stripped):
                    x86_count += 1
                    break
            
            # Check for ARM64 registers
            for reg in self.arm64_registers:
                if re.search(rf'\b{reg}\b', stripped):
                    arm64_count += 1
                    break
        
        if arm64_count > x86_count:
            return 'arm64'
        if x86_count > 0:
            return 'x86_64'
        return None
    
    def get_block_arch(self, asm_lines):
        """Determine architecture for a block, preferring auto-detection."""
        detected = self.detect_arch(asm_lines)
        if detected:
            return detected
        return self.arch or 'x86_64'

    def convert(self):
        """Main conversion entry point."""
        self.detected_archs = set()
        
        i = 0
        while i < len(self.lines):
            line = self.lines[i]
            stripped = line.strip()
            
            # Check for asm( block start
            asm_match = re.match(r'^(\s*)(asm|__asm__|__asm)\s*(volatile\s*)?\(\s*$', stripped, re.IGNORECASE)
            if asm_match:
                indent = self.get_indent(line)
                asm_lines = []
                i += 1
                while i < len(self.lines):
                    asm_line = self.lines[i]
                    if asm_line.strip() == ')' or asm_line.strip().startswith(')'):
                        i += 1
                        break
                    asm_lines.append(asm_line)
                    i += 1
                
                # Collect any printr(register) calls that follow this asm block
                printf_registers = []
                while i < len(self.lines):
                    next_line = self.lines[i]
                    next_stripped = next_line.strip()
                    # Check for printr(register) pattern
                    printf_match = re.match(r'^printr\s*\(\s*([a-zA-Z][a-zA-Z0-9]*)\s*\)\s*;?\s*$', next_stripped)
                    if printf_match:
                        reg = printf_match.group(1).lower()
                        if reg in self.x86_registers or reg in self.arm64_registers:
                            printf_registers.append((reg, self.get_indent(next_line)))
                            i += 1
                            continue
                    # Skip empty lines between asm block and printf
                    if not next_stripped:
                        i += 1
                        continue
                    break
                
                block_arch = self.get_block_arch(asm_lines)
                self.detected_archs.add(block_arch)
                
                if block_arch == 'arm64':
                    converted = self.convert_arm64_asm_block(asm_lines, indent, printf_registers)
                else:
                    converted = self.convert_asm_block(asm_lines, indent, printf_registers)
                self.output_lines.append(converted)
            # Check for direct assembly lines
            elif self.is_assembly_line(stripped):
                indent = self.get_indent(line)
                asm_lines = [line]
                i += 1
                while i < len(self.lines):
                    next_line = self.lines[i]
                    next_stripped = next_line.strip()
                    if self.is_assembly_line(next_stripped):
                        asm_lines.append(next_line)
                        i += 1
                    elif not next_stripped:
                        j = i + 1
                        while j < len(self.lines) and not self.lines[j].strip():
                            j += 1
                        if j < len(self.lines) and self.is_assembly_line(self.lines[j].strip()):
                            asm_lines.append(next_line)
                            i += 1
                        else:
                            break
                    else:
                        break
                
                # Collect any printr(register) calls that follow this asm block
                printf_registers = []
                while i < len(self.lines):
                    next_line = self.lines[i]
                    next_stripped = next_line.strip()
                    # Check for printr(register) pattern
                    printf_match = re.match(r'^printr\s*\(\s*([a-zA-Z][a-zA-Z0-9]*)\s*\)\s*;?\s*$', next_stripped)
                    if printf_match:
                        reg = printf_match.group(1).lower()
                        if reg in self.x86_registers or reg in self.arm64_registers:
                            printf_registers.append((reg, self.get_indent(next_line)))
                            i += 1
                            continue
                    # Skip empty lines
                    if not next_stripped:
                        i += 1
                        continue
                    break
                
                block_arch = self.get_block_arch(asm_lines)
                self.detected_archs.add(block_arch)
                
                if block_arch == 'arm64':
                    converted = self.convert_arm64_asm_block(asm_lines, indent, printf_registers)
                else:
                    converted = self.convert_asm_block(asm_lines, indent, printf_registers)
                self.output_lines.append(converted)
            else:
                # Check for standalone printr(register) pattern (not following asm block)
                converted_line = self.convert_printr_register(line)
                self.output_lines.append(converted_line)
                i += 1
        
        # Add architecture metadata
        arch_list = ','.join(sorted(self.detected_archs)) if self.detected_archs else 'none'
        result = f'// CASM_ARCH: {arch_list}\n' + '\n'.join(self.output_lines)
        return result

    def is_assembly_line(self, stripped):
        """Check if a line is a direct assembly instruction."""
        if not stripped:
            return False
        if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
            return False
        if stripped.startswith('#'):
            return False
        if stripped.endswith(';') and not stripped.endswith('\\n\\t";'):
            return False
        if '{' in stripped or '}' in stripped:
            return False
        # Skip if there's an unbalanced parenthesis (C statement)
        if '(' in stripped:
            if stripped.count('(') != stripped.count(')'):
                return False
            # Also skip function calls and variable declarations with init
            if not re.match(r'^\w+\s+\w+,', stripped):
                return False
        if stripped.startswith('return ') or stripped.startswith('if ') or stripped.startswith('else'):
            return False
        if stripped.startswith('for ') or stripped.startswith('while ') or stripped.startswith('switch '):
            return False
        # Skip C variable declarations
        c_types = {'int', 'char', 'short', 'long', 'float', 'double', 'void', 'unsigned', 'signed', 
                   'const', 'static', 'auto', 'register', 'volatile', 'extern', 'size_t', 'ssize_t',
                   'int8_t', 'int16_t', 'int32_t', 'int64_t', 'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t'}
        parts = stripped.split()
        if parts and parts[0] in c_types:
            return False
        
        # Check for labels
        if re.match(r'^[a-zA-Z_]\w*:$', stripped) and not stripped.startswith('case ') and stripped != 'default:':
            return True
        
        # Get first word and check against known mnemonics
        parts = stripped.split()
        if not parts:
            return False
        first_word = parts[0].lower()
        
        all_mnemonics = set()
        all_mnemonics.update(self.write_ops)
        all_mnemonics.update(self.rmw_ops)
        all_mnemonics.update(self.read_ops)
        all_mnemonics.update(self.arm64_write_ops)
        all_mnemonics.update(self.arm64_read_ops)
        all_mnemonics.update({
            'mov', 'add', 'sub', 'mul', 'div', 'and', 'or', 'xor', 'not', 'neg',
            'push', 'pop', 'call', 'ret', 'jmp', 'je', 'jne', 'jg', 'jl', 'jge', 'jle',
            'cmp', 'test', 'lea', 'nop', 'inc', 'dec', 'shl', 'shr', 'sar', 'sal',
            'imul', 'idiv', 'movzx', 'movsx', 'movsxd', 'xchg', 'bswap',
            'ldr', 'str', 'ldp', 'stp', 'lsl', 'lsr', 'asr', 'ror',
            'csel', 'csinc', 'cbz', 'cbnz', 'bl', 'br', 'blr', 'svc',
            'syscall', 'int', 'hlt', 'leave', 'enter',
        })
        
        return first_word in all_mnemonics

    def get_indent(self, line):
        """Extract leading whitespace from a line."""
        match = re.match(r'^(\s*)', line)
        return match.group(1) if match else ''

    def convert_printr_register(self, line):
        """
        Convert printr(register) to proper printf with format string.
        
        Supports:
        - printr(rax)  -> prints 64-bit integer
        - printr(eax)  -> prints 32-bit integer  
        - printr(al)   -> prints 8-bit as char
        - printr(x0)   -> prints ARM64 register
        """
        stripped = line.strip()
        indent = self.get_indent(line)
        
        # Match printr(register) pattern - with or without semicolon
        match = re.match(r'^printr\s*\(\s*([a-zA-Z][a-zA-Z0-9]*)\s*\)\s*;?\s*$', stripped)
        if not match:
            return line
        
        reg = match.group(1).lower()
        
        # Check if it's an x86 register
        if reg in self.x86_registers:
            size = self.x86_registers[reg]
            self.detected_archs.add('x86_64')
            
            if size == 'b':
                # 8-bit register - print as character
                # Need to read register value into a variable first
                return f'''{indent}{{
{indent}    unsigned char __reg_val__;
{indent}    __asm__ volatile("movb %%{reg}, %0" : "=r" (__reg_val__));
{indent}    printf("%c", __reg_val__);
{indent}}}'''
            elif size == 'w':
                # 16-bit register
                return f'''{indent}{{
{indent}    unsigned short __reg_val__;
{indent}    __asm__ volatile("movw %%{reg}, %0" : "=r" (__reg_val__));
{indent}    printf("%d", __reg_val__);
{indent}}}'''
            elif size == 'l':
                # 32-bit register
                return f'''{indent}{{
{indent}    unsigned int __reg_val__;
{indent}    __asm__ volatile("movl %%e{reg[-2:]}, %0" : "=r" (__reg_val__) : : );
{indent}    printf("%d", __reg_val__);
{indent}}}'''
            elif size == 'q':
                # 64-bit register
                return f'''{indent}{{
{indent}    unsigned long long __reg_val__;
{indent}    __asm__ volatile("movq %%{reg}, %0" : "=r" (__reg_val__));
{indent}    printf("%lld", __reg_val__);
{indent}}}'''
            else:
                # SIMD registers - print as hex
                return f'{indent}printf("(SIMD register {reg})");'
        
        # Check if it's an ARM64 register
        elif reg in self.arm64_registers:
            self.detected_archs.add('arm64')
            
            if reg.startswith('x') or reg == 'sp':
                # 64-bit ARM register
                return f'''{indent}{{
{indent}    unsigned long long __reg_val__;
{indent}    __asm__ volatile("mov %0, {reg}" : "=r" (__reg_val__));
{indent}    printf("%lld", __reg_val__);
{indent}}}'''
            elif reg.startswith('w'):
                # 32-bit ARM register
                return f'''{indent}{{
{indent}    unsigned int __reg_val__;
{indent}    __asm__ volatile("mov %w0, {reg}" : "=r" (__reg_val__));
{indent}    printf("%d", __reg_val__);
{indent}}}'''
            else:
                return f'{indent}printf("(ARM register {reg})");'
        
        # Not a register, return line unchanged
        return line

    def convert_asm_block(self, lines, indent, printf_registers=None):
        """Convert a block of NASM-style assembly to GCC inline assembly."""
        if printf_registers is None:
            printf_registers = []
        
        block_id = CAsmConverter._asm_block_counter
        CAsmConverter._asm_block_counter += 1
        
        variables = {}
        clobbers = set()
        converted_lines = []
        has_memory_write = False
        push_count = 0
        has_call = False
        local_labels = set()
        global_labels = {}
        
        # First pass: collect labels
        for line in lines:
            stripped = line.strip()
            if stripped.endswith(':') and not stripped.startswith('case '):
                label_part = stripped[:-1]
                if '@global' in label_part:
                    label_name = label_part.replace('@global', '').strip()
                    unique_name = f'.L_casm_global_{label_name}'
                    global_labels[label_name] = unique_name
                    CAsmConverter._global_labels[label_name] = unique_name
                elif label_part.startswith('global_'):
                    unique_name = f'.L_casm_{label_part}'
                    global_labels[label_part] = unique_name
                    CAsmConverter._global_labels[label_part] = unique_name
                else:
                    local_labels.add(label_part)
        
        for line in lines:
            stripped = line.strip()
            
            if not stripped or stripped.startswith(';') or stripped.startswith('//'):
                continue
            
            # Handle inline comments
            if ';' in stripped:
                parts = stripped.split(';', 1)
                stripped = parts[0].strip()
            
            if not stripped:
                continue
            
            # Handle labels
            if stripped.endswith(':') and not stripped.startswith('case '):
                label_part = stripped[:-1]
                if '@global' in label_part:
                    label_name = label_part.replace('@global', '').strip()
                    unique_name = global_labels.get(label_name, f'.L_casm_global_{label_name}')
                    converted_lines.append(f'"{unique_name}:\\n\\t"')
                elif label_part.startswith('global_'):
                    unique_name = global_labels.get(label_part, f'.L_casm_{label_part}')
                    converted_lines.append(f'"{unique_name}:\\n\\t"')
                else:
                    converted_lines.append(f'".L_casm_{label_part}_%=:\\n\\t"')
                continue
            
            # Parse instruction
            parts = stripped.split(None, 1)
            if not parts:
                continue
                
            mnemonic = parts[0].lower()
            operands_str = parts[1] if len(parts) > 1 else ""
            operands = self.parse_operands(operands_str)
            
            # Track push/pop
            if mnemonic == 'push':
                push_count += 1
            elif mnemonic == 'pop':
                push_count -= 1
            
            # Track function calls
            if mnemonic == 'call':
                has_call = True
                clobbers.update(['rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11'])
                has_memory_write = True
            
            # Check for memory writes
            if operands and mnemonic in self.write_ops:
                dest = operands[0]
                if dest.startswith('[') and dest.endswith(']'):
                    has_memory_write = True
            
            # Determine instruction suffix
            suffix = self.determine_suffix(mnemonic, operands)
            
            # Track variables and clobbers
            self.analyze_operands(mnemonic, operands, variables, clobbers)
            
            # Special handling for LEA with simple variable
            # lea rbx, [buffer] -> need to load address into register
            if mnemonic == 'lea' and len(operands) == 2:
                dest_reg = operands[0].lower()
                src = operands[1]
                # Check for [variable] pattern (simple variable reference)
                var_match = re.match(r'^\[([a-zA-Z_][a-zA-Z0-9_]*)\]$', src)
                if var_match:
                    var_name = var_match.group(1)
                    if var_name.lower() not in self.x86_registers:
                        # This is lea reg, [variable] - convert to mov reg, address
                        # In GCC inline asm, we use leaq with RIP-relative or direct address
                        clobbers.add(self.normalize_register(dest_reg))
                        # Use leaq with the variable name directly (GCC will handle it)
                        asm_instr = f'"leaq {var_name}(%%rip), %%{dest_reg}\\n\\t"'
                        converted_lines.append(asm_instr)
                        continue
            
            # Convert operands to AT&T format
            att_operands = []
            for op in operands:
                att_op = self.convert_operand(op, mnemonic)
                # Update jump targets
                if mnemonic in {'jmp', 'je', 'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle',
                               'ja', 'jae', 'jb', 'jbe', 'jo', 'jno', 'js', 'jns', 'jp', 'jnp',
                               'loop', 'loope', 'loopne', 'loopz', 'loopnz', 'call'}:
                    if op in local_labels:
                        att_op = f'.L_casm_{op}_%='
                    elif op in global_labels:
                        att_op = global_labels[op]
                    elif op in CAsmConverter._global_labels:
                        att_op = CAsmConverter._global_labels[op]
                att_operands.append(att_op)
            
            # Reverse operand order for AT&T (except for single-operand instructions)
            if len(att_operands) == 2 and mnemonic not in {'push', 'pop', 'call', 'jmp'}:
                att_operands.reverse()
            elif len(att_operands) == 3:
                # Three-operand: dest, src, imm -> imm, src, dest
                att_operands = [att_operands[2], att_operands[1], att_operands[0]]
            
            # Build the instruction string
            # Handle movsxd -> movslq conversion (AT&T name)
            if mnemonic == 'movsxd':
                att_mnemonic = 'movslq'
            else:
                att_mnemonic = mnemonic + suffix
            if att_operands:
                asm_instr = f'"{att_mnemonic} {", ".join(att_operands)}\\n\\t"'
            else:
                asm_instr = f'"{att_mnemonic}\\n\\t"'
            
            converted_lines.append(asm_instr)
        
        # Add stack alignment for calls if needed
        if has_call and push_count != 0:
            converted_lines.insert(0, '"subq $8, %%rsp\\n\\t"')
            converted_lines.append('"addq $8, %%rsp\\n\\t"')
        
        # Add memory clobber
        if has_memory_write:
            clobbers.add('memory')
        
        # Handle printf(register) - prepare output constraints for register extraction
        # We add these outputs FIRST, then build_constraints will account for them
        printf_var_names = []
        printf_outputs = []
        if printf_registers:
            for reg_name, _ in printf_registers:
                var_name = f'__casm_reg_{reg_name}__'
                printf_var_names.append((reg_name, var_name))
                printf_outputs.append(f'"=r" ({var_name})')
                # Don't clobber this register since we're reading it
                norm_reg = self.normalize_register(reg_name)
                clobbers.discard(norm_reg)
        
        # Build constraint lists - with offset to account for printf outputs
        outputs, inputs, var_to_index = self.build_constraints(variables, len(printf_outputs))
        
        # Add printf output mov instructions using indices after regular outputs
        printf_output_start_idx = len(printf_outputs) + len(outputs)
        for i, (reg_name, var_name) in enumerate(printf_var_names):
            norm_reg = self.normalize_register(reg_name)
            # Printf outputs are at indices 0..len(printf_outputs)-1
            output_idx = i
            converted_lines.append(f'"movq %%{norm_reg}, %{output_idx}\\n\\t"')
        
        # Prepend printf outputs to the outputs list
        final_outputs = printf_outputs + outputs
        
        # Replace variable placeholders
        final_lines = []
        for line in converted_lines:
            for var_name, idx in var_to_index.items():
                line = re.sub(f'__VAR_{re.escape(var_name)}__', f'%{idx}', line)
            final_lines.append(line)
        
        # Build final __asm__ block
        # First, declare any printf register variables
        result = ''
        if printf_var_names:
            for _, var_name in printf_var_names:
                result += f'{indent}unsigned long long {var_name};\n'
        
        result += f'{indent}__asm__ volatile(\n'
        result += f'{indent}    ' + f'\n{indent}    '.join(final_lines)
        
        if final_outputs or inputs:
            result += f'\n{indent}    : ' + ', '.join(final_outputs)
            result += f'\n{indent}    : ' + ', '.join(inputs)
        else:
            result += f'\n{indent}    : '
            result += f'\n{indent}    : '
        
        if clobbers:
            clobber_list = [f'"{c}"' for c in sorted(clobbers)]
            result += f'\n{indent}    : ' + ', '.join(clobber_list)
        
        result += f'\n{indent});'
        
        # Add printf statements for each register
        if printf_var_names:
            for reg_name, var_name in printf_var_names:
                result += f'\n{indent}printf("%lld", (long long){var_name});'
        
        return result

    def parse_operands(self, operands_str):
        """Parse comma-separated operands, respecting brackets."""
        if not operands_str:
            return []
        
        operands = []
        current = ""
        depth = 0
        
        for char in operands_str:
            if char == '[':
                depth += 1
                current += char
            elif char == ']':
                depth -= 1
                current += char
            elif char == ',' and depth == 0:
                operands.append(current.strip())
                current = ""
            else:
                current += char
        
        if current.strip():
            operands.append(current.strip())
        
        return operands

    def determine_suffix(self, mnemonic, operands):
        """Determine the AT&T instruction suffix."""
        no_suffix_ops = {
            'jmp', 'je', 'jne', 'jg', 'jge', 'jl', 'jle', 'ja', 'jae', 'jb', 'jbe',
            'jz', 'jnz', 'jo', 'jno', 'js', 'jns', 'jp', 'jnp',
            'call', 'ret', 'leave', 'nop', 'hlt', 'syscall', 'int',
            'loop', 'loope', 'loopne', 'push', 'pop',
            'movsxd', 'movsx', 'movzx',  # These have implicit sizing
            'lea', 'leaq',  # LEA uses destination register size
        }
        
        if mnemonic in no_suffix_ops:
            return ''
        
        # Check for explicit size
        for op in operands:
            op_lower = op.lower()
            if 'byte' in op_lower:
                return 'b'
            elif 'word' in op_lower and 'dword' not in op_lower and 'qword' not in op_lower:
                return 'w'
            elif 'dword' in op_lower:
                return 'l'
            elif 'qword' in op_lower:
                return 'q'
        
        # Check operands for register sizes
        for op in operands:
            clean_op = re.sub(r'\b(byte|word|dword|qword)\s+(ptr\s+)?', '', op, flags=re.IGNORECASE).strip()
            reg = clean_op.lower()
            if reg in self.x86_registers:
                return self.x86_registers[reg]
        
        return 'q'

    def analyze_operands(self, mnemonic, operands, variables, clobbers):
        """Analyze operands to track variable usage and register clobbers."""
        if operands:
            dest = operands[0]
            is_write = mnemonic in self.write_ops
            is_read = mnemonic in self.rmw_ops
            self.track_operand(dest, is_read, is_write, variables, clobbers)
        
        if len(operands) > 1:
            src = operands[1]
            self.track_operand(src, True, False, variables, clobbers)

    def track_operand(self, op, is_read, is_write, variables, clobbers):
        """Track an operand for variable references and register clobbers."""
        op = re.sub(r'\b(byte|word|dword|qword)\s+(ptr\s+)?', '', op, flags=re.IGNORECASE).strip()
        
        # Check for [var] pattern
        var_match = re.match(r'^\[([a-zA-Z_][a-zA-Z0-9_]*)\]$', op)
        if var_match:
            var_name = var_match.group(1)
            if var_name.lower() not in self.x86_registers:
                self.track_variable(var_name, is_read, is_write, variables)
            return
        
        # Check for memory operands with complex addressing
        if '[' in op and ']' in op:
            match = re.search(r'\[(.*?)\]', op)
            if match:
                content = match.group(1)
                parts = re.split(r'([+\-])', content)
                parts = [p.strip() for p in parts if p.strip()]
                
                first_token = True
                for part in parts:
                    if part in '+-':
                        continue
                    
                    scale_match = re.match(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\*\s*\d+', part)
                    if scale_match:
                        token = scale_match.group(1)
                        if token.lower() not in self.x86_registers:
                            self.track_variable(token, True, False, variables, is_array_index=True)
                        continue
                    
                    scale_match2 = re.match(r'\d+\s*\*\s*([a-zA-Z_][a-zA-Z0-9_]*)', part)
                    if scale_match2:
                        token = scale_match2.group(1)
                        if token.lower() not in self.x86_registers:
                            self.track_variable(token, True, False, variables, is_array_index=True)
                        continue
                    
                    if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', part):
                        if part.lower() not in self.x86_registers:
                            if first_token:
                                self.track_variable(part, True, False, variables, is_array_base=True)
                            else:
                                self.track_variable(part, True, False, variables, is_array_index=True)
                    
                    first_token = False
            return
        
        # Check for register
        reg = op.lower()
        if reg in self.x86_registers:
            if is_write:
                clobbers.add(self.normalize_register(reg))
            return
        
        # Check for bare identifier (C variable without brackets)
        if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', op):
            self.track_variable(op, is_read, is_write, variables)

    def track_variable(self, name, is_read, is_write, variables, is_array_base=False, is_array_index=False):
        """Track a C variable for constraint generation."""
        if name not in variables:
            variables[name] = {
                'index': len(variables), 
                'read': False, 
                'write': False,
                'is_array_base': False,
                'is_array_index': False
            }
        
        if is_read:
            variables[name]['read'] = True
        if is_write:
            variables[name]['write'] = True
        if is_array_base:
            variables[name]['is_array_base'] = True
        if is_array_index:
            variables[name]['is_array_index'] = True

    def normalize_register(self, reg):
        """Normalize register to its 64-bit parent."""
        reg = reg.lower()
        mapping = {
            'eax': 'rax', 'ax': 'rax', 'al': 'rax', 'ah': 'rax',
            'ebx': 'rbx', 'bx': 'rbx', 'bl': 'rbx', 'bh': 'rbx',
            'ecx': 'rcx', 'cx': 'rcx', 'cl': 'rcx', 'ch': 'rcx',
            'edx': 'rdx', 'dx': 'rdx', 'dl': 'rdx', 'dh': 'rdx',
            'esi': 'rsi', 'si': 'rsi', 'sil': 'rsi',
            'edi': 'rdi', 'di': 'rdi', 'dil': 'rdi',
            'ebp': 'rbp', 'bp': 'rbp', 'bpl': 'rbp',
            'esp': 'rsp', 'sp': 'rsp', 'spl': 'rsp',
            'r8d': 'r8', 'r8w': 'r8', 'r8b': 'r8',
            'r9d': 'r9', 'r9w': 'r9', 'r9b': 'r9',
            'r10d': 'r10', 'r10w': 'r10', 'r10b': 'r10',
            'r11d': 'r11', 'r11w': 'r11', 'r11b': 'r11',
            'r12d': 'r12', 'r12w': 'r12', 'r12b': 'r12',
            'r13d': 'r13', 'r13w': 'r13', 'r13b': 'r13',
            'r14d': 'r14', 'r14w': 'r14', 'r14b': 'r14',
            'r15d': 'r15', 'r15w': 'r15', 'r15b': 'r15',
        }
        return mapping.get(reg, reg)

    def convert_operand(self, op, mnemonic):
        """Convert a NASM operand to AT&T format."""
        op = re.sub(r'\b(byte|word|dword|qword)\s+(ptr\s+)?', '', op, flags=re.IGNORECASE).strip()
        
        # Handle [var] - C variable
        var_match = re.match(r'^\[([a-zA-Z_][a-zA-Z0-9_]*)\]$', op)
        if var_match:
            var_name = var_match.group(1)
            if var_name.lower() not in self.x86_registers:
                return f'__VAR_{var_name}__'
            else:
                return f'(%%{var_name.lower()})'
        
        # Handle complex memory operands
        if '[' in op and ']' in op:
            return self.convert_memory_operand(op)
        
        # Handle registers
        reg = op.lower()
        if reg in self.x86_registers:
            return f'%%{reg}'
        
        # Handle immediates
        if op.startswith('0x') or op.startswith('0X'):
            return f'${op}'
        if op.isdigit() or (op.startswith('-') and op[1:].isdigit()):
            return f'${op}'
        
        # Handle labels (for jumps/calls)
        if mnemonic in {'jmp', 'je', 'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle',
                       'ja', 'jae', 'jb', 'jbe', 'call', 'loop'}:
            return op
        
        # Handle bare identifier (C variable without brackets)
        if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', op):
            return f'__VAR_{op}__'
        
        return op

    def convert_memory_operand(self, op):
        """Convert complex memory addressing to AT&T format."""
        match = re.search(r'\[(.*?)\]', op)
        if not match:
            return op
        
        content = match.group(1)
        base = None
        index = None
        scale = None
        displacement = ""
        
        parts = re.split(r'([+\-])', content)
        parts = [p.strip() for p in parts if p.strip()]
        
        current_sign = '+'
        for part in parts:
            if part == '+':
                current_sign = '+'
                continue
            elif part == '-':
                current_sign = '-'
                continue
            
            # Check for index*scale pattern
            scale_match = re.match(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\*\s*(\d+)', part)
            if scale_match:
                idx_name = scale_match.group(1)
                scale = scale_match.group(2)
                if idx_name.lower() in self.x86_registers:
                    index = f'%%{idx_name.lower()}'
                else:
                    index = f'__VAR_{idx_name}__'
                continue
            
            # Check for scale*index pattern
            scale_match2 = re.match(r'(\d+)\s*\*\s*([a-zA-Z_][a-zA-Z0-9_]*)', part)
            if scale_match2:
                scale = scale_match2.group(1)
                idx_name = scale_match2.group(2)
                if idx_name.lower() in self.x86_registers:
                    index = f'%%{idx_name.lower()}'
                else:
                    index = f'__VAR_{idx_name}__'
                continue
            
            # Check if it's a register
            if part.lower() in self.x86_registers:
                if base is None:
                    base = f'%%{part.lower()}'
                elif index is None:
                    index = f'%%{part.lower()}'
                    scale = '1'
                continue
            
            # Check if it's a number
            if part.isdigit() or (part.startswith('0x')):
                if current_sign == '-':
                    displacement = f'-{part}'
                else:
                    displacement = part
                continue
            
            # It's a variable
            if base is None:
                base = f'__VAR_{part}__'
            elif index is None:
                index = f'__VAR_{part}__'
                scale = '1'
        
        # Build AT&T format: displacement(base, index, scale)
        result = ""
        if displacement:
            result = displacement
        
        if base or index:
            result += f'({base or ""}' 
            if index:
                result += f', {index}'
                if scale and scale != '1':
                    result += f', {scale}'
            result += ')'
        
        return result if result else '0'

    def build_constraints(self, variables, index_offset=0):
        """Build output and input constraint lists.
        
        Args:
            variables: Dict of variable info
            index_offset: Starting index offset for constraint numbering
        """
        outputs = []
        inputs = []
        var_to_index = {}
        current_idx = index_offset
        
        sorted_vars = sorted(variables.items(), key=lambda x: x[1]['index'])
        
        # First pass: outputs
        for var_name, info in sorted_vars:
            if info['write']:
                if info['read']:
                    outputs.append(f'"+r" ({var_name})')
                else:
                    outputs.append(f'"=r" ({var_name})')
                var_to_index[var_name] = current_idx
                current_idx += 1
        
        # Second pass: inputs
        for var_name, info in sorted_vars:
            if not info['write'] and info['read']:
                # For array bases used with LEA, we need "m" constraint for memory
                # But for general usage, we use "r" for registers
                if info.get('is_array_base'):
                    inputs.append(f'"r" ({var_name})')
                else:
                    inputs.append(f'"r" ({var_name})')
                var_to_index[var_name] = current_idx
                current_idx += 1
        
        return outputs, inputs, var_to_index

    # =========================================================================
    # ARM64 Support
    # =========================================================================
    
    def convert_arm64_asm_block(self, lines, indent, printf_registers=None):
        """Convert ARM64 assembly to GCC inline assembly."""
        if printf_registers is None:
            printf_registers = []
        
        variables = {}
        clobbers = set()
        converted_lines = []
        has_memory_write = False
        local_labels = set()
        
        # First pass: collect labels
        for line in lines:
            stripped = line.strip()
            if stripped.endswith(':') and not stripped.startswith('case '):
                label_name = stripped[:-1]
                local_labels.add(label_name)
        
        for line in lines:
            stripped = line.strip()
            
            if not stripped or stripped.startswith(';') or stripped.startswith('//'):
                continue
            
            # Handle inline comments
            if ';' in stripped:
                stripped = stripped.split(';', 1)[0].strip()
            if '//' in stripped:
                stripped = stripped.split('//', 1)[0].strip()
            
            if not stripped:
                continue
            
            # Handle labels
            if stripped.endswith(':') and not stripped.startswith('case '):
                label_name = stripped[:-1]
                converted_lines.append(f'".L_casm_{label_name}_%=:\\n\\t"')
                continue
            
            # Parse instruction
            parts = stripped.split(None, 1)
            if not parts:
                continue
            
            mnemonic = parts[0].lower()
            operands_str = parts[1] if len(parts) > 1 else ""
            operands = [o.strip() for o in operands_str.split(',') if o.strip()]
            
            # Track variables and clobbers
            for op in operands:
                var_match = re.match(r'^\[([a-zA-Z_][a-zA-Z0-9_]*)\]$', op)
                if var_match:
                    var_name = var_match.group(1)
                    if var_name.lower() not in self.arm64_registers:
                        is_write = mnemonic in {'str', 'stp', 'strb', 'strh'}
                        is_read = mnemonic in {'ldr', 'ldp', 'ldrb', 'ldrh', 'ldrsb', 'ldrsh', 'ldrsw'}
                        self.track_variable(var_name, is_read, is_write, variables)
                        if is_write:
                            has_memory_write = True
                elif op.lower() in self.arm64_registers:
                    if mnemonic in self.arm64_write_ops:
                        clobbers.add(op.lower())
            
            # Convert operands
            att_operands = []
            for op in operands:
                att_op = self.convert_arm64_operand(op, mnemonic)
                if mnemonic in {'b', 'bl', 'cbz', 'cbnz', 'tbz', 'tbnz',
                               'b.eq', 'b.ne', 'b.lt', 'b.gt', 'b.le', 'b.ge'}:
                    if op in local_labels:
                        att_op = f'.L_casm_{op}_%='
                att_operands.append(att_op)
            
            # Build instruction
            if att_operands:
                asm_instr = f'"{mnemonic} {", ".join(att_operands)}\\n\\t"'
            else:
                asm_instr = f'"{mnemonic}\\n\\t"'
            
            converted_lines.append(asm_instr)
        
        if has_memory_write:
            clobbers.add('memory')
        
        # Handle printf(register) - prepare output constraints for register extraction
        printf_var_names = []
        printf_outputs = []
        if printf_registers:
            for reg_name, _ in printf_registers:
                var_name = f'__casm_reg_{reg_name}__'
                printf_var_names.append((reg_name, var_name))
                printf_outputs.append(f'"=r" ({var_name})')
                # Normalize register to 64-bit (x0 instead of w0)
                norm_reg = reg_name
                if reg_name.startswith('w'):
                    norm_reg = 'x' + reg_name[1:]
                clobbers.discard(reg_name)
                clobbers.discard(norm_reg)
        
        # Build constraint lists with offset to account for printf outputs
        outputs, inputs, var_to_index = self.build_constraints(variables, len(printf_outputs))
        
        # Add the printf register extraction instructions
        # Printf outputs are at indices 0..len(printf_outputs)-1
        for i, (reg_name, var_name) in enumerate(printf_var_names):
            norm_reg = reg_name
            if reg_name.startswith('w'):
                norm_reg = 'x' + reg_name[1:]
            output_idx = i
            converted_lines.append(f'"mov %{output_idx}, {norm_reg}\\n\\t"')
        
        # Prepend printf outputs to the outputs list
        final_outputs = printf_outputs + outputs
        
        # Replace variable placeholders
        final_lines = []
        for line in converted_lines:
            for var_name, idx in var_to_index.items():
                line = re.sub(f'__VAR_{re.escape(var_name)}__', f'%{idx}', line)
            final_lines.append(line)
        
        # Build final __asm__ block
        # First, declare any printf register variables
        result = ''
        if printf_var_names:
            for _, var_name in printf_var_names:
                result += f'{indent}unsigned long long {var_name};\n'
        
        result += f'{indent}__asm__ volatile(\n'
        result += f'{indent}    ' + f'\n{indent}    '.join(final_lines)
        
        if final_outputs or inputs:
            result += f'\n{indent}    : ' + ', '.join(final_outputs)
            result += f'\n{indent}    : ' + ', '.join(inputs)
        else:
            result += f'\n{indent}    : '
            result += f'\n{indent}    : '
        
        if clobbers:
            clobber_list = [f'"{c}"' for c in sorted(clobbers)]
            result += f'\n{indent}    : ' + ', '.join(clobber_list)
        
        result += f'\n{indent});'
        
        # Add printf statements for each register
        if printf_var_names:
            for reg_name, var_name in printf_var_names:
                result += f'\n{indent}printf("%lld", (long long){var_name});'
        
        return result

    def convert_arm64_operand(self, op, mnemonic=''):
        """Convert ARM64 operand format."""
        op = op.strip()
        
        # Handle [var] - C variable
        var_match = re.match(r'^\[([a-zA-Z_][a-zA-Z0-9_]*)\]$', op)
        if var_match:
            var_name = var_match.group(1)
            if var_name.lower() not in self.arm64_registers:
                return f'__VAR_{var_name}__'
            else:
                return f'[{var_name}]'
        
        # Handle complex memory operands [reg, #offset]
        if '[' in op and ']' in op:
            match = re.search(r'\[([^,\]]+)(?:,\s*#?(-?\d+))?\](!)?', op)
            if match:
                base = match.group(1).strip()
                offset = match.group(2) if match.group(2) else '0'
                writeback = match.group(3) if match.group(3) else ''
                
                if base.lower() in self.arm64_registers:
                    return f'[{base}, #{offset}]{writeback}'
                else:
                    return f'__VAR_{base}__'
        
        # Handle immediate with #
        if op.startswith('#'):
            return op
        
        # Handle registers
        if op.lower() in self.arm64_registers:
            return op
        
        return op

