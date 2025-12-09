import re


class CppAsmConverter:
    # Class-level counter for unique asm block IDs
    _asm_block_counter = 0
    # Class-level registry for global labels (shared across asm blocks)
    _global_labels = {}  # label_name -> unique_name
    
    def __init__(self, source, arch=None):
        """
        Initialize the converter.
        
        Args:
            source: The C++ source code
            arch: Target architecture ('x86_64', 'arm64', or None for auto-detect)
        """
        self.source = source
        self.lines = source.split('\n')
        self.output_lines = []
        self.arch = arch  # Will be auto-detected if None
        
        # Reset global labels for each file conversion
        CppAsmConverter._global_labels = {}
        CppAsmConverter._asm_block_counter = 0
        
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
            'div', 'mul', 'idiv', 'imul',
        }
        
        # ARM64 registers
        self.arm64_registers = set()
        # General purpose registers x0-x30 and w0-w30
        for i in range(31):
            self.arm64_registers.add(f'x{i}')
            self.arm64_registers.add(f'w{i}')
        # Special registers
        self.arm64_registers.update(['sp', 'xzr', 'wzr', 'lr', 'fp'])
        # SIMD registers v0-v31 and their aliases
        for i in range(32):
            self.arm64_registers.add(f'v{i}')
            self.arm64_registers.add(f'd{i}')
            self.arm64_registers.add(f's{i}')
            self.arm64_registers.add(f'h{i}')
            self.arm64_registers.add(f'b{i}')
            self.arm64_registers.add(f'q{i}')
        
        # ARM64 instructions that write to the first operand
        self.arm64_write_ops = {
            'mov', 'movz', 'movn', 'movk', 'ldr', 'ldp', 'ldrb', 'ldrh', 'ldrsb', 'ldrsh', 'ldrsw',
            'add', 'sub', 'mul', 'sdiv', 'udiv', 'madd', 'msub',
            'and', 'orr', 'eor', 'bic', 'orn', 'eon',
            'lsl', 'lsr', 'asr', 'ror',
            'adc', 'sbc', 'neg', 'mvn',
            'csel', 'csinc', 'csinv', 'csneg',
            'sxtb', 'sxth', 'sxtw', 'uxtb', 'uxth',
            'rev', 'rev16', 'rev32', 'clz', 'cls',
            'fmov', 'fadd', 'fsub', 'fmul', 'fdiv', 'fneg', 'fabs', 'fsqrt',
            'fcvt', 'scvtf', 'ucvtf', 'fcvtzs', 'fcvtzu',
        }
        
        # ARM64 instructions that only read from first operand (stores)
        self.arm64_read_ops = {
            'str', 'stp', 'strb', 'strh',
            'cmp', 'cmn', 'tst',
            'b', 'bl', 'br', 'blr', 'ret',
            'cbz', 'cbnz', 'tbz', 'tbnz',
            'b.eq', 'b.ne', 'b.lt', 'b.le', 'b.gt', 'b.ge', 'b.lo', 'b.ls', 'b.hi', 'b.hs',
            'nop', 'svc',
            'fcmp', 'fccmp',
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
        return None  # Couldn't determine
    
    def get_block_arch(self, asm_lines):
        """Determine architecture for a block, preferring auto-detection."""
        detected = self.detect_arch(asm_lines)
        # If we detected an architecture from the code, use it
        if detected:
            return detected
        # Otherwise fall back to the provided arch or default to x86_64
        return self.arch or 'x86_64'

    def convert(self):
        """Main conversion entry point."""
        # Track all architectures used in this file
        self.detected_archs = set()
        
        i = 0
        while i < len(self.lines):
            line = self.lines[i]
            stripped = line.strip()
            
            # Check for asm( block start
            # Support: asm(, __asm__(, __asm__ volatile(, asm volatile(
            asm_match = re.match(r'^(\s*)(asm|__asm__|__asm)\s*(volatile\s*)?\(\s*$', stripped, re.IGNORECASE)
            if asm_match:
                indent = self.get_indent(line)
                # Collect all lines until closing )
                asm_lines = []
                i += 1
                while i < len(self.lines):
                    asm_line = self.lines[i]
                    if asm_line.strip() == ')':
                        i += 1
                        break
                    # Also check for ); or ) with trailing stuff
                    if asm_line.strip().startswith(')'):
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
                    # Skip empty lines between asm block and printr
                    if not next_stripped:
                        i += 1
                        continue
                    break
                
                # Auto-detect architecture from code (prioritizes code over CLI arg)
                block_arch = self.get_block_arch(asm_lines)
                self.detected_archs.add(block_arch)
                
                # Convert the asm block based on architecture
                if block_arch == 'arm64':
                    converted = self.convert_arm64_asm_block(asm_lines, indent, printf_registers)
                else:
                    converted = self.convert_asm_block(asm_lines, indent, printf_registers)
                self.output_lines.append(converted)
            # Check for inline assembly written directly (no asm() wrapper)
            elif self.is_direct_asm_line(stripped):
                indent = self.get_indent(line)
                # Collect consecutive assembly lines
                asm_lines = [line]
                i += 1
                while i < len(self.lines):
                    next_line = self.lines[i]
                    next_stripped = next_line.strip()
                    if self.is_direct_asm_line(next_stripped):
                        asm_lines.append(next_line)
                        i += 1
                    elif not next_stripped:
                        # Empty line - check if more asm follows
                        j = i + 1
                        while j < len(self.lines) and not self.lines[j].strip():
                            j += 1
                        if j < len(self.lines) and self.is_direct_asm_line(self.lines[j].strip()):
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
                
                # Auto-detect architecture from code (prioritizes code over CLI arg)
                block_arch = self.get_block_arch(asm_lines)
                self.detected_archs.add(block_arch)
                
                # Convert the direct asm block
                if block_arch == 'arm64':
                    converted = self.convert_arm64_asm_block(asm_lines, indent, printf_registers)
                else:
                    converted = self.convert_asm_block(asm_lines, indent, printf_registers)
                self.output_lines.append(converted)
            else:
                # Check for printr(register) pattern and convert it (standalone)
                converted_line = self.convert_printr_register(line)
                self.output_lines.append(converted_line)
                i += 1
        
        # Add architecture metadata comment at the top
        arch_list = ','.join(sorted(self.detected_archs)) if self.detected_archs else 'none'
        result = f'// CASM_ARCH: {arch_list}\n' + '\n'.join(self.output_lines)
        return result

    def is_direct_asm_line(self, stripped):
        """Check if a line is a direct assembly instruction (without asm() wrapper)."""
        if not stripped:
            return False
        
        # Skip C++ constructs
        if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
            return False
        if stripped.startswith('#'):  # preprocessor
            return False
        if stripped.endswith(';') and not stripped.endswith('\\n\\t";'):
            return False  # C++ statement
        if '{' in stripped or '}' in stripped:
            return False
        if '(' in stripped and ')' in stripped and not re.match(r'^\w+\s+\w+,', stripped):
            return False  # function call or declaration
        if stripped.startswith('return ') or stripped.startswith('if ') or stripped.startswith('else'):
            return False
        if stripped.startswith('for ') or stripped.startswith('while ') or stripped.startswith('switch '):
            return False
        if stripped.startswith('class ') or stripped.startswith('struct ') or stripped.startswith('namespace '):
            return False
        if '::' in stripped and '[' not in stripped:  # C++ scope resolution (but not asm)
            return False
        if stripped.startswith('std::') or 'cout' in stripped or 'cin' in stripped:
            return False
        
        # Check for labels (word followed by colon, not case:)
        if re.match(r'^[a-zA-Z_]\w*:$', stripped) and not stripped.startswith('case ') and stripped != 'default:':
            return True
        
        # Get first word
        parts = stripped.split()
        if not parts:
            return False
        first_word = parts[0].lower()
        
        # Check for known assembly mnemonics
        all_mnemonics = set()
        
        # x86 mnemonics
        all_mnemonics.update(self.write_ops)
        all_mnemonics.update(self.rmw_ops)
        all_mnemonics.update(self.read_ops)
        
        # ARM64 mnemonics
        all_mnemonics.update(self.arm64_write_ops)
        all_mnemonics.update(self.arm64_read_ops)
        
        # Additional common mnemonics
        all_mnemonics.update({
            'mov', 'add', 'sub', 'mul', 'div', 'and', 'or', 'xor', 'not', 'neg',
            'push', 'pop', 'call', 'ret', 'jmp', 'je', 'jne', 'jg', 'jl', 'jge', 'jle',
            'cmp', 'test', 'lea', 'nop', 'inc', 'dec', 'shl', 'shr', 'sar', 'sal',
            'imul', 'idiv', 'movzx', 'movsx', 'movsxd', 'xchg', 'bswap',
            'ldr', 'str', 'ldp', 'stp', 'lsl', 'lsr', 'asr', 'ror',
            'csel', 'csinc', 'cbz', 'cbnz', 'bl', 'br', 'blr', 'svc',
            'adc', 'sbb', 'rol', 'rcl', 'rcr', 'bt', 'bts', 'btr', 'btc',
            'cmovz', 'cmovnz', 'cmove', 'cmovne', 'cmovg', 'cmovl',
            'sete', 'setne', 'setg', 'setl', 'setge', 'setle',
            'syscall', 'int', 'hlt', 'leave', 'enter',
        })
        
        if first_word in all_mnemonics:
            return True
        
        return False

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
        """
        Convert a block of NASM-style assembly to GCC inline assembly.
        
        Supports advanced features:
        - push/pop tracking
        - function calls with ABI handling
        - array indexing [array + i * 8]
        - memory clobber detection
        - local labels with unique names
        - printf(register) integration
        
        Input (NASM style):
            mov rax, [num1]
            add rax, [num2]
            mov [result], rax
        
        Output (GCC inline asm):
            __asm__ volatile(
                "movq %1, %%rax\n\t"
                "addq %2, %%rax\n\t"
                "movq %%rax, %0\n\t"
                : "=m" (result)
                : "m" (num1), "m" (num2)
                : "rax", "memory"
            );
        """
        if printf_registers is None:
            printf_registers = []
        
        # Get unique block ID for this asm block
        block_id = CppAsmConverter._asm_block_counter
        CppAsmConverter._asm_block_counter += 1
        
        variables = {}  # var_name -> {'index': i, 'read': bool, 'write': bool, 'is_array': bool}
        clobbers = set()
        converted_lines = []
        has_memory_write = False
        push_count = 0  # Track push/pop balance
        has_call = False  # Track if we have function calls
        local_labels = set()  # Labels local to this block (use %=)
        global_labels = {}  # Labels accessible from other blocks (use block-specific name)
        
        # First pass: collect labels and analyze
        # Labels can be marked as global with @global or global_ prefix
        for line in lines:
            stripped = line.strip()
            if stripped.endswith(':') and not stripped.startswith('case '):
                label_part = stripped[:-1]
                
                # Check for @global annotation
                if '@global' in label_part:
                    label_name = label_part.replace('@global', '').strip()
                    unique_name = f'.L_casm_global_{label_name}'
                    global_labels[label_name] = unique_name
                    CppAsmConverter._global_labels[label_name] = unique_name
                # Check for global_ prefix
                elif label_part.startswith('global_'):
                    label_name = label_part
                    unique_name = f'.L_casm_{label_name}'
                    global_labels[label_name] = unique_name
                    CppAsmConverter._global_labels[label_name] = unique_name
                else:
                    # Local label - will use %= suffix
                    local_labels.add(label_part)
        
        for line in lines:
            stripped = line.strip()
            
            # Skip empty lines and comments
            if not stripped or stripped.startswith(';') or stripped.startswith('//'):
                continue
            
            # Handle inline comments
            comment = ""
            if ';' in stripped:
                parts = stripped.split(';', 1)
                stripped = parts[0].strip()
                comment = " // " + parts[1].strip()
            
            if not stripped:
                continue
            
            # Handle labels
            if stripped.endswith(':') and not stripped.startswith('case '):
                label_part = stripped[:-1]
                
                # Check for @global annotation
                if '@global' in label_part:
                    label_name = label_part.replace('@global', '').strip()
                    unique_name = global_labels.get(label_name, f'.L_casm_global_{label_name}')
                    converted_lines.append(f'"{unique_name}:\\n\\t"')
                # Check for global_ prefix
                elif label_part.startswith('global_'):
                    unique_name = global_labels.get(label_part, f'.L_casm_{label_part}')
                    converted_lines.append(f'"{unique_name}:\\n\\t"')
                else:
                    # Local label - use %= for unique suffix in GCC inline asm
                    converted_lines.append(f'".L_casm_{label_part}_%=:\\n\\t"')
                continue
            
            # Parse instruction
            parts = stripped.split(None, 1)
            if not parts:
                continue
                
            mnemonic = parts[0].lower()
            operands_str = parts[1] if len(parts) > 1 else ""
            
            # Parse operands (handle commas, but be careful with brackets)
            operands = self.parse_operands(operands_str)
            
            # Track push/pop
            if mnemonic == 'push':
                push_count += 1
            elif mnemonic == 'pop':
                push_count -= 1
            
            # Track function calls
            if mnemonic == 'call':
                has_call = True
                # Add caller-saved registers to clobbers (System V AMD64 ABI)
                clobbers.update(['rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11'])
                has_memory_write = True  # Calls may modify memory
            
            # Check for memory writes (stores to [var])
            if operands and mnemonic in self.write_ops:
                dest = operands[0]
                if dest.startswith('[') and dest.endswith(']'):
                    has_memory_write = True
            
            # Determine instruction suffix based on operand sizes
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
                    if var_name.lower() not in self.registers:
                        # This is lea reg, [variable] - use RIP-relative addressing
                        clobbers.add(self.normalize_register(dest_reg))
                        asm_instr = f'"leaq {var_name}(%%rip), %%{dest_reg}\\n\\t"'
                        converted_lines.append(asm_instr)
                        continue
            
            # Convert each operand to AT&T format
            att_operands = []
            for op in operands:
                att_op = self.convert_operand(op, mnemonic)
                
                # Update jump/call targets to use appropriate labels
                if mnemonic in {'jmp', 'je', 'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle',
                               'ja', 'jae', 'jb', 'jbe', 'jo', 'jno', 'js', 'jns', 'jp', 'jnp',
                               'loop', 'loope', 'loopne', 'loopz', 'loopnz', 'call'}:
                    # Check if it's a local label
                    if op in local_labels:
                        att_op = f'.L_casm_{op}_%='
                    # Check if it's a global label (defined in this block)
                    elif op in global_labels:
                        att_op = global_labels[op]
                    # Check if it's a global label (defined in another block)
                    elif op in CppAsmConverter._global_labels:
                        att_op = CppAsmConverter._global_labels[op]
                    # Check for global_ prefix
                    elif op.startswith('global_'):
                        att_op = f'.L_casm_{op}'
                
                att_operands.append(att_op)
            
            # AT&T uses reversed operand order (src, dest) for most instructions
            # For 2-operand instructions: reverse to (src, dest)
            # For 3-operand imul: imul dest, src, imm -> imulq $imm, src, dest
            if len(att_operands) == 2 and mnemonic not in {'push', 'pop', 'call', 'jmp'}:
                att_operands.reverse()
            elif len(att_operands) == 3:
                # Three-operand instructions (like imul rax, rbx, 3 -> imulq $3, %rbx, %rax)
                # NASM: dest, src, imm -> AT&T: imm, src, dest
                att_operands = [att_operands[2], att_operands[1], att_operands[0]]
            
            # Build the instruction string
            # Note: Comments are not preserved in inline asm to avoid syntax issues
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
        
        # Add stack alignment for calls if push/pop is unbalanced
        if has_call and push_count != 0:
            # Insert stack alignment at the beginning
            converted_lines.insert(0, '"subq $8, %%rsp\\n\\t"  // Stack alignment for call')
            converted_lines.append('"addq $8, %%rsp\\n\\t"  // Restore stack')
        
        # Add memory clobber if we write to memory
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
        
        # Build constraint lists (with offset for printf outputs)
        outputs, inputs, var_to_index = self.build_constraints(variables, len(printf_outputs))
        
        # Add printf output mov instructions (indices 0..len(printf_outputs)-1)
        for i, (reg_name, var_name) in enumerate(printf_var_names):
            norm_reg = self.normalize_register(reg_name)
            output_idx = i
            converted_lines.append(f'"movq %%{norm_reg}, %{output_idx}\\n\\t"')
        
        # Prepend printf outputs to the outputs list
        final_outputs = printf_outputs + outputs
        
        # Replace variable placeholders with operand indices
        final_lines = []
        for line in converted_lines:
            for var_name, idx in var_to_index.items():
                # Replace [var] patterns that were converted to __VAR_var__
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
        bracket_depth = 0
        
        for char in operands_str:
            if char == '[':
                bracket_depth += 1
                current += char
            elif char == ']':
                bracket_depth -= 1
                current += char
            elif char == ',' and bracket_depth == 0:
                operands.append(current.strip())
                current = ""
            else:
                current += char
        
        if current.strip():
            operands.append(current.strip())
        
        return operands

    def determine_suffix(self, mnemonic, operands):
        """Determine the AT&T instruction suffix based on operand sizes."""
        # Instructions that don't need suffixes
        no_suffix_ops = {
            'jmp', 'je', 'jne', 'jg', 'jge', 'jl', 'jle', 'ja', 'jae', 'jb', 'jbe',
            'jz', 'jnz', 'jo', 'jno', 'js', 'jns', 'jp', 'jnp',
            'call', 'ret', 'leave', 'nop', 'hlt', 'syscall', 'int',
            'loop', 'loope', 'loopne',
            'push', 'pop',  # These infer size from operand
            'movsxd', 'movsx', 'movzx',  # These have implicit sizing
            'lea', 'leaq',  # LEA uses destination register size
        }
        
        if mnemonic in no_suffix_ops:
            return ''
        
        # Check for explicit size specifiers in operands
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
            # Strip size prefixes
            clean_op = re.sub(r'\b(byte|word|dword|qword)\s+(ptr\s+)?', '', op, flags=re.IGNORECASE).strip()
            # Check if it's a register
            reg = clean_op.lower()
            if reg in self.registers:
                return self.registers[reg]
        
        # Default to qword (64-bit) for modern x86-64
        return 'q'

    def analyze_operands(self, mnemonic, operands, variables, clobbers):
        """Analyze operands to track variable usage and register clobbers."""
        # First operand (Intel dest)
        if operands:
            dest = operands[0]
            is_write = mnemonic in self.write_ops
            is_read = mnemonic in self.rmw_ops
            self.track_operand(dest, is_read, is_write, variables, clobbers)
        
        # Second operand (Intel src)
        if len(operands) > 1:
            src = operands[1]
            self.track_operand(src, True, False, variables, clobbers)

    def track_operand(self, op, is_read, is_write, variables, clobbers):
        """Track an operand for variable references and register clobbers."""
        # Strip size specifiers
        op = re.sub(r'\b(byte|word|dword|qword)\s+(ptr\s+)?', '', op, flags=re.IGNORECASE).strip()
        
        # Check for [var] pattern - C++ variable reference
        var_match = re.match(r'^\[([a-zA-Z_][a-zA-Z0-9_]*)\]$', op)
        if var_match:
            var_name = var_match.group(1)
            # Skip if it's a register
            if var_name.lower() not in self.registers:
                self.track_variable(var_name, is_read, is_write, variables)
            return
        
        # Check for memory operands with complex addressing [base + offset]
        if '[' in op and ']' in op:
            # Extract content inside brackets
            match = re.search(r'\[(.*?)\]', op)
            if match:
                content = match.group(1)
                
                # Parse the memory expression to identify base vs index
                # Pattern: base + index * scale + displacement
                # or: base + displacement
                
                # Split on + and - while preserving the operators
                parts = re.split(r'([+\-])', content)
                parts = [p.strip() for p in parts if p.strip()]
                
                # First non-operator part is typically the base
                first_token = True
                for i, part in enumerate(parts):
                    if part in '+-':
                        continue
                    
                    # Check for index*scale pattern
                    scale_match = re.match(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\*\s*\d+', part)
                    if scale_match:
                        token = scale_match.group(1)
                        if token.lower() not in self.registers:
                            # This is a variable used as array index
                            self.track_variable(token, True, False, variables, is_array_index=True)
                        continue
                    
                    # Check for scale*index pattern
                    scale_match2 = re.match(r'\d+\s*\*\s*([a-zA-Z_][a-zA-Z0-9_]*)', part)
                    if scale_match2:
                        token = scale_match2.group(1)
                        if token.lower() not in self.registers:
                            self.track_variable(token, True, False, variables, is_array_index=True)
                        continue
                    
                    # Check if it's a simple identifier (variable or register)
                    if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', part):
                        if part.lower() not in self.registers:
                            if first_token:
                                # First identifier is likely the array base
                                # Memory operations on array are read/write based on instruction
                                self.track_variable(part, True, False, variables, is_array_base=True)
                            else:
                                # Additional identifiers are indices
                                self.track_variable(part, True, False, variables, is_array_index=True)
                    
                    first_token = False
            return
        
        # Check for register - add to clobbers if written
        reg = op.lower()
        if reg in self.registers:
            if is_write:
                clobbers.add(self.normalize_register(reg))
            return
        
        # Check for immediate values
        if op.startswith('0x') or op.startswith('0X') or op.isdigit() or \
           (op.startswith('-') and op[1:].isdigit()):
            return
        
        # Check for labels (used in jumps/calls)
        if not op.startswith('['):
            return

    def track_variable(self, name, is_read, is_write, variables, is_array_base=False, is_array_index=False):
        """Track a C++ variable for constraint generation."""
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
        """Normalize register to its 64-bit parent for clobber list."""
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
        # Strip size specifiers but remember them
        op = re.sub(r'\b(byte|word|dword|qword)\s+(ptr\s+)?', '', op, flags=re.IGNORECASE).strip()
        
        # Handle [var] - C++ variable (memory operand)
        var_match = re.match(r'^\[([a-zA-Z_][a-zA-Z0-9_]*)\]$', op)
        if var_match:
            var_name = var_match.group(1)
            if var_name.lower() not in self.registers:
                # Use a placeholder that will be replaced with the operand index
                return f'__VAR_{var_name}__'
            else:
                # It's a register used as a pointer: [rax] -> (%%rax)
                return f'(%%{var_name.lower()})'
        
        # Handle complex memory operands [base + index*scale + disp]
        if '[' in op and ']' in op:
            return self.convert_memory_operand(op)
        
        # Handle registers
        reg = op.lower()
        if reg in self.registers:
            return f'%%{reg}'
        
        # Handle immediates
        if op.startswith('0x') or op.startswith('0X'):
            return f'${op}'
        if op.isdigit() or (op.startswith('-') and op[1:].isdigit()):
            return f'${op}'
        
        # Labels (for jumps/calls)
        return op

    def convert_memory_operand(self, op):
        """
        Convert NASM memory operand [base + index*scale + disp] to AT&T format.
        
        Supports:
        - [rax]                  -> (%%rax)
        - [rax + 8]              -> 8(%%rax)
        - [rax + rbx*4]          -> (%%rax, %%rbx, 4)
        - [rax + rbx*4 + 16]     -> 16(%%rax, %%rbx, 4)
        - [array]                -> __VAR_array__ (variable)
        - [array + i*8]          -> (__VAR_array__, __VAR_i__, 8) (array indexing)
        - [rax + i*8]            -> (%%rax, __VAR_i__, 8) (register + var index)
        """
        match = re.search(r'\[(.*?)\]', op)
        if not match:
            return op
        
        content = match.group(1).strip()
        
        base = None
        base_is_var = False
        index = None
        index_is_var = False
        scale = None
        disp = None
        disp_parts = []
        
        # Split by + and - while keeping the sign
        parts = re.split(r'(\+|-)', content)
        current_sign = '+'
        
        for part in parts:
            part = part.strip()
            if part == '+':
                current_sign = '+'
                continue
            elif part == '-':
                current_sign = '-'
                continue
            elif not part:
                continue
            
            # Check for scale: var*n or n*var or reg*n or n*reg
            scale_match = re.match(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\*\s*(\d+)', part)
            if scale_match:
                idx_name = scale_match.group(1)
                scale = scale_match.group(2)
                if idx_name.lower() in self.registers:
                    index = idx_name.lower()
                    index_is_var = False
                else:
                    index = idx_name
                    index_is_var = True
                continue
            
            scale_match = re.match(r'(\d+)\s*\*\s*([a-zA-Z_][a-zA-Z0-9_]*)', part)
            if scale_match:
                scale = scale_match.group(1)
                idx_name = scale_match.group(2)
                if idx_name.lower() in self.registers:
                    index = idx_name.lower()
                    index_is_var = False
                else:
                    index = idx_name
                    index_is_var = True
                continue
            
            # Check if it's a register
            if part.lower() in self.registers:
                if base is None:
                    base = part.lower()
                    base_is_var = False
                elif index is None:
                    index = part.lower()
                    index_is_var = False
                continue
            
            # Check if it's a number (displacement)
            if part.isdigit():
                disp_val = int(part) if current_sign == '+' else -int(part)
                if disp is None:
                    disp = disp_val
                else:
                    disp += disp_val
                continue
            
            # Check for hex numbers
            if part.startswith('0x') or part.startswith('0X'):
                try:
                    disp_val = int(part, 16) if current_sign == '+' else -int(part, 16)
                    if disp is None:
                        disp = disp_val
                    else:
                        disp += disp_val
                    continue
                except ValueError:
                    pass
            
            # It's a variable name (could be array base or index)
            if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', part):
                if part.lower() not in self.registers:
                    if base is None:
                        base = part
                        base_is_var = True
                    elif index is None:
                        index = part
                        index_is_var = True
                else:
                    if base is None:
                        base = part.lower()
                        base_is_var = False
                    elif index is None:
                        index = part.lower()
                        index_is_var = False
        
        # Build AT&T format: disp(base, index, scale)
        result = ""
        
        # Handle displacement
        if disp is not None and disp != 0:
            result += str(disp)
        
        # Build the addressing mode
        if base or index:
            result += "("
            if base:
                if base_is_var:
                    result += f"__VAR_{base}__"
                else:
                    result += f"%%{base}"
            if index:
                if base:
                    result += ", "
                if index_is_var:
                    result += f"__VAR_{index}__"
                else:
                    result += f"%%{index}"
                if scale:
                    result += f", {scale}"
            result += ")"
        
        return result if result else "0"

    def build_constraints(self, variables, index_offset=0):
        """Build output and input constraint lists for inline assembly.
        
        Args:
            variables: Dict of variable info
            index_offset: Starting index offset for constraint numbering
        """
        outputs = []
        inputs = []
        var_to_index = {}
        current_idx = index_offset
        
        # Sort variables by their first appearance order
        sorted_vars = sorted(variables.items(), key=lambda x: x[1]['index'])
        
        # First pass: outputs (written variables)
        for var_name, info in sorted_vars:
            if info['write']:
                # Array bases need special handling - they hold an address
                if info.get('is_array_base'):
                    if info['read']:
                        outputs.append(f'"+r" ({var_name})')
                    else:
                        outputs.append(f'"=r" ({var_name})')
                elif info['read']:
                    # Read-modify-write: use +r constraint
                    outputs.append(f'"+r" ({var_name})')
                else:
                    # Write-only: use =r constraint
                    outputs.append(f'"=r" ({var_name})')
                var_to_index[var_name] = current_idx
                current_idx += 1
        
        # Second pass: inputs (read-only variables)
        for var_name, info in sorted_vars:
            if not info['write'] and info['read']:
                # Array bases should use "r" to get the address in a register
                if info.get('is_array_base'):
                    inputs.append(f'"r" ({var_name})')
                # Array indices should use "r" to get the value in a register  
                elif info.get('is_array_index'):
                    inputs.append(f'"r" ({var_name})')
                else:
                    # Regular memory operands
                    inputs.append(f'"r" ({var_name})')
                var_to_index[var_name] = current_idx
                current_idx += 1
        
        return outputs, inputs, var_to_index

    # =========================================================================
    # ARM64 Support
    # =========================================================================
    
    def convert_arm64_asm_block(self, lines, indent, printf_registers=None):
        """
        Convert a block of ARM64 assembly to GCC inline assembly.
        
        ARM64 assembly already uses a syntax similar to what GCC expects,
        but we need to:
        1. Map C++ variables [var] to operand placeholders
        2. Track register clobbers
        3. Generate proper constraints
        4. Handle printf(register) integration
        
        Input:
            ldr x0, [num1]
            ldr x1, [num2]
            add x0, x0, x1
            str x0, [result]
        
        Output:
            __asm__ volatile(
                "ldr x0, %1\n\t"
                "ldr x1, %2\n\t"
                "add x0, x0, x1\n\t"
                "str x0, %0\n\t"
                : "=m" (result)
                : "m" (num1), "m" (num2)
                : "x0", "x1"
            );
        """
        if printf_registers is None:
            printf_registers = []
        
        variables = {}  # var_name -> {'index': i, 'read': bool, 'write': bool}
        clobbers = set()
        converted_lines = []
        
        for line in lines:
            stripped = line.strip()
            
            # Skip empty lines and comments
            if not stripped or stripped.startswith(';') or stripped.startswith('//'):
                continue
            
            # Handle inline comments
            comment = ""
            if '//' in stripped:
                parts = stripped.split('//', 1)
                stripped = parts[0].strip()
                comment = " // " + parts[1].strip()
            
            if not stripped:
                continue
            
            # Handle labels
            if stripped.endswith(':') and not stripped.startswith('case '):
                converted_lines.append(f'"{stripped}\\n\\t"')
                continue
            
            # Parse instruction
            parts = stripped.split(None, 1)
            if not parts:
                continue
                
            mnemonic = parts[0].lower()
            operands_str = parts[1] if len(parts) > 1 else ""
            
            # Parse operands
            operands = self.parse_arm64_operands(operands_str)
            
            # Track variables and clobbers
            self.analyze_arm64_operands(mnemonic, operands, variables, clobbers)
            
            # Convert operands (mainly handling [var] patterns)
            converted_ops = []
            for op in operands:
                converted_op = self.convert_arm64_operand(op)
                converted_ops.append(converted_op)
            
            # Build the instruction string
            if converted_ops:
                asm_instr = f'"{mnemonic} {", ".join(converted_ops)}\\n\\t"'
            else:
                asm_instr = f'"{mnemonic}\\n\\t"'
            
            if comment:
                asm_instr = asm_instr[:-1] + comment + '"'
            
            converted_lines.append(asm_instr)
        
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
        
        # Build constraint lists with offset for printf outputs
        outputs, inputs, var_to_index = self.build_constraints(variables, len(printf_outputs))
        
        # Add printf output mov instructions (indices 0..len(printf_outputs)-1)
        for i, (reg_name, var_name) in enumerate(printf_var_names):
            norm_reg = reg_name
            if reg_name.startswith('w'):
                norm_reg = 'x' + reg_name[1:]
            output_idx = i
            converted_lines.append(f'"mov %{output_idx}, {norm_reg}\\n\\t"')
        
        # Prepend printf outputs to the outputs list
        final_outputs = printf_outputs + outputs
        
        # Replace variable placeholders with operand indices
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

    def parse_arm64_operands(self, operands_str):
        """Parse ARM64 operands, respecting brackets."""
        if not operands_str:
            return []
        
        operands = []
        current = ""
        bracket_depth = 0
        
        for char in operands_str:
            if char == '[':
                bracket_depth += 1
                current += char
            elif char == ']':
                bracket_depth -= 1
                current += char
            elif char == ',' and bracket_depth == 0:
                operands.append(current.strip())
                current = ""
            else:
                current += char
        
        if current.strip():
            operands.append(current.strip())
        
        return operands

    def analyze_arm64_operands(self, mnemonic, operands, variables, clobbers):
        """Analyze ARM64 operands for variable usage and clobbers."""
        # First operand is usually the destination for most instructions
        if operands:
            dest = operands[0]
            is_write = mnemonic in self.arm64_write_ops
            is_read = mnemonic not in {'mov', 'movz', 'movn', 'ldr', 'ldp', 'ldrb', 'ldrh'}
            self.track_arm64_operand(dest, is_read, is_write, variables, clobbers)
        
        # Remaining operands are usually sources
        for op in operands[1:]:
            # Check for store instructions where the first operand is actually the source
            if mnemonic in {'str', 'stp', 'strb', 'strh'}:
                # For store, first operand is source (read), memory operand is dest (write)
                if '[' in op:
                    self.track_arm64_operand(op, False, True, variables, clobbers)
                else:
                    self.track_arm64_operand(op, True, False, variables, clobbers)
            else:
                self.track_arm64_operand(op, True, False, variables, clobbers)

    def track_arm64_operand(self, op, is_read, is_write, variables, clobbers):
        """Track an ARM64 operand for variables and clobbers."""
        # Check for [var] pattern - C++ variable reference
        var_match = re.match(r'^\[([a-zA-Z_][a-zA-Z0-9_]*)\]$', op)
        if var_match:
            var_name = var_match.group(1)
            if var_name.lower() not in self.arm64_registers:
                self.track_variable(var_name, is_read, is_write, variables)
            return
        
        # Check for memory operands with register base [x0], [x0, #offset], etc.
        if '[' in op and ']' in op:
            match = re.search(r'\[(.*?)\]', op)
            if match:
                content = match.group(1)
                # Check if it's a variable
                tokens = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*', content)
                for token in tokens:
                    if token.lower() not in self.arm64_registers:
                        self.track_variable(token, True, is_write, variables)
            return
        
        # Check for register - add to clobbers if written
        reg = op.lower()
        # Handle register with optional suffix like x0.8b
        base_reg = reg.split('.')[0]
        if base_reg in self.arm64_registers:
            if is_write:
                clobbers.add(base_reg)
            return

    def convert_arm64_operand(self, op, mnemonic=''):
        """Convert an ARM64 operand, handling variable references."""
        # Handle [var] - C++ variable reference
        var_match = re.match(r'^\[([a-zA-Z_][a-zA-Z0-9_]*)\]$', op)
        if var_match:
            var_name = var_match.group(1)
            if var_name.lower() not in self.arm64_registers:
                # For mov instructions, we want to use the value directly
                return f'__VAR_{var_name}__'
            # It's a register: [x0] stays as [x0]
            return op
        
        # Handle memory operands [reg, #offset] etc.
        if '[' in op and ']' in op:
            match = re.search(r'\[([^\]]*)\]', op)
            if match:
                content = match.group(1)
                # Check if content contains a variable
                tokens = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*', content)
                for token in tokens:
                    if token.lower() not in self.arm64_registers:
                        # Replace variable with placeholder
                        content = re.sub(rf'\b{re.escape(token)}\b', f'__VAR_{token}__', content)
                return f'[{content}]'
        
        # Handle immediate with # prefix
        if op.startswith('#'):
            return op
        
        # Other operands pass through unchanged
        return op
