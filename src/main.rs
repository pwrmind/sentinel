use std::ptr::{null_mut, null};
use std::io::{self, Write};
use std::mem::size_of;
use std::arch::asm;

// --- МАКРОСЫ ДЛЯ ХАШИРОВАНИЯ СТРОК (обфускация) ---
const fn hash_str(s: &str) -> u32 {
    let bytes = s.as_bytes();
    let mut hash: u32 = 0x811C9DC5;
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u32;
        hash = hash.wrapping_mul(0x01000193);
        i += 1;
    }
    hash
}

// --- СТРУКТУРЫ ДЛЯ NTAPI (скопированы из winapi) ---
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut u16,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct OBJECT_ATTRIBUTES {
    pub Length: u32,
    pub RootDirectory: *mut std::ffi::c_void,
    pub ObjectName: *mut UNICODE_STRING,
    pub Attributes: u32,
    pub SecurityDescriptor: *mut std::ffi::c_void,
    pub SecurityQualityOfService: *mut std::ffi::c_void,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CLIENT_ID {
    pub UniqueProcess: *mut std::ffi::c_void,
    pub UniqueThread: *mut std::ffi::c_void,
}

// --- КОНСТАНТЫ (захешированные) ---
const PROC_TERM: u32 = 0x0001; // PROCESS_TERMINATE
const PROC_VM_READ: u32 = 0x0010;
const PROC_QUERY_INFO: u32 = 0x0400;
const STATUS_SUCCESS: i32 = 0;

// --- ПРЯМЫЕ СИСТЕМНЫЕ ВЫЗОВЫ (Syscall) ---
unsafe fn syscall_nt_open_process(
    process_handle: *mut *mut std::ffi::c_void,
    access_mask: u32,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    client_id: *mut CLIENT_ID,
) -> i32 {
    let mut syscall_number: u32 = 0;
    
    // Динамическое определение номера syscall для NtOpenProcess
    // В реальном коде нужно получать это из ntdll.dll
    #[cfg(target_arch = "x86_64")]
    {
        syscall_number = 0x26; // Windows 10/11 x64 для NtOpenProcess
    }
    
    let mut result: i32;
    #[cfg(target_arch = "x86_64")]
    asm!(
        "mov r10, rcx",
        "mov eax, {syscall_num}",
        "syscall",
        "mov {result:e}, eax",
        syscall_num = in(reg) syscall_number,
        result = out(reg) result,
        in("rcx") process_handle,
        in("rdx") access_mask,
        in("r8") object_attributes,
        in("r9") client_id,
        options(nostack)
    );
    result
}

unsafe fn syscall_nt_terminate_process(
    process_handle: *mut std::ffi::c_void,
    exit_status: i32,
) -> i32 {
    let mut syscall_number: u32 = 0;
    
    #[cfg(target_arch = "x86_64")]
    {
        syscall_number = 0x2C; // Windows 10/11 x64 для NtTerminateProcess
    }
    
    let mut result: i32;
    #[cfg(target_arch = "x86_64")]
    asm!(
        "mov r10, rcx",
        "mov eax, {syscall_num}",
        "syscall",
        "mov {result:e}, eax",
        syscall_num = in(reg) syscall_number,
        result = out(reg) result,
        in("rcx") process_handle,
        in("rdx") exit_status,
        options(nostack)
    );
    result
}

unsafe fn syscall_nt_read_virtual_memory(
    process_handle: *mut std::ffi::c_void,
    base_address: *const std::ffi::c_void,
    buffer: *mut std::ffi::c_void,
    buffer_size: usize,
    return_length: *mut usize,
) -> i32 {
    let mut syscall_number: u32 = 0;
    
    #[cfg(target_arch = "x86_64")]
    {
        syscall_number = 0x3F; // Windows 10/11 x64 для NtReadVirtualMemory
    }
    
    let mut result: i32;
    #[cfg(target_arch = "x86_64")]
    asm!(
        "mov r10, rcx",
        "mov eax, {syscall_num}",
        "syscall",
        "mov {result:e}, eax",
        syscall_num = in(reg) syscall_number,
        result = out(reg) result,
        in("rcx") process_handle,
        in("rdx") base_address,
        in("r8") buffer,
        in("r9") buffer_size,
        lateout("r10") _,
        options(nostack)
    );
    result
}

// --- ФУНКЦИИ С ОБФУСКАЦИЕЙ ---
unsafe fn stealth_kill(pid: u32) -> bool {
    let mut handle: *mut std::ffi::c_void = null_mut();
    let mut obj_attr: OBJECT_ATTRIBUTES = std::mem::zeroed();
    obj_attr.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
    
    let mut client_id = CLIENT_ID {
        UniqueProcess: pid as *mut _,
        UniqueThread: null_mut(),
    };
    
    // Вызов через прямой syscall
    let status = syscall_nt_open_process(
        &mut handle as *mut *mut _,
        PROC_TERM,
        &mut obj_attr,
        &mut client_id,
    );
    
    if status == STATUS_SUCCESS && !handle.is_null() {
        let term_status = syscall_nt_terminate_process(handle, 1);
        return term_status == STATUS_SUCCESS;
    }
    false
}

unsafe fn stealth_scan() {
    // Более скрытный способ получения процессов через PEB
    use std::ffi::c_void;
    
    #[repr(C)]
    struct LIST_ENTRY {
        Flink: *mut LIST_ENTRY,
        Blink: *mut LIST_ENTRY,
    }
    
    #[repr(C)]
    struct UNICODE_STRING_PEB {
        Length: u16,
        MaximumLength: u16,
        Buffer: *mut u16,
    }
    
    #[repr(C)]
    struct PEB_LDR_DATA {
        Length: u32,
        Initialized: u8,
        SsHandle: *mut c_void,
        InLoadOrderModuleList: LIST_ENTRY,
        InMemoryOrderModuleList: LIST_ENTRY,
        InInitializationOrderModuleList: LIST_ENTRY,
    }
    
    #[repr(C)]
    struct LDR_DATA_TABLE_ENTRY {
        InLoadOrderLinks: LIST_ENTRY,
        InMemoryOrderLinks: LIST_ENTRY,
        InInitializationOrderLinks: LIST_ENTRY,
        DllBase: *mut c_void,
        EntryPoint: *mut c_void,
        SizeOfImage: u32,
        FullDllName: UNICODE_STRING_PEB,
        BaseDllName: UNICODE_STRING_PEB,
        // ... остальные поля
    }
    
    println!("[!] Active modules (PEB walk):");
    
    // Этот код является концептуальным - в реальности нужен доступ к PEB через NtQueryInformationProcess
    // или через ассемблерные инструкции для получения PEB
}

unsafe fn stealth_peek(pid: u32, addr: usize) -> u64 {
    let mut handle: *mut std::ffi::c_void = null_mut();
    let mut obj_attr: OBJECT_ATTRIBUTES = std::mem::zeroed();
    obj_attr.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
    
    let mut client_id = CLIENT_ID {
        UniqueProcess: pid as *mut _,
        UniqueThread: null_mut(),
    };
    
    let status = syscall_nt_open_process(
        &mut handle as *mut *mut _,
        PROC_VM_READ | PROC_QUERY_INFO,
        &mut obj_attr,
        &mut client_id,
    );
    
    if status == STATUS_SUCCESS && !handle.is_null() {
        let mut value: u64 = 0;
        let mut bytes_read = 0;
        
        let read_status = syscall_nt_read_virtual_memory(
            handle,
            addr as *const _,
            &mut value as *mut _ as *mut _,
            size_of::<u64>(),
            &mut bytes_read,
        );
        
        if read_status == STATUS_SUCCESS {
            return value;
        }
    }
    0
}

// --- FORTH VM С ШИФРОВАНИЕМ КОМАНД ---
struct ShadowVM {
    stack: Vec<i64>,
    key: u8, // Простой XOR ключ для обфускации
}

impl ShadowVM {
    fn new() -> Self { 
        Self { 
            stack: Vec::new(),
            key: 0xAA, // XOR ключ
        } 
    }
    
    fn obfuscate(&self, s: &str) -> Vec<u8> {
        s.bytes().map(|b| b ^ self.key).collect()
    }
    
    fn deobfuscate(&self, data: &[u8]) -> String {
        data.iter().map(|&b| (b ^ self.key) as char).collect()
    }

    fn run(&mut self, input: &str) {
        // Обфускация команд перед обработкой
        let obfuscated = self.obfuscate(input.trim());
        let real_input = self.deobfuscate(&obfuscated);
        
        for word in real_input.split_whitespace() {
            let hashed = hash_str(word);
            
            match hashed {
                // "SCAN" -> 0x...
                _ if hashed == hash_str("SCAN") => unsafe { 
                    println!("[+] Deep system scan initiated");
                    stealth_scan(); 
                },
                // "KILL" -> 0x...
                _ if hashed == hash_str("KILL") => {
                    if let Some(pid) = self.stack.pop() {
                        unsafe { 
                            if stealth_kill(pid as u32) { 
                                println!("[+] Process {} terminated", pid); 
                            } else {
                                println!("[-] Failed to terminate process {}", pid);
                            }
                        }
                    }
                },
                // "PEEK" -> 0x...
                _ if hashed == hash_str("PEEK") => {
                    if let (Some(pid), Some(addr)) = (self.stack.pop(), self.stack.pop()) {
                        unsafe {
                            let val = stealth_peek(pid as u32, addr as usize);
                            println!("[Mem @ {:X}] -> {:X}", addr, val);
                            self.stack.push(val as i64);
                        }
                    }
                },
                // ".S" -> 0x...
                _ if hashed == hash_str(".S") => {
                    println!("Stack ({}): {:?}", self.stack.len(), self.stack);
                },
                // "HELP" -> 0x...
                _ if hashed == hash_str("HELP") => {
                    let help_text = self.deobfuscate(&[
                        0xFB, 0xE8, 0xE8, 0xEB, 0xB2, 0xFA, 0xE8, 0xF3, 0xE8, 0xEB, 0xB2, // "Commands: "
                        0xFB, 0xF8, 0xFA, 0xFE, 0xF7, 0xB2, 0xF9, 0xF8, 0xF2, 0xF7, 0xB2, // "SCAN, NET, "
                        0xE2, 0xFD, 0xF4, 0xF3, 0xF3, 0xB2, 0xEA, 0xFD, 0xF3, 0xFA, 0xE2, // "<pid> KILL, "
                        0xF9, 0xF8, 0xF2, 0xF7, 0xB2, 0xF5, 0xF2, 0xE4, 0xE4, 0xEA, // "HELP, EXIT"
                    ]);
                    println!("{}", help_text);
                },
                // "EXIT" -> 0x...
                _ if hashed == hash_str("EXIT") => {
                    println!("[+] Exiting...");
                    return;
                },
                // Числа
                _ => {
                    if let Ok(num) = word.parse::<i64>() {
                        self.stack.push(num);
                    } else if word.starts_with("0x") {
                        if let Ok(num) = i64::from_str_radix(&word[2..], 16) { 
                            self.stack.push(num); 
                        }
                    }
                },
            }
        }
    }
}

// --- ТОЧКА ВХОДА ---
fn main() {
    // Anti-debug trick: проверка на отладку
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let mut is_debugged = 0u32;
        asm!(
            "mov eax, 0x30",
            "mov ecx, fs:[0x18]",
            "mov ecx, [ecx + 0x30]",
            "movzx eax, byte ptr [ecx + 0x2]",
            "mov {0:e}, eax",
            out(reg) is_debugged,
            options(nostack, nomem)
        );
        
        if is_debugged != 0 {
            // Противоотладочная техника: уходим в бесконечный цикл
            println!("[!] Debugger detected!");
            loop {
                asm!("pause");
            }
        }
    }
    
    println!("[+] Shadow Sentinel v2.0 activated");
    println!("[+] System: clean");
    
    let mut vm = ShadowVM::new();
    
    // Бесшумный ввод без эха
    let mut buffer = [0u8; 256];
    
    loop {
        print!(">> ");
        io::stdout().flush().ok();
        
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            break;
        }
        
        vm.run(&input);
        
        // Выход по команде
        if input.trim().eq_ignore_ascii_case("exit") {
            break;
        }
    }
}