use std::ptr::null_mut;
use std::io::{self, Write};
use std::mem::size_of;
use std::arch::asm;
use std::slice;

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

// --- СТРУКТУРЫ ДЛЯ NTAPI ---
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ObjectAttributes {
    pub length: u32,
    pub root_directory: *mut std::ffi::c_void,
    pub object_name: *mut UnicodeString,
    pub attributes: u32,
    pub security_descriptor: *mut std::ffi::c_void,
    pub security_quality_of_service: *mut std::ffi::c_void,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ClientId {
    pub unique_process: *mut std::ffi::c_void,
    pub unique_thread: *mut std::ffi::c_void,
}

// Структуры для NtQuerySystemInformation
#[repr(C)]
struct SystemProcessInformation {
    next_entry_offset: u32,
    number_of_threads: u32,
    working_set_private_size: u64,
    hard_fault_count: u32,
    number_of_threads_high_watermark: u32,
    cycle_time: u64,
    create_time: i64,
    user_time: i64,
    kernel_time: i64,
    image_name: UnicodeString,
    base_priority: i32,
    unique_process_id: *mut std::ffi::c_void,
    inherited_from_unique_process_id: *mut std::ffi::c_void,
    // ... остальные поля не нужны для нашего сканирования
}

// --- КОНСТАНТЫ ---
const PROC_TERM: u32 = 0x0001; // PROCESS_TERMINATE
const PROC_VM_READ: u32 = 0x0010;
const PROC_QUERY_INFO: u32 = 0x0400;
const STATUS_SUCCESS: i32 = 0;
const SYSTEM_PROCESS_INFORMATION: u32 = 5;

// --- ПРЯМЫЕ СИСТЕМНЫЕ ВЫЗОВЫ (Syscall) ---
unsafe fn syscall_nt_open_process(
    process_handle: *mut *mut std::ffi::c_void,
    access_mask: u32,
    object_attributes: *mut ObjectAttributes,
    client_id: *mut ClientId,
) -> i32 {
    let syscall_number: u32 = 0x26; // Windows 10/11 x64 для NtOpenProcess
    
    let result: i32;
    asm!(
        "mov r10, rcx",
        "mov eax, {0:e}",
        "syscall",
        in(reg) syscall_number,
        in("rcx") process_handle,
        in("rdx") access_mask,
        in("r8") object_attributes,
        in("r9") client_id,
        lateout("rax") result,
        options(nostack, preserves_flags)
    );
    result
}

unsafe fn syscall_nt_terminate_process(
    process_handle: *mut std::ffi::c_void,
    exit_status: i32,
) -> i32 {
    let syscall_number: u32 = 0x2C; // Windows 10/11 x64 для NtTerminateProcess
    
    let result: i32;
    asm!(
        "mov r10, rcx",
        "mov eax, {0:e}",
        "syscall",
        in(reg) syscall_number,
        in("rcx") process_handle,
        in("rdx") exit_status,
        lateout("rax") result,
        options(nostack, preserves_flags)
    );
    result
}

unsafe fn syscall_nt_read_virtual_memory(
    process_handle: *mut std::ffi::c_void,
    base_address: *const std::ffi::c_void,
    buffer: *mut std::ffi::c_void,
    buffer_size: usize,
    _return_length: *mut usize,
) -> i32 {
    let syscall_number: u32 = 0x3F; // Windows 10/11 x64 для NtReadVirtualMemory
    
    let result: i32;
    asm!(
        "mov r10, rcx",
        "mov eax, {0:e}",
        "syscall",
        in(reg) syscall_number,
        in("rcx") process_handle,
        in("rdx") base_address,
        in("r8") buffer,
        in("r9") buffer_size,
        lateout("rax") result,
        options(nostack, preserves_flags)
    );
    result
}

unsafe fn syscall_nt_query_system_information(
    system_information_class: u32,
    system_information: *mut std::ffi::c_void,
    system_information_length: u32,
    return_length: *mut u32,
) -> i32 {
    let syscall_number: u32 = 0x36; // Windows 10/11 x64 для NtQuerySystemInformation
    
    let result: i32;
    asm!(
        "mov r10, rcx",
        "mov eax, {0:e}",
        "syscall",
        in(reg) syscall_number,
        in("rcx") system_information_class,
        in("rdx") system_information,
        in("r8") system_information_length,
        in("r9") return_length,
        lateout("rax") result,
        options(nostack, preserves_flags)
    );
    result
}

// --- ФУНКЦИИ С ОБФУСКАЦИЕЙ ---
unsafe fn stealth_kill(pid: u32) -> bool {
    let mut handle: *mut std::ffi::c_void = null_mut();
    let mut obj_attr: ObjectAttributes = std::mem::zeroed();
    obj_attr.length = size_of::<ObjectAttributes>() as u32;
    
    let mut client_id = ClientId {
        unique_process: pid as *mut _,
        unique_thread: null_mut(),
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
    let mut buffer_size: u32 = 0;
    let mut return_length: u32 = 0;
    
    // Первый вызов - получаем необходимый размер буфера
    let status = syscall_nt_query_system_information(
        SYSTEM_PROCESS_INFORMATION,
        null_mut(),
        0,
        &mut buffer_size
    );
    
    if status != 0xC0000004 && status != 0 { // STATUS_INFO_LENGTH_MISMATCH или другой код
        println!("[-] Failed to query system information: 0x{:X}", status);
        return;
    }
    
    // Выделяем буфер с запасом
    let mut buffer = vec![0u8; (buffer_size + 16384) as usize];
    
    // Второй вызов - получаем данные
    let status = syscall_nt_query_system_information(
        SYSTEM_PROCESS_INFORMATION,
        buffer.as_mut_ptr() as *mut _,
        buffer_size + 16384,
        &mut return_length
    );
    
    if status == STATUS_SUCCESS {
        println!("[+] Active processes:");
        println!("{:<8} | {:<30} | {:<6}", "PID", "Name", "Threads");
        println!("{}", "-".repeat(50));
        
        let mut current = buffer.as_ptr() as *const SystemProcessInformation;
        
        loop {
            let process = &*current;
            let pid = process.unique_process_id as u32;
            
            if pid != 0 {
                let mut process_name = String::new();
                
                // Извлекаем имя процесса из UNICODE_STRING
                if !process.image_name.buffer.is_null() && process.image_name.length > 0 {
                    let name_length = (process.image_name.length / 2) as usize;
                    let name_slice = slice::from_raw_parts(process.image_name.buffer, name_length);
                    process_name = String::from_utf16_lossy(name_slice);
                    
                    // Берем только имя файла без пути
                    if let Some(last_backslash) = process_name.rfind('\\') {
                        process_name = process_name[last_backslash + 1..].to_string();
                    }
                } else {
                    process_name = "System".to_string();
                }
                
                println!("{:<8} | {:<30} | {:<6}", 
                    pid, 
                    process_name,
                    process.number_of_threads
                );
            }
            
            // Переходим к следующему процессу
            if process.next_entry_offset == 0 {
                break;
            }
            
            current = (current as *const u8).add(process.next_entry_offset as usize) 
                as *const SystemProcessInformation;
        }
    } else {
        println!("[-] Failed to get process list: 0x{:X}", status);
    }
}

unsafe fn stealth_peek(pid: u32, addr: usize) -> u64 {
    let mut handle: *mut std::ffi::c_void = null_mut();
    let mut obj_attr: ObjectAttributes = std::mem::zeroed();
    obj_attr.length = size_of::<ObjectAttributes>() as u32;
    
    let mut client_id = ClientId {
        unique_process: pid as *mut _,
        unique_thread: null_mut(),
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
    key: u8,
}

impl ShadowVM {
    fn new() -> Self { 
        Self { 
            stack: Vec::new(),
            key: 0xAA,
        } 
    }
    
    fn obfuscate(&self, s: &str) -> Vec<u8> {
        s.bytes().map(|b| b ^ self.key).collect()
    }
    
    fn deobfuscate(&self, data: &[u8]) -> String {
        data.iter().map(|&b| (b ^ self.key) as char).collect()
    }

    fn run(&mut self, input: &str) {
        let real_input = input.trim();
        
        for word in real_input.split_whitespace() {
            let hashed = hash_str(word);
            
            match hashed {
                _ if hashed == hash_str("SCAN") => unsafe { 
                    println!("[+] Deep system scan initiated");
                    stealth_scan(); 
                },
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
                _ if hashed == hash_str("PEEK") => {
                    if let (Some(pid), Some(addr)) = (self.stack.pop(), self.stack.pop()) {
                        unsafe {
                            let val = stealth_peek(pid as u32, addr as usize);
                            println!("[Mem @ {:X}] -> {:X}", addr, val);
                            self.stack.push(val as i64);
                        }
                    }
                },
                _ if hashed == hash_str(".S") => {
                    println!("Stack ({}): {:?}", self.stack.len(), self.stack);
                },
                _ if hashed == hash_str("HELP") => {
                    println!("Commands: SCAN, <pid> KILL, <addr> <pid> PEEK, .S, HELP, EXIT");
                },
                _ if hashed == hash_str("EXIT") => {
                    println!("[+] Exiting...");
                    return;
                },
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
        let is_debugged: u32;
        asm!(
            "mov eax, 0x30",
            "mov rcx, gs:[0x60]",
            "movzx eax, byte ptr [rcx + 0x2]",
            inout("eax") 0u32 => is_debugged,
            options(nostack, nomem, preserves_flags)
        );
        
        if is_debugged != 0 {
            println!("[!] Debugger detected!");
            // Противоотладочная техника: уходим в бесконечный цикл
            loop {
                asm!("pause");
            }
        }
    }
    
    println!("[+] Shadow Sentinel v2.0 activated");
    println!("[+] System: clean");
    
    let mut vm = ShadowVM::new();
    
    loop {
        print!(">> ");
        io::stdout().flush().ok();
        
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            break;
        }
        
        vm.run(&input);
        
        if input.trim().eq_ignore_ascii_case("exit") {
            break;
        }
    }
}