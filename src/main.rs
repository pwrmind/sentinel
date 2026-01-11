use std::ptr::null_mut;
use std::io::{self, Write};
use std::mem::size_of;
use std::arch::asm;
use std::slice;

// --- ХЕШИРОВАНИЕ СТРОК ДЛЯ ОБФУСКАЦИИ ---
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

// --- СТРУКТУРЫ NTAPI ---
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

// --- СТРУКТУРА ДЛЯ СИСТЕМНОЙ ИНФОРМАЦИИ ---
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
    handle_count: u32,
    session_id: u32,
    unique_process_key: *mut std::ffi::c_void,
    peak_virtual_size: usize,
    virtual_size: usize,
    page_fault_count: u32,
    peak_working_set_size: usize,
    working_set_size: usize,
    quota_peak_paged_pool_usage: usize,
    quota_paged_pool_usage: usize,
    quota_peak_non_paged_pool_usage: usize,
    quota_non_paged_pool_usage: usize,
    pagefile_usage: usize,
    peak_pagefile_usage: usize,
    private_page_count: usize,
}

// --- КОНСТАНТЫ ---
const PROC_TERM: u32 = 0x0001;
const PROC_VM_READ: u32 = 0x0010;
const PROC_QUERY_INFO: u32 = 0x0400;
const STATUS_SUCCESS: i32 = 0;
// Исправленная константа: 0xC0000004 в беззнаковом виде это 3221225476, в знаковом это -1073741820
const STATUS_INFO_LENGTH_MISMATCH: i32 = -1073741820i32; // 0xC0000004
const SYSTEM_PROCESS_INFORMATION: u32 = 5;

// --- СИСТЕМНЫЕ ВЫЗОВЫ ---
unsafe fn syscall_nt_open_process(
    process_handle: *mut *mut std::ffi::c_void,
    access_mask: u32,
    object_attributes: *mut ObjectAttributes,
    client_id: *mut ClientId,
) -> i32 {
    let syscall_number: u32 = 0x26;
    
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
    let syscall_number: u32 = 0x2C;
    
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
    let syscall_number: u32 = 0x3F;
    
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
    let syscall_number: u32 = 0x36;
    
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

// --- ОСНОВНЫЕ ФУНКЦИИ ---
unsafe fn stealth_kill(pid: u32) -> bool {
    let mut handle: *mut std::ffi::c_void = null_mut();
    let mut obj_attr: ObjectAttributes = std::mem::zeroed();
    obj_attr.length = size_of::<ObjectAttributes>() as u32;
    
    let mut client_id = ClientId {
        unique_process: pid as *mut _,
        unique_thread: null_mut(),
    };
    
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
    
    // Первый вызов для получения размера
    let status = syscall_nt_query_system_information(
        SYSTEM_PROCESS_INFORMATION,
        null_mut(),
        0,
        &mut buffer_size
    );
    
    // Проверяем на STATUS_INFO_LENGTH_MISMATCH или другие допустимые статусы
    if status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_SUCCESS {
        println!("[-] Failed to query system information: 0x{:X}", status as u32);
        return;
    }
    
    // Выделяем буфер с запасом
    let allocated_size = buffer_size.saturating_add(32768);
    let mut buffer = vec![0u8; allocated_size as usize];
    
    // Второй вызов для получения данных
    let status = syscall_nt_query_system_information(
        SYSTEM_PROCESS_INFORMATION,
        buffer.as_mut_ptr() as *mut _,
        allocated_size,
        &mut return_length
    );
    
    if status == STATUS_SUCCESS {
        println!("[+] Active processes:");
        println!("{:<8} | {:<30}", "PID", "Name");
        println!("{}", "-".repeat(45));
        
        let mut current = buffer.as_ptr() as *const SystemProcessInformation;
        let mut first = true;
        
        while !current.is_null() {
            let process = &*current;
            let pid = process.unique_process_id as usize;
            
            if pid != 0 || first {
                first = false;
                
                let process_name = if !process.image_name.buffer.is_null() && process.image_name.length > 0 {
                    let name_length = (process.image_name.length / 2) as usize;
                    let name_slice = slice::from_raw_parts(process.image_name.buffer, name_length);
                    let mut name = String::from_utf16_lossy(name_slice);
                    
                    if let Some(last_backslash) = name.rfind('\\') {
                        name = name[last_backslash + 1..].to_string();
                    }
                    name
                } else {
                    if pid == 0 { "System Idle".to_string() } else { "System".to_string() }
                };
                
                println!("{:<8} | {:<30}", pid, process_name);
            }
            
            if process.next_entry_offset == 0 {
                break;
            }
            
            current = (current as *const u8).add(process.next_entry_offset as usize) 
                as *const SystemProcessInformation;
        }
    } else {
        println!("[-] Failed to get process list: 0x{:X}", status as u32);
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

// --- FORTH VM ---
struct ShadowVM {
    stack: Vec<i64>,
}

impl ShadowVM {
    fn new() -> Self { 
        Self { 
            stack: Vec::new(),
        } 
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
                    println!("Commands:");
                    println!("  SCAN             - List all processes");
                    println!("  <pid> KILL       - Terminate process by PID");
                    println!("  <addr> <pid> PEEK - Read memory from process");
                    println!("  .S               - Show stack");
                    println!("  HELP             - Show this help");
                    println!("  EXIT             - Exit");
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
                    } else {
                        println!("[!] Unknown command: {}", word);
                    }
                },
            }
        }
    }
}

// --- ТОЧКА ВХОДА ---
fn main() {
    // Простая анти-отладка
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
            return;
        }
    }
    
    println!("[+] Shadow Sentinel v3.0");
    println!("[+] Type HELP for commands");
    
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