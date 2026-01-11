use std::ptr::null_mut;
use std::ffi::c_void;
use std::io::{self, Write};
use ntapi::ntzwapi::{ZwQuerySystemInformation, ZwOpenProcess, ZwTerminateProcess, ZwReadVirtualMemory};
use ntapi::ntexapi::{SystemProcessInformation, SYSTEM_PROCESS_INFORMATION};
use ntapi::ntobapi::OBJECT_ATTRIBUTES;
use ntapi::ntapi_base::CLIENT_ID;
use windows::Win32::Foundation::{STATUS_SUCCESS, HANDLE};
use windows::Win32::System::Threading::{PROCESS_TERMINATE, PROCESS_VM_READ, PROCESS_QUERY_INFORMATION};
use windows::Win32::NetworkManagement::IpHelper::{GetExtendedTcpTable, TCP_TABLE_OWNER_PID_ALL};
use windows::Win32::Networking::WinSock::AF_INET;

// --- МИНИМАЛЬНЫЙ ВСТРОЕННЫЙ FORTH-ДВИЖОК ---
struct ForthVM {
    stack: Vec<i64>,
}

impl ForthVM {
    fn new() -> Self { Self { stack: Vec::new() } }

    fn run(&mut self, input: &str) {
        for word in input.split_whitespace() {
            match word {
                "SCAN" => unsafe { deep_scan() },
                "NET"  => unsafe { scan_network() },
                "KILL" => if let Some(pid) = self.stack.pop() {
                    unsafe { if kill_process(pid as usize) { println!("[+] Killed {}", pid); } }
                },
                "PEEK" => if let (Some(pid), Some(addr)) = (self.stack.pop(), self.stack.pop()) {
                    unsafe {
                        let val = peek_memory(pid as usize, addr as usize);
                        println!("[Mem @ {:X}] -> {:X}", addr, val);
                        self.stack.push(val as i64);
                    }
                },
                ".S" => println!("Stack: {:?}", self.stack),
                "HELP" => println!("SCAN, NET, <pid> KILL, <addr> <pid> PEEK, .S (stack)"),
                _ => if let Ok(num) = word.parse::<i64>() {
                    self.stack.push(num);
                } else if word.starts_with("0x") {
                    if let Ok(num) = i64::from_str_radix(&word[2..], 16) { self.stack.push(num); }
                },
            }
        }
    }
}

// --- СИСТЕМНЫЕ ФУНКЦИИ (ИСПРАВЛЕННЫЕ) ---

unsafe fn kill_process(pid: usize) -> bool {
    let mut handle = HANDLE(std::ptr::null_mut());
    let mut obj_attr: OBJECT_ATTRIBUTES = std::mem::zeroed();
    obj_attr.Length = std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32;
    let mut client_id = CLIENT_ID { UniqueProcess: pid as *mut c_void, UniqueThread: null_mut() };
    
    if ZwOpenProcess(&mut handle.0 as *mut *mut c_void, PROCESS_TERMINATE.0, &mut obj_attr, &mut client_id) == STATUS_SUCCESS.0 {
        return ZwTerminateProcess(handle.0, 1) == STATUS_SUCCESS.0;
    }
    false
}

unsafe fn deep_scan() {
    let mut buffer_size = 0;
    let _ = ZwQuerySystemInformation(SystemProcessInformation, null_mut(), 0, &mut buffer_size);
    let mut buffer = vec![0u8; buffer_size as usize + 8192];
    if ZwQuerySystemInformation(SystemProcessInformation, buffer.as_mut_ptr() as *mut c_void, buffer.len() as u32, &mut buffer_size) == STATUS_SUCCESS.0 {
        let mut current_ptr = buffer.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;
        loop {
            let proc_info = &*current_ptr;
            let pid = proc_info.UniqueProcessId as usize;
            let name = if !proc_info.ImageName.Buffer.is_null() {
                String::from_utf16_lossy(std::slice::from_raw_parts(proc_info.ImageName.Buffer, (proc_info.ImageName.Length / 2) as usize))
            } else { "System".into() };
            println!("  ID: {:<6} | {}", pid, name);
            if proc_info.NextEntryOffset == 0 { break; }
            current_ptr = (current_ptr as *const u8).add(proc_info.NextEntryOffset as usize) as *const SYSTEM_PROCESS_INFORMATION;
        }
    }
}

unsafe fn scan_network() {
    use windows::Win32::NetworkManagement::IpHelper::MIB_TCPTABLE_OWNER_PID;
    
    let mut table_size = 0;
    let _ = GetExtendedTcpTable(Some(std::ptr::null_mut()), &mut table_size, false, AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0);
    let mut buffer = vec![0u8; table_size as usize];
    if GetExtendedTcpTable(Some(buffer.as_mut_ptr() as *mut c_void), &mut table_size, false, AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0) == 0 {
        let table = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        println!("{:<15} | {:<15} | {:<10}", "Local", "Remote", "PID");
        for i in 0..table.dwNumEntries {
            let row = *table.table.as_ptr().add(i as usize);
            if row.dwRemoteAddr != 0 {
                let r = std::net::Ipv4Addr::from(u32::from_be(row.dwRemoteAddr));
                println!("{:<15} | {:<15} | {:<10}", "...", r, row.dwOwningPid);
            }
        }
    }
}

unsafe fn peek_memory(pid: usize, addr: usize) -> u64 {
    let mut handle = HANDLE(std::ptr::null_mut());
    let mut obj_attr: OBJECT_ATTRIBUTES = std::mem::zeroed();
    obj_attr.Length = std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32;
    let mut client_id = CLIENT_ID { UniqueProcess: pid as *mut c_void, UniqueThread: null_mut() };
    
    if ZwOpenProcess(&mut handle.0 as *mut *mut c_void, (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION).0, &mut obj_attr, &mut client_id) == STATUS_SUCCESS.0 {
        let mut value = 0u64;
        let mut read = 0;
        ZwReadVirtualMemory(handle.0, addr as *mut c_void, &mut value as *mut _ as *mut c_void, 8, &mut read);
        return value;
    }
    0
}

fn main() {
    println!("=== SENTINEL MONOLITH v1.0 (2026) ===");
    let mut vm = ForthVM::new();
    loop {
        print!("sentinel> "); io::stdout().flush().ok();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() || input.trim() == "exit" { break; }
        vm.run(&input);
    }
}