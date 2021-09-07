use std::sync::Mutex;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Fd {
    real_fd: i32,
    opening: i32,
}

impl Fd {
    fn new() -> Fd {
        Fd {
            real_fd: 0,
            opening: 0,
        }
    }
}

struct FdStore {
    fd_map: [Fd;1024],
}

impl FdStore {
    fn new() -> FdStore {

        let mut store = FdStore {
            fd_map: [Fd::new(); 1024],
        };

        store.fd_map[0].real_fd = 0;
        store.fd_map[0].opening = 1;

        store.fd_map[1].real_fd = 1;
        store.fd_map[1].opening = 1;

        store.fd_map[2].real_fd = 2;
        store.fd_map[2].opening = 1;

        let mut i = 3;
        while i < 1024 {
            store.fd_map[i].opening = 0;
            i += 1;
        }

        store
    }

    fn set_fd(&mut self, index: i32, fd: i32) {
        self.fd_map[index as usize].real_fd = fd;
        self.fd_map[index as usize].opening = 1;
    }

    fn close_fd(&mut self, index: i32) {
        self.fd_map[index as usize].opening = 0;
    }
}

lazy_static::lazy_static! {
    static ref CACHE: Mutex<FdStore> = Mutex::new(FdStore::new());
}

fn physical_fd(index: i32) ->i32 {
    CACHE.lock().unwrap().fd_map[index as usize].real_fd
}

fn get_available_fd() -> i32 {
    let store = CACHE.lock().unwrap();

    let mut i = 0;
    while i < 1024 {
        if store.fd_map[i].opening == 0 {
            break;
        }
        i += 1;
    }
    if i < 1024 {
        return i as i32
    } else {
        -1
    }
}

fn set_available_fd(index: i32, fd: i32) {
    let mut store = CACHE.lock().unwrap();

    store.set_fd(index, fd)
}

fn close_available_fd(index: i32) {
    let mut store = CACHE.lock().unwrap();

    store.close_fd(index)
}

static UNUSED_VAR: i32 = 0x0eadffff;

pub fn handler(dir: u8, nr: u16, offset: *mut u32, mem: *mut u8) -> i32 {
    let masked_nr = nr & 0x8000;
    if masked_nr == 0 {
        return -1;
    }
    match nr {
        0x8000 => {
            return handler_open(dir, offset, mem);
        }
        0x8001 => {
            return handler_read(dir, offset, mem);
        }
        0x8002 => {
            return handler_write(dir, offset, mem);
        }
        0x8003 => {
            return handler_close(dir, offset, mem);
        }
        0x8004 => {
            return handler_lseek(dir, offset, mem);
        }
        0x8005 => {
            return handler_exit(dir, offset, mem);
        }
        _ => {
            return handler_panic(dir, offset, mem);
        }
    }
}

#[allow(dead_code)]
fn raw_str_check(ptr: *mut u8) -> usize {
    let mut off: usize = 0;
    loop {
        unsafe {
            if *(ptr.add(off)) == 0x0 {
                break;
            } else {
                off += 1;
            }
        }
    }
    off
}

fn handler_open(dir: u8, offset_ptr: *mut u32, mem: *mut u8) -> i32 {
    static mut RET: i32 = UNUSED_VAR;
    if dir == 1 {
        // out dir
        let offset = unsafe {
            *offset_ptr
        };
        
        unsafe {
            let ufd = get_available_fd();
            if ufd < 0 {
                RET = -1;
            }    

            let fd = libc::open(mem.add(offset as usize) as *mut libc::c_char, libc::O_RDONLY, 0) as i32;

            if fd < 0 {
                RET = 115;
            } else {
                set_available_fd(ufd, fd);
                RET = ufd;
            }
        }
    } else {
        
        // in dir
        unsafe {
            if RET == UNUSED_VAR {
                return -1;
            }

            std::ptr::write(offset_ptr, RET as u32);
            RET = UNUSED_VAR;
        };
    }

    0
}

fn handler_read(dir: u8, offset_ptr: *mut u32, mem: *mut u8) -> i32 {
    static mut RET: i32 = UNUSED_VAR;

    let offset = unsafe {
        *offset_ptr
    };

    if dir == 1 {
        unsafe {
            let kbuf: *mut u64 = mem.offset(offset as isize) as *mut u64;
    
            let ufd = *(kbuf.add(0)) as i32;
            let paddr = *(kbuf.add(1)) as u64;
            let nbytes = *(kbuf.add(2)) as u64;
    
            let fd = physical_fd(ufd);
    
            let dst = mem.offset(paddr as isize) as *mut u8;
    
            RET = libc::read(fd, dst as *mut libc::c_void, nbytes as usize) as i32;
            if RET < 0 {
                RET = 115;
            }
        }
    } else {
        // in dir
        unsafe {
            if RET == UNUSED_VAR {
                return -1;
            }

            std::ptr::write(offset_ptr, RET as u32);
            RET = UNUSED_VAR;
        }
    }

    0
}

fn handler_write(dir: u8, offset_ptr: *mut u32, mem: *mut u8) -> i32 {
    static mut RET: i32 = UNUSED_VAR;

    let offset = unsafe {
        *offset_ptr
    };

    if dir == 1 {
        unsafe {
            let kbuf: *mut u64 = mem.offset(offset as isize) as *mut u64;
    
            let ufd = *(kbuf.add(0)) as i32;
            let paddr = *(kbuf.add(1)) as u64;
            let nbytes = *(kbuf.add(2)) as u64;
    
            let fd = physical_fd(ufd);
    
            let dst = mem.offset(paddr as isize) as *mut u8;
    
            RET = libc::write(fd, dst as *mut libc::c_void, nbytes as usize) as i32;
            if RET < 0 {
                RET = 115;
            }
        } 
    } else {
        // in dir
        unsafe {
            if RET == UNUSED_VAR {
                return -1;
            }

            std::ptr::write(offset_ptr, RET as u32);

            RET = UNUSED_VAR;
        }  
    }

    0
}

fn handler_close(dir: u8, offset_ptr: *mut u32, _mem: *mut u8) -> i32 {
    static mut RET: i32 = UNUSED_VAR;

    if dir == 1 {
        let offset = unsafe {
            *offset_ptr
        };
    
        let ufd = offset;
        let fd = physical_fd(ufd as i32);
    
        close_available_fd(ufd as i32);
    
        unsafe {
            RET = libc::close(fd);
            if RET < 0 {
                RET = 115;
            }
        }
    } else {
        // in dir
        unsafe {
            if RET == UNUSED_VAR {
                return -1;
            }

            std::ptr::write(offset_ptr, RET as u32);
            RET = UNUSED_VAR;
        }
    }

    0
}

fn handler_lseek(dir: u8, offset_ptr: *mut u32, mem: *mut u8) -> i32 {
    static mut RET: i32 = UNUSED_VAR;

    if dir == 1 {
        let offset = unsafe {
            *offset_ptr
        };
    
        unsafe {
            let kbuf: *mut u32 = mem.offset(offset as isize) as *mut u32;
    
            let ufd = *(kbuf.add(0)) as i32;
            let off = *(kbuf.add(1)) as u32;
            let whence = *(kbuf.add(2)) as i32;
    
            let fd = physical_fd(ufd);
    
            RET = libc::lseek(fd, off as i64, whence) as i32;
            if RET < 0 {
                RET = 115;
            }
        }
    } else {
        // in dir
        unsafe {
            if RET == UNUSED_VAR {
                return -1;
            }

            std::ptr::write(offset_ptr, RET as u32);
            RET = UNUSED_VAR;
        }
    }

    0
}

fn handler_exit(_dir: u8, offset_ptr: *mut u32, _mem: *mut u8) -> i32 {
    let offset = unsafe {
        *offset_ptr
    };

    unsafe {
        let status = offset;
        println!("+++ exited with {} +++\n", status);
        libc::exit(0);
    }
}

fn handler_panic(_dir: u8, offset_ptr: *mut u32, _mem: *mut u8) -> i32 {
    let offset = unsafe {
        *offset_ptr
    };

    unsafe {
        println!("+++ panic with {} +++\n", offset);
        libc::exit(1);
    }
}

#[test]
fn parse_test() {
    use std::ptr::null_mut;
    use core::ptr::copy;

    let mem: *mut u8 = unsafe {
        libc::mmap(
            null_mut(),
            1024 as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_SHARED,
            -1,
            0,
        ) as *mut u8
    };

    let src = "test";

    unsafe {
        copy(src.as_bytes().as_ptr() as *mut u8, mem, src.len());
    }

    let offset = 0;

    let bin_data_len: usize;
    unsafe {
        let dst = mem.offset(offset as isize) as *mut u8;
        bin_data_len = raw_str_check(dst);
    };
    
    let bin_data: &[u8];
    unsafe {
        bin_data = std::slice::from_raw_parts(mem.add(offset as usize), bin_data_len as usize);
        let filename = str::from_utf8(bin_data).unwrap();
        assert!(src == filename);
    }
}