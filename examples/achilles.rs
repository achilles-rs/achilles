use kvm_ioctls::{Kvm};
use kvm_ioctls::VcpuExit;
use kvm_bindings::kvm_segment;
use std::env;

use std::fs::{self, File};
use std::io::Read;

use core::ptr::copy;

use vmm::handler::handler;
use vmm::utils::dump_regs;

fn get_file_as_byte_vec(filename: &String) -> Vec<u8> {
    let mut f = File::open(&filename).expect("no file found");
    let metadata = fs::metadata(&filename).expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read(&mut buffer).expect("buffer overflow");

    buffer
}

fn main(){
    use std::io::Write;
    use std::slice;
    use std::ptr::null_mut;

    use kvm_bindings::kvm_userspace_memory_region;

    let ps_limit: u64 = 0x200000;
    let kernel_stack_size: u64 = 0x4000;

    let page_table_size: u64 = 0x5000;
    let max_kernel_size: u64 = ps_limit - page_table_size - kernel_stack_size;
    let mem_size: u64 = ps_limit * 0x2;

    let guest_addr = 0;
    let cr4_pae: u64 = 0x20;

    let args: Vec<String> = env::args().collect();

    let kernel_code = get_file_as_byte_vec(&args[1]);

    // 1. Instantiate KVM.
    let kvm = Kvm::new().unwrap();

    // 2. Create a VM.
    let vm = kvm.create_vm().unwrap();

    // 3. Initialize Guest Memory.
    let mem: *mut u8 = unsafe {
        libc::mmap(
            null_mut(),
            mem_size as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_SHARED,
            -1,
            0,
        ) as *mut u8
    };

    // Write the code in the guest memory. This will generate a dirty page.
    unsafe {
        let mut slice = slice::from_raw_parts_mut(mem, mem_size as usize);
        slice.write(&kernel_code).unwrap();
    }

    let slot = 0;
    // When initializing the guest memory slot specify the
    // `KVM_MEM_LOG_DIRTY_PAGES` to enable the dirty log.
    let mem_region = kvm_userspace_memory_region {
        slot,
        guest_phys_addr: 0,
        memory_size: mem_size as u64,
        userspace_addr: mem as u64,
        flags: 0,
    };
    unsafe { vm.set_user_memory_region(mem_region).unwrap() };

    unsafe {
        println!("mem = {:?}", *mem);
    }

    // 4. Create one vCPU.
    let vcpu_fd = vm.create_vcpu(0).unwrap();
    
    // 5. Initialize general purpose registers.
    let mut vcpu_regs = vcpu_fd.get_regs().unwrap();
    vcpu_regs.rip = guest_addr;
    vcpu_regs.rsp = ps_limit;
    vcpu_regs.rdi = ps_limit;
    vcpu_regs.rsi = mem_size - vcpu_regs.rdi; /* total length of free pages */
    vcpu_regs.rflags = 0x2;
    vcpu_fd.set_regs(&vcpu_regs).unwrap();

    // 6. setup paging
    let mut vcpu_sregs = vcpu_fd.get_sregs().unwrap();
    let pml4_addr: isize = max_kernel_size as isize;
    let pdp_addr: isize = pml4_addr + 0x1000;
    let pd_addr: isize = pdp_addr + 0x1000;
    unsafe {
        let plm4 = mem.offset(pml4_addr) as *mut u64;
        let pdp = mem.offset(pdp_addr) as *mut u64;
        let pd = mem.offset(pd_addr) as *mut u64;

        std::ptr::write(plm4, 7 | pdp_addr as u64);  // PDE64_PRESENT | PDE64_RW | PDE64_USER | pdpt_addr
        std::ptr::write(pdp, 7 | pd_addr as u64);    // PDE64_PRESENT | PDE64_RW | PDE64_USER |  pd_addr
        std::ptr::write(pd, 3 | 0x80);       //PDE64_PRESENT | PDE64_RW | PDE64_PS
    }

    vcpu_sregs.cr3 = pml4_addr as u64;
    vcpu_sregs.cr4 = cr4_pae;    //// CR4_PAE;
    vcpu_sregs.cr4 |= 0x600; // CR4_OSFXSR | CR4_OSXMMEXCPT; /* enable SSE instructions */
    vcpu_sregs.cr0 = 0x80050033; // CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG
    vcpu_sregs.efer = 0x500; // EFER_LME | EFER_LMA
    vcpu_sregs.efer |= 0x1; // EFER_SCE /* enable syscall instruction */
    vcpu_fd.set_sregs(&vcpu_sregs).unwrap();

    // 7. set segment regs
    let mut vcpu_segregs = vcpu_fd.get_sregs().unwrap();
    let mut sseg = kvm_segment {
        base: 0,
        limit: 0xffffffff,
        selector: 1 << 3,
        type_: 0xb, /* Code segment */
        present: 1,
        dpl: 0, /* Kernel: level 0 */
        db: 0,
        s: 1,
        l: 1,  /* long mode */
        g: 1,
        avl: 0,
        padding: 0,
        unusable: 0,
    };
    vcpu_segregs.cs = sseg;
    sseg.type_ = 0x3; /* Data segment */
    sseg.selector = 2 << 3;
    vcpu_segregs.ds = sseg;
    vcpu_segregs.es = sseg;
    vcpu_segregs.fs = sseg;
    vcpu_segregs.gs = sseg;
    vcpu_segregs.ss = sseg;
    vcpu_fd.set_sregs(&vcpu_segregs).unwrap();

    // 8. Copy Application code
    let args: Vec<String> = env::args().collect();
    let mut stack_regs = vcpu_fd.get_regs().unwrap();
    unsafe {
        let mut sp_off: u64 = stack_regs.rsp;
        let n = args.len();
        let arg_count = n - 2;

        let mut stack_argv: Vec<u64> = vec![];
        for i in 0..arg_count {
            let index = n - 1 - i;
            let para = &args[index];
            let para_len = para.len() + 1;

            sp_off -= para_len as u64;
            let dst = mem.offset(sp_off as isize) as *mut u8;

            copy(para.as_ptr() as *mut u8, dst, para_len);
            stack_argv.push(sp_off);
        }

        sp_off = sp_off & (0xfffffffffffffff0);

        sp_off -= 8;
        let dst = mem.offset(sp_off as isize) as *mut u64;
        std::ptr::write(dst, 0);

        for i in 0..arg_count {
            sp_off -= 8;
            let dst = mem.offset(sp_off as isize) as *mut u64;
            std::ptr::write(dst, stack_argv[i]);
        }

        sp_off -= 8;
        let dst = mem.offset(sp_off as isize) as *mut u64;
        std::ptr::write(dst, arg_count as u64);

        stack_regs.rsp = sp_off;
    }

    vcpu_fd.set_regs(&stack_regs).unwrap();

    let vcpu_mmap_size = kvm.get_vcpu_mmap_size().unwrap();
    let run_size = vm.run_size();
    println!("vcpu_mmap_size = {}, run_size = {}", vcpu_mmap_size, run_size);

    dump_regs(&vcpu_fd);
    // 9. Run code on the vCPU.
    loop {
        match vcpu_fd.run().expect("run failed") {
            VcpuExit::IoIn(addr, data) => {
                let offset: *mut u32 = data.as_ptr() as *mut u32;

                let res = handler(0, addr, offset, mem);
                if res < 0 {
                    println!("Hypercall handler: {:?}", addr);
                }
            }
            VcpuExit::IoOut(addr, data) => {
                let offset: *mut u32 = data.as_ptr() as *mut u32;

                let res = handler(1, addr, offset, mem);
                if res < 0 {
                    println!("Hypercall handler: {:?}", addr);
                }
            }
            VcpuExit::MmioRead(addr, _data) => {
                println!(
                    "Received an MMIO Read Request for the address {:#x}.",
                    addr,
                );
            }
            VcpuExit::MmioWrite(addr, _data) => {
                println!(
                    "Received an MMIO Write Request to the address {:#x}.",
                    addr,
                );
                // The code snippet dirties 1 page when it is loaded in memory
                let dirty_pages_bitmap = vm.get_dirty_log(slot, mem_size as usize).unwrap();
                let dirty_pages = dirty_pages_bitmap
                    .into_iter()
                    .map(|page| page.count_ones())
                    .fold(0, |dirty_page_count, i| dirty_page_count + i);
                assert_eq!(dirty_pages, 1);
                // Since on aarch64 there is not halt instruction,
                // we break immediately after the last known instruction
                // of the asm code example so that we avoid an infinite loop.
                #[cfg(target_arch = "aarch64")]
                break;
            }
            VcpuExit::Hlt => {
                break;
            }
            r => panic!("Unexpected exit reason: {:?}", r),
        }
    }
}
