use kvm_ioctls::VcpuFd;
use kvm_bindings::kvm_segment;

pub fn dump_seg(name: String, seg :&kvm_segment) {
    println!("{} base=0x{:016X} limit=0x{:08X} selector=0x{:04X} \
              type_=0x{:02X} dpl={} db = {} l = {} g={} avl={}",  
              name, seg.base, seg.limit, seg.selector, 
              seg.type_, seg.dpl, seg.db, seg.l, seg.g, seg.avl);
}

pub fn dump_regs(vcpu_fd: &VcpuFd) {
    let vcpu_regs = vcpu_fd.get_regs().unwrap();

    println!("rax\t0x{:016X} rbx\t0x{:016X} rcx\t0x{:016X}  rdx\t0x{:016X}", vcpu_regs.rax, vcpu_regs.rbx, vcpu_regs.rcx, vcpu_regs.rdx);
    println!("rsp\t0x{:016X} rbp\t0x{:016X} rsi\t0x{:016X}  rdi\t0x{:016X}", vcpu_regs.rsp, vcpu_regs.rbp, vcpu_regs.rsi, vcpu_regs.rdi);
    println!("rip\t0x{:016X} r8\t0x{:016X} r9\t0x{:016X}  r10\t0x{:016X}", vcpu_regs.rip, vcpu_regs.r8, vcpu_regs.r9, vcpu_regs.r10);
    println!("r11\t0x{:016X} r12\t0x{:016X} r13\t0x{:016X}  r14\t0x{:016X}", vcpu_regs.r11, vcpu_regs.r12, vcpu_regs.r13, vcpu_regs.r14);
    println!("r15\t0x{:016X} rflags\t0x{:016X}", vcpu_regs.r15, vcpu_regs.rflags);

    let vcpu_sregs = vcpu_fd.get_sregs().unwrap();
    dump_seg("cs".to_string(), &vcpu_sregs.cs);
    dump_seg("ds".to_string(), &vcpu_sregs.ds);
    dump_seg("es".to_string(), &vcpu_sregs.es);
    dump_seg("ss".to_string(), &vcpu_sregs.ss);
    dump_seg("fs".to_string(), &vcpu_sregs.fs);
    dump_seg("gs".to_string(), &vcpu_sregs.gs);

    println!("cr0\t0x{:016X}", vcpu_sregs.cr0);
    println!("cr3\t0x{:016X}", vcpu_sregs.cr3);
}
