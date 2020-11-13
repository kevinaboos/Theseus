//! memory management functions 

use hashbrown::HashMap;
use memory::{MappedPages, VirtualAddress};
use spin::Mutex;
use libm::ceil;
use core::ptr;
use core::ops::DerefMut;
use core::sync::atomic::{AtomicI32, Ordering};
use libc::*;

use crate::unistd::NULL;


lazy_static! {
    /// Stores the anonymous mappings created by mmap 
    pub static ref MMAP_MAPPINGS: Mutex<HashMap<VirtualAddress, MappedPages>> = Mutex::new(HashMap::new());
}


/// Creates a new mapping in the virtual address space.
/// 
/// # Arguments
/// * `addr`: Starting address of the new mapping. If it's NULL then the kernel decides the address of the new mapping.
/// * `length`: length of the mapping which must be greater than zero.
/// * `prot`: describes the desired memory protection of the mapping.
/// * `flags`: determines whether updates to the mapping are visible to other processes mapping the same region, and whether updates are carried through to the underlying file
/// * `fd`: file descriptor,
/// * `offset`: offset in the file where the mapping will start. It must be a multiple of the page size. 
/// 
/// Currently this function only implements anonymous mappings without a given address, and ignores all protection flags.
#[no_mangle]
pub extern fn mmap(addr: *mut c_void, length: size_t, prot: c_int, flags: c_int, fd: c_int, offset: off_t) -> *mut c_void {
    if length == 0 {
        return ptr::null_mut();
    }

    // Most systems support MAP_ANON and MAP_FIXED
    if flags & MAP_ANON == MAP_ANON {
        // allocate the number of pages
        let kernel_mmi_ref = memory::get_kernel_mmi_ref().unwrap();
        let allocator_ref = memory::get_frame_allocator_ref().unwrap();
        let allocated_pages = if addr != ptr::null_mut() {
            let vaddr = VirtualAddress::new(addr as usize).unwrap();
            memory::allocate_pages_by_bytes_at(vaddr, length as usize)
        } else {
            memory::allocate_pages_by_bytes(length as usize).ok_or("failed to allocate pages")
        }.unwrap();
        let mp = kernel_mmi_ref.lock().page_table.map_allocated_pages(
            allocated_pages,
            Default::default(), // TODO: FIXME: use proper flags
            allocator_ref.lock().deref_mut()
        ).unwrap();

        let vaddr = mp.start_address();
        MMAP_MAPPINGS.lock().insert(vaddr, mp);
        return vaddr.value() as *mut c_void;
    }

    ptr::null_mut()
}

/// Unmaps memory mapped pages
/// # Arguments
/// * `addr`: starting virtual address of the mapped pages
/// * `len`: the size of the mapping in bytes
#[no_mangle]
pub extern fn munmap(addr: *mut c_void, len: size_t) {
    match VirtualAddress::new(addr as usize) {
        Ok(x) => {MMAP_MAPPINGS.lock().remove(&x);},
        Err(x) => error!("libc::mman::munmap(): Couldn't retrieve mapping: {:?}", x),
    };
}
