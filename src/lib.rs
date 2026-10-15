pub mod apply;
pub mod cli;
pub mod config;
pub mod config_export;
pub mod diagnostics;
pub mod diff;
pub mod display;
pub mod doctor;
pub mod error;
pub mod http_client;
pub mod import;
pub mod json_output;
pub mod jwt;
pub mod plugin_catalog;
pub mod policy;
pub mod reconcile;
pub mod review;
pub mod secrets;
pub mod state;
pub mod validate;
pub mod verdict;
pub mod verify;
pub mod version;

/// Per-thread allocation accounting for tests that bound memory use.
#[cfg(test)]
pub(crate) mod alloc_meter {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    thread_local! {
        static CURRENT: Cell<isize> = const { Cell::new(0) };
        static PEAK: Cell<isize> = const { Cell::new(0) };
    }

    fn record(delta: isize) {
        let _ = CURRENT.try_with(|current| {
            let now = current.get() + delta;
            current.set(now);
            let _ = PEAK.try_with(|peak| {
                if now > peak.get() {
                    peak.set(now);
                }
            });
        });
    }

    pub struct Meter;

    // SAFETY: every call is forwarded unchanged to the system allocator;
    // the bookkeeping only touches const-initialized thread-local cells,
    // which never allocate.
    unsafe impl GlobalAlloc for Meter {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let pointer = unsafe { System.alloc(layout) };
            if !pointer.is_null() {
                record(layout.size() as isize);
            }
            pointer
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            unsafe { System.dealloc(pointer, layout) };
            record(-(layout.size() as isize));
        }

        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            let moved = unsafe { System.realloc(pointer, layout, new_size) };
            if !moved.is_null() {
                record(new_size as isize - layout.size() as isize);
            }
            moved
        }
    }

    #[global_allocator]
    static METER: Meter = Meter;

    /// Run `f` and return its result with the peak bytes it held at once on
    /// this thread, beyond what was allocated before it started.
    pub fn peak_bytes<T>(f: impl FnOnce() -> T) -> (T, usize) {
        let start = CURRENT.with(Cell::get);
        PEAK.with(|peak| peak.set(start));
        let result = f();
        let peak = PEAK.with(Cell::get);
        (result, (peak - start).max(0) as usize)
    }
}
