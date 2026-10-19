use libafl_targets::{map_shared_memory, start_forkserver};

/// Called automatically before main() via .init_array, so targets without
/// __AFL_INIT() (e.g. unibench binaries) also get a forkserver.
#[no_mangle]
#[link_section = ".init_array"]
pub static FORKSERVER_INIT: extern "C" fn() = libafl_start_forkserver;

#[no_mangle]
pub extern "C" fn libafl_start_forkserver() {
    // Only start the forkserver when the fuzzer has set up shared memory.
    // This prevents configure/build-time test binaries from exiting with an error.
    if std::env::var("__AFL_SHM_ID").is_err() {
        return;
    }
    // Map shared memory region for the edge coverage map
    map_shared_memory();
    // Start the forkserver
    start_forkserver();
}
