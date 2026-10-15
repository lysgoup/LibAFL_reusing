use std::env;

use libafl_cc::{ClangWrapper, CompilerWrapper, LLVMPasses, ToolWrapper};

pub fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let mut dir = env::current_exe().unwrap();
        let wrapper_name = dir.file_name().unwrap().to_str().unwrap();

        let is_cpp = match wrapper_name[wrapper_name.len()-2..].to_lowercase().as_str() {
            "cc" => false,
            "++" | "pp" | "xx" => true,
            _ => panic!("Could not figure out if c or c++ wrapper was called. Expected {dir:?} to end with c or cxx"),
        };

        dir.pop();

        let mut cc = ClangWrapper::new();

        #[cfg(any(target_os = "linux", target_vendor = "apple"))]
        cc.add_pass(LLVMPasses::AutoTokens);

        if let Some(code) = cc
            .cpp(is_cpp)
            // silence the compiler wrapper output, needed for some configure scripts.
            .silence(true)
            // Always instrument: forkserver is injected via .init_array constructor,
            // so every compiled binary must have the passes and library linked.
            // __AFL_SHM_ID guard in libafl_start_forkserver() prevents configure
            // test programs from crashing when the fuzzer is not running.
            .need_libafl_arg(false)
            .parse_args(&args)
            .expect("Failed to parse the command line")
            // Enable libafl's coverage instrumentation
            .add_arg("-fsanitize-coverage=trace-pc-guard")
            // Imitate afl-cc's compile definitions
            .add_arg("-D__AFL_FUZZ_INIT()=int __afl_sharedmem_fuzzing = 1;extern unsigned int *__afl_fuzz_len;extern unsigned char *__afl_fuzz_ptr;unsigned char __afl_fuzz_alt[1048576];unsigned char *__afl_fuzz_alt_ptr = __afl_fuzz_alt;void libafl_start_forkserver(void)")
            .add_arg("-D__AFL_FUZZ_TESTCASE_BUF=(__afl_fuzz_ptr ? __afl_fuzz_ptr : __afl_fuzz_alt_ptr)")
            .add_arg("-D__AFL_FUZZ_TESTCASE_LEN=(__afl_fuzz_ptr ? *__afl_fuzz_len : (*__afl_fuzz_len = read(0, __afl_fuzz_alt_ptr, 1048576)) == 0xffffffff ? 0 : *__afl_fuzz_len)")
            .add_arg("-D__AFL_INIT()=libafl_start_forkserver()")
            // Link with libafl's forkserver implementation
            .link_staticlib(&dir, "libforkserver_libafl_cc")
            .run()
            .expect("Failed to run the wrapped compiler")
        {
            std::process::exit(code);
        }
    } else {
        panic!("LibAFL CC: No Arguments given");
    }
}
