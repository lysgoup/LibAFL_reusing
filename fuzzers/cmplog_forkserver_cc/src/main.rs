//! The baseline forkserver fuzzer plus cmplog, nothing else.
//!
//! Identical to reusing_forkserver_cc's baseline arm (same scheduler,
//! feedback, mutator and mutational stage) with upstream's
//! `fuzzbench_forkserver_cmplog` block in front of havoc: colorization, a
//! tracing run against a cmplog-instrumented build of the target, then
//! AFL++'s RedQueen input-to-state mutator. Without `-c` it IS the baseline.

use core::time::Duration;
use std::path::PathBuf;

use clap::Parser;
use libafl::{
    corpus::{Corpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{forkserver::ForkserverExecutor, HasObservers},
    feedback_and_fast, feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    monitors::{OnDiskTOMLMonitor, SimpleMonitor},
    mutators::{
        scheduled::havoc_mutations, token_mutations::AFLppRedQueen, tokens_mutations,
        StdScheduledMutator, Tokens,
    },
    observers::{CanTrack, HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::{
        mutational::StdMutationalStage,
        ColorizationStage, IfStage,
    },
    state::{HasCorpus, HasCurrentTestcase, StdState},
    Error, HasMetadata,
};
use libafl_bolts::{
    ownedref::OwnedRefMut,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, UnixShMemProvider},
    tuples::{tuple_list, Handled, Merge},
    AsSliceMut, Truncate,
};
use libafl_targets::EDGES_MAP_SIZE_IN_USE;
use nix::sys::signal::Signal;

mod aflpp_cmplog;
use aflpp_cmplog::{
    AFLppCmpLogMap, AFLppCmpLogObserver, AFLppCmplogTracingStage, CappedMultiMutationalStage,
};

/// The commandline args this fuzzer accepts
#[derive(Debug, Parser)]
#[command(
    name = "cmplog_forkserver_cc",
    about = "The baseline forkserver fuzzer plus cmplog (RedQueen)"
)]
struct Opt {
    #[arg(
        help = "The instrumented binary we want to fuzz",
        name = "EXEC",
        required = true
    )]
    executable: String,

    #[arg(
        help = "The directory to read initial inputs from ('seeds')",
        name = "INPUT_DIR",
        required = true
    )]
    in_dir: PathBuf,

    #[arg(
        help = "Timeout for each individual execution, in milliseconds",
        short = 't',
        long = "timeout",
        default_value = "1200"
    )]
    timeout: u64,

    #[arg(
        help = "If not set, the child's stdout and stderror will be redirected to /dev/null",
        short = 'd',
        long = "debug-child",
        default_value = "false"
    )]
    debug_child: bool,

    #[arg(
        help = "Arguments passed to the target",
        name = "arguments",
        num_args(1..),
        allow_hyphen_values = true,
    )]
    arguments: Vec<String>,

    #[arg(
        help = "Signal used to stop child",
        short = 's',
        long = "signal",
        value_parser = str::parse::<Signal>,
        default_value = "SIGKILL"
    )]
    signal: Signal,

    #[arg(
        help = "Output directory for queue and crashes (created if absent)",
        short = 'o',
        long = "output-dir",
        default_value = "./output"
    )]
    output_dir: PathBuf,

    #[arg(
        help = "The same target built with AFL++'s cmplog instrumentation; \
                enables the colorization/tracing/RedQueen stages",
        short = 'c',
        long = "cmplog"
    )]
    cmplog: Option<String>,
}

#[allow(clippy::similar_names)]
pub fn main() {
    env_logger::init();

    const MAP_SIZE: usize = EDGES_MAP_SIZE_IN_USE;
    let opt = Opt::parse();

    let corpus_dirs: Vec<PathBuf> = [opt.in_dir].to_vec();

    let queue_dir = opt.output_dir.join("queue");
    let crashes_dir = opt.output_dir.join("crashes");
    std::fs::create_dir_all(&queue_dir).expect("Failed to create queue dir");
    std::fs::create_dir_all(&crashes_dir).expect("Failed to create crashes dir");

    // The unix shmem provider supported by LibAFL for shared memory
    let mut shmem_provider = UnixShMemProvider::new().unwrap();

    // The coverage map shared between observer and executor
    let mut shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();
    // let the forkserver know the shmid
    shmem.write_to_env("__AFL_SHM_ID").unwrap();
    let shmem_buf = shmem.as_slice_mut();

    // Create an observation channel using the signals map
    let edges_observer = unsafe {
        HitcountsMapObserver::new(StdMapObserver::new("shared_mem", shmem_buf)).track_indices()
    };

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    // Feedback to rate the interestingness of an input
    let mut feedback = feedback_or!(
        MaxMapFeedback::new(&edges_observer),
        TimeFeedback::new(&time_observer)
    );

    // A feedback to choose if an input is a solution or not
    let mut objective = feedback_and_fast!(
        CrashFeedback::new(),
        MaxMapFeedback::with_name("mapfeedback_metadata_objective", &edges_observer)
    );

    // create a State from scratch
    let mut state = StdState::new(
        StdRand::new(),
        // Corpus that will be evolved, saved to disk so it persists across runs
        OnDiskCorpus::<BytesInput>::new(&queue_dir).unwrap(),
        // Corpus in which we store solutions (crashes)
        OnDiskCorpus::<BytesInput>::new(&crashes_dir).unwrap(),
        &mut feedback,
        &mut objective,
    )
    .unwrap();

    let stats_file = opt.output_dir.join("stats.toml");

    // The Monitor trait define how the fuzzer stats are reported to the user
    let monitor = OnDiskTOMLMonitor::new(
        &stats_file,
        SimpleMonitor::with_user_monitor(|s| {
            println!("{s}");
        }),
    );

    // The event manager handle the various events generated during the fuzzing loop
    let mut mgr = SimpleEventManager::new(monitor);

    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let debug_child = opt.debug_child;
    let args = opt.arguments;
    let observer_handle = edges_observer.handle();

    // ColorizationStage keeps a handle, so build it before the observer moves
    // into the executor.
    let colorization = ColorizationStage::new(&edges_observer);

    let mut tokens = Tokens::new();
    let mut executor = ForkserverExecutor::builder()
        .program(opt.executable)
        .debug_child(debug_child)
        .shmem_provider(&mut shmem_provider)
        .autotokens(&mut tokens)
        .parse_afl_cmdline(args.clone())
        .coverage_map_size(MAP_SIZE)
        .timeout(Duration::from_millis(opt.timeout))
        .kill_signal(opt.signal)
        .build(tuple_list!(time_observer, edges_observer))
        .unwrap();

    if let Some(dynamic_map_size) = executor.coverage_map_size() {
        executor.observers_mut()[&observer_handle]
            .as_mut()
            .truncate(dynamic_map_size);
    }

    // In case the corpus is empty (on first run), reset
    if state.must_load_initial_inputs() {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
            .unwrap_or_else(|err| {
                panic!(
                    "Failed to load initial corpus at {:?}: {:?}",
                    &corpus_dirs, err
                )
            });
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    let signal_dir = queue_dir.join("signal");
    std::fs::create_dir_all(&signal_dir).unwrap();
    std::fs::File::create(signal_dir.join("dryrun_finish")).unwrap();

    state.add_metadata(tokens);

    // Setup a mutational stage with a basic bytes mutator
    let mutator =
        StdScheduledMutator::with_max_stack_pow(havoc_mutations().merge(tokens_mutations()), 6);

    if let Some(cmplog_exec) = opt.cmplog {
        // The one line that proves afterwards what this campaign ran with.
        println!("Cmplog binary: {cmplog_exec}");

        // The cmplog map shared between observer and executor
        let mut cmplog_shmem = shmem_provider.uninit_on_shmem::<AFLppCmpLogMap>().unwrap();
        // let the forkserver know the shmid
        cmplog_shmem.write_to_env("__AFL_CMPLOG_SHM_ID").unwrap();
        let cmpmap = unsafe { OwnedRefMut::from_shmem(&mut cmplog_shmem) };

        let cmplog_observer = AFLppCmpLogObserver::new("cmplog", cmpmap, true);
        let cmplog_ref = cmplog_observer.handle();

        // The tracing run replays an input the colorization stage prepared,
        // so it gets the ordinary timeout with the same x10 headroom upstream
        // gives it: a cmplog build is slower than the plain one.
        let cmplog_executor = ForkserverExecutor::builder()
            .program(cmplog_exec)
            .debug_child(debug_child)
            .shmem_provider(&mut shmem_provider)
            .parse_afl_cmdline(args)
            .timeout(Duration::from_millis(opt.timeout * 10))
            .kill_signal(opt.signal)
            .build(tuple_list!(cmplog_observer))
            .unwrap();

        let tracing = AFLppCmplogTracingStage::new(cmplog_executor, cmplog_ref);

        // Setup a randomic Input2State stage
        let rq = CappedMultiMutationalStage::new(AFLppRedQueen::with_cmplog_options(true, true));

        // Upstream runs the cmplog pipeline on an entry's second schedule:
        // the first visit calibrates nothing here, but keeping the gate the
        // same keeps the arms comparable.
        let cb = |_fuzzer: &mut _,
                  _executor: &mut _,
                  state: &mut StdState<_, OnDiskCorpus<BytesInput>, _, _>,
                  _event_manager: &mut _|
         -> Result<bool, Error> {
            let testcase = state.current_testcase()?;
            let res = testcase.scheduled_count() == 1; // let's try on the 2nd trial

            Ok(res)
        };

        let cmplog = IfStage::new(cb, tuple_list!(colorization, tracing, rq));

        // The order of the stages matter!
        let mut stages = tuple_list!(cmplog, StdMutationalStage::new(mutator));

        fuzzer
            .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
            .expect("Error in the fuzzing loop");
    } else {
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));

        fuzzer
            .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
            .expect("Error in the fuzzing loop");
    }
}
