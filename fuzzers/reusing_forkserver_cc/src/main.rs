use core::{ptr::addr_of_mut, time::Duration};
use std::path::PathBuf;

use clap::Parser;
use libafl::{
    corpus::{Corpus, OnDiskCorpus},
    events::{SimpleEventManager, EVENTMGR_SIGHANDLER_STATE},
    executors::{forkserver::ForkserverExecutor, HasObservers},
    feedback_and_fast, feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, Input},
    monitors::{SimpleMonitor, OnDiskTOMLMonitor},
    mutators::{scheduled::havoc_mutations, tokens_mutations, StdScheduledMutator, Tokens},
    observers::{CanTrack, HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, StdState},
    HasMetadata,
};
use libafl_bolts::{
    os::unix_signals::setup_signal_handler,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, UnixShMemProvider},
    tuples::{tuple_list, Handled, MatchNameRef, Merge},
    AsSliceMut, Truncate,
};
use libafl_targets::EDGES_MAP_SIZE_IN_USE;
use nix::sys::signal::Signal;
use reusing_core::{FromSeed, ReusingEnergyStage, ReusingStage};

/// The commandline args this fuzzer accepts
#[derive(Debug, Parser)]
#[command(
    name = "forkserver_libafl_cc",
    about = "This is a simple example fuzzer to fuzz a executable instrumented by libafl_cc.",
    author = "ergrelet <ergrelet@users.noreply.github.com>"
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
        help = "Directory with the taint scan's output (value_pool.dict, \
                unsolved_condition, the .dtaint files); enables the reusing \
                stage and the energy split",
        short = 'r',
        long = "reusing-dir"
    )]
    reusing_dir: Option<PathBuf>,
}

#[allow(clippy::similar_names)]
pub fn main() {
    env_logger::init();

    // The harness launches this as a shell background job, which starts it
    // with SIGINT and SIGQUIT ignored; SimpleEventManager installs nothing, so
    // SIGINT (archive_campaigns.sh, `timeout --signal=INT`, docker stop via
    // entrypoint.sh's trap) would never stop it. LibAFL's own shutdown handler
    // exits on SIGINT/SIGTERM/SIGQUIT with CTRL_C_EXIT.
    unsafe { setup_signal_handler(addr_of_mut!(EVENTMGR_SIGHANDLER_STATE)) }
        .expect("Failed to install the shutdown signal handler");

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

    let mut tokens = Tokens::new();
    let mut executor = ForkserverExecutor::builder()
        .program(opt.executable)
        .debug_child(debug_child)
        .shmem_provider(&mut shmem_provider)
        .autotokens(&mut tokens)
        .parse_afl_cmdline(args)
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

    if let Some(reusing_dir) = opt.reusing_dir {
        // Everything in the corpus right now came in with the seeds: the
        // energy split pays finds over seeds, and this mark is how it tells
        // them apart. Loud failure on a missing scan dir for the same reason
        // ReusingStage::new is loud: an arm quietly running without its pool
        // is indistinguishable from the baseline afterwards.
        let seed_ids: Vec<_> = state.corpus().ids().collect();
        for id in seed_ids {
            state
                .corpus()
                .get(id)
                .unwrap()
                .borrow_mut()
                .add_metadata(FromSeed);
        }

        // The corpus names its entries by Input::generate_name, a hash of the
        // bytes, and forgets the seed's own filename -- which is the key the
        // scan wrote each .dtaint under. Hash every seed file the same way up
        // front so the stage can translate back. A duplicate seed (same
        // bytes, two names) keeps the first name; identical bytes got an
        // identical .dtaint anyway.
        let mut seed_names = std::collections::HashMap::new();
        for dir in &corpus_dirs {
            for entry in std::fs::read_dir(dir).expect("Failed to list the seed dir") {
                let path = entry.expect("Failed to list the seed dir").path();
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                let Ok(bytes) = std::fs::read(&path) else {
                    continue;
                };

                seed_names
                    .entry(BytesInput::new(bytes).generate_name(None))
                    .or_insert_with(|| name.to_string());
            }
        }

        let reusing_stage = ReusingStage::new(reusing_dir, seed_names)
            .expect("Failed to load the taint scan's output");

        // The one line that proves afterwards what this campaign loaded; the
        // AFL++ arm keeps the same record as reusing_load.log.
        let pool_stats = reusing_stage.pool().stats();
        println!(
            "Reusing pool loaded: {} entries ({} segments, {} patterns), {} unsolved sites, {} malformed lines",
            pool_stats.entries,
            pool_stats.segments,
            pool_stats.patterns,
            pool_stats.unsolved_sites,
            pool_stats.malformed
        );
        let mut stages = tuple_list!(
            reusing_stage,
            ReusingEnergyStage::new(StdMutationalStage::new(mutator))
        );

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
