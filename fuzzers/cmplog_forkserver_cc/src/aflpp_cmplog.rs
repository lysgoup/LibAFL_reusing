//! The cmplog map, observer and tracing stage of `libafl_targets`, with the
//! map laid out the way the pinned AFL++ (v5.03a, see
//! forkserver_libafl_cmplog-target/Dockerfile) writes it.
//!
//! `libafl_targets::AFLppCmpLogMap` matches no AFL++ release: it pairs the
//! 2-byte header AFL++ adopted in 2024-02 with the 32-byte operands it had
//! already left behind. Against v5.03a the map it allocates is 64 MiB where
//! the target writes 144 MiB, so every cmplog run past a hash bucket of about
//! 29127 segfaults, and the values that do land in range are read at the
//! wrong offsets. Only the layout below differs from upstream; the observer,
//! the metadata conversion and the tracing stage are upstream's, renamed.

use std::{
    borrow::Cow,
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};

use libafl::{
    executors::{Executor, ExitKind, HasObservers},
    inputs::{BytesInput, HasMutatorBytes, UsesInput},
    mutators::MultiMutator,
    observers::{
        cmp::{
            AFLppCmpLogHeader, AFLppCmpValuesMetadata, CmpMap, CmpObserver, CmpObserverMetadata,
            CmpValues,
        },
        Observer, ObserversTuple,
    },
    stages::{
        colorization::TaintMetadata,
        mutational::{MutatedTransform, MutatedTransformPost},
        RetryCountRestartHelper, Stage,
    },
    state::{HasCorpus, HasCurrentTestcase, HasExecutions, HasRand, UsesState},
    Error, Evaluator, HasMetadata, HasNamedMetadata,
};
use libafl_bolts::{
    ownedref::OwnedRefMut,
    tuples::{Handle, MatchNameRef},
    Named,
};

// AFL++ include/cmplog.h
const CMP_MAP_W: usize = 65536;
const CMP_MAP_H: usize = 32;
const CMP_MAP_RTN_H: usize = CMP_MAP_H / 2;
const CMP_TYPE_INS: u8 = 0;
// How many cmpfn_operands one log[k] row holds; only the first CMP_MAP_RTN_H
// are ever written, but the row stride has to stay that of log[k].
const CMP_MAP_RTN_ROW: usize =
    CMP_MAP_H * size_of::<AFLppCmpLogOperands>() / size_of::<AFLppCmpLogFnOperands>();

/// AFL++ `struct cmp_operands`
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct AFLppCmpLogOperands {
    v0: u64,
    v0_128: u64,
    v0_256_0: u64,
    v0_256_1: u64,
    v1: u64,
    v1_128: u64,
    v1_256_0: u64,
    v1_256_1: u64,
    unused: [u8; 8],
}

/// AFL++ `struct cmpfn_operands`
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct AFLppCmpLogFnOperands {
    v0: [u8; 32],
    v1: [u8; 32],
    v0_len: u8,
    v1_len: u8,
    addr_attr: u8,
    unused: [u8; 5],
}

/// AFL++ `log[CMP_MAP_W][CMP_MAP_H]`; a routine hook casts an instruction row
/// to `cmpfn_operands *` and writes its first `CMP_MAP_RTN_H` slots.
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub union AFLppCmpLogVals {
    operands: [[AFLppCmpLogOperands; CMP_MAP_H]; CMP_MAP_W],
    fn_operands: [[AFLppCmpLogFnOperands; CMP_MAP_RTN_ROW]; CMP_MAP_W],
}

/// AFL++ `struct cmp_map`
#[derive(Clone)]
#[repr(C, packed)]
pub struct AFLppCmpLogMap {
    headers: [AFLppCmpLogHeader; CMP_MAP_W],
    vals: AFLppCmpLogVals,
}

const _: () = assert!(size_of::<AFLppCmpLogOperands>() == 72);
const _: () = assert!(size_of::<AFLppCmpLogFnOperands>() == 72);
const _: () = assert!(
    size_of::<[AFLppCmpLogFnOperands; CMP_MAP_RTN_ROW]>()
        == size_of::<[AFLppCmpLogOperands; CMP_MAP_H]>()
);
const _: () = assert!(size_of::<AFLppCmpLogMap>() == CMP_MAP_W * 2 + CMP_MAP_W * CMP_MAP_H * 72);

impl Debug for AFLppCmpLogMap {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("AFLppCmpLogMap").finish_non_exhaustive()
    }
}

impl CmpMap for AFLppCmpLogMap {
    fn len(&self) -> usize {
        CMP_MAP_W
    }

    fn executions_for(&self, idx: usize) -> usize {
        self.headers[idx].hits() as usize
    }

    fn usable_executions_for(&self, idx: usize) -> usize {
        if self.headers[idx]._type() == CMP_TYPE_INS {
            if self.executions_for(idx) < CMP_MAP_H {
                self.executions_for(idx)
            } else {
                CMP_MAP_H
            }
        } else if self.executions_for(idx) < CMP_MAP_RTN_H {
            self.executions_for(idx)
        } else {
            CMP_MAP_RTN_H
        }
    }

    fn values_of(&self, idx: usize, execution: usize) -> Option<CmpValues> {
        if self.headers[idx]._type() == CMP_TYPE_INS {
            unsafe {
                match self.headers[idx].shape() {
                    0 => Some(CmpValues::U8((
                        self.vals.operands[idx][execution].v0 as u8,
                        self.vals.operands[idx][execution].v1 as u8,
                    ))),
                    1 => Some(CmpValues::U16((
                        self.vals.operands[idx][execution].v0 as u16,
                        self.vals.operands[idx][execution].v1 as u16,
                    ))),
                    3 => Some(CmpValues::U32((
                        self.vals.operands[idx][execution].v0 as u32,
                        self.vals.operands[idx][execution].v1 as u32,
                    ))),
                    7 => Some(CmpValues::U64((
                        self.vals.operands[idx][execution].v0,
                        self.vals.operands[idx][execution].v1,
                    ))),
                    // TODO handle 128 bits cmps
                    // other => panic!("Invalid CmpLog shape {}", other),
                    _ => None,
                }
            }
        } else {
            unsafe {
                let v0_len = self.vals.fn_operands[idx][execution].v0_len & (0x80 - 1);
                let v1_len = self.vals.fn_operands[idx][execution].v1_len & (0x80 - 1);
                Some(CmpValues::Bytes((
                    self.vals.fn_operands[idx][execution].v0[..(v0_len as usize)].to_vec(),
                    self.vals.fn_operands[idx][execution].v1[..(v1_len as usize)].to_vec(),
                )))
            }
        }
    }

    fn reset(&mut self) -> Result<(), Error> {
        // For performance, we reset just the headers
        self.headers.fill(AFLppCmpLogHeader { data: [0; 2] });

        Ok(())
    }
}

/// A [`CmpObserver`] observer for AFL++ redqueen
#[derive(Debug)]
pub struct AFLppCmpLogObserver<'a, S> {
    cmp_map: OwnedRefMut<'a, AFLppCmpLogMap>,
    size: Option<OwnedRefMut<'a, usize>>,
    name: Cow<'static, str>,
    add_meta: bool,
    original: <AFLppCmpValuesMetadata as CmpObserverMetadata<'a, AFLppCmpLogMap>>::Data,
    phantom: PhantomData<S>,
}

impl<'a, S> CmpObserver<'a, AFLppCmpLogMap, S, AFLppCmpValuesMetadata>
    for AFLppCmpLogObserver<'a, S>
where
    S: UsesInput + HasMetadata,
{
    /// Get the number of usable cmps (all by default)
    fn usable_count(&self) -> usize {
        match &self.size {
            None => self.cmp_map.as_ref().len(),
            Some(o) => *o.as_ref(),
        }
    }

    fn cmp_map(&self) -> &AFLppCmpLogMap {
        self.cmp_map.as_ref()
    }

    fn cmp_map_mut(&mut self) -> &mut AFLppCmpLogMap {
        self.cmp_map.as_mut()
    }

    fn cmp_observer_data(
        &self,
    ) -> <AFLppCmpValuesMetadata as CmpObserverMetadata<'a, AFLppCmpLogMap>>::Data {
        self.original
    }

    /// Add `AFLppCmpValuesMetadata` to the State including the logged values.
    /// This routine does a basic loop filtering because loop index cmps are not interesting.
    fn add_cmpvalues_meta(&mut self, state: &mut S)
    where
        S: HasMetadata,
    {
        #[allow(clippy::option_if_let_else)] // we can't mutate state in a closure
        let meta = if let Some(meta) = state.metadata_map_mut().get_mut::<AFLppCmpValuesMetadata>()
        {
            meta
        } else {
            state.add_metadata(AFLppCmpValuesMetadata::new());
            state
                .metadata_map_mut()
                .get_mut::<AFLppCmpValuesMetadata>()
                .unwrap()
        };

        if self.original {
            // If this observer is for original input, then we have run the un-mutated input
            // Clear orig_cmpvals
            meta.orig_cmpvals.clear();
            // Clear headers
            meta.headers.clear();
        } else {
            // If this observer is for the mutated input
            meta.new_cmpvals.clear();
        }

        let usable_count = self.usable_count();
        let cmp_observer_data = self.cmp_observer_data();

        meta.add_from(usable_count, self.cmp_map_mut(), cmp_observer_data);
    }
}

impl<'a, S> Observer<S> for AFLppCmpLogObserver<'a, S>
where
    S: UsesInput + HasMetadata,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        self.cmp_map.as_mut().reset()?;
        Ok(())
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        if self.add_meta {
            self.add_cmpvalues_meta(state);
        }
        Ok(())
    }
}

impl<'a, S> Named for AFLppCmpLogObserver<'a, S> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<'a, S> AFLppCmpLogObserver<'a, S> {
    /// Creates a new [`AFLppCmpLogObserver`] with the given name and map.
    #[must_use]
    pub fn new(
        name: &'static str,
        cmp_map: OwnedRefMut<'a, AFLppCmpLogMap>,
        add_meta: bool,
    ) -> Self {
        Self {
            name: Cow::from(name),
            size: None,
            cmp_map,
            add_meta,
            original: false,
            phantom: PhantomData,
        }
    }
    /// Setter for the flag if the executed input is a mutated one or the original one
    pub fn set_original(&mut self, v: bool) {
        self.original = v;
    }
}

impl<'a> CmpObserverMetadata<'a, AFLppCmpLogMap> for AFLppCmpValuesMetadata {
    type Data = bool;

    fn new_metadata() -> Self {
        Self::new()
    }

    fn add_from(
        &mut self,
        usable_count: usize,
        cmp_map: &mut AFLppCmpLogMap,
        cmp_observer_data: Self::Data,
    ) {
        let count = usable_count;
        for i in 0..count {
            let execs = cmp_map.usable_executions_for(i);
            if execs > 0 {
                if cmp_observer_data {
                    // Update header
                    self.headers.push((i, cmp_map.headers[i]));
                }

                // Recongize loops and discard if needed
                if execs > 4 {
                    let mut increasing_v0 = 0;
                    let mut increasing_v1 = 0;
                    let mut decreasing_v0 = 0;
                    let mut decreasing_v1 = 0;

                    let mut last: Option<CmpValues> = None;
                    for j in 0..execs {
                        if let Some(val) = cmp_map.values_of(i, j) {
                            if let Some(l) = last.and_then(|x| x.to_u64_tuple()) {
                                if let Some(v) = val.to_u64_tuple() {
                                    if l.0.wrapping_add(1) == v.0 {
                                        increasing_v0 += 1;
                                    }
                                    if l.1.wrapping_add(1) == v.1 {
                                        increasing_v1 += 1;
                                    }
                                    if l.0.wrapping_sub(1) == v.0 {
                                        decreasing_v0 += 1;
                                    }
                                    if l.1.wrapping_sub(1) == v.1 {
                                        decreasing_v1 += 1;
                                    }
                                }
                            }
                            last = Some(val);
                        }
                    }
                    // We check for execs-2 because the logged execs may wrap and have something like
                    // 8 9 10 3 4 5 6 7
                    if increasing_v0 >= execs - 2
                        || increasing_v1 >= execs - 2
                        || decreasing_v0 >= execs - 2
                        || decreasing_v1 >= execs - 2
                    {
                        continue;
                    }
                }

                let cmpmap_idx = i;
                let mut cmp_values = Vec::new();
                if cmp_observer_data {
                    // push into orig_cmpvals
                    for j in 0..execs {
                        if let Some(val) = cmp_map.values_of(i, j) {
                            cmp_values.push(val);
                        }
                    }
                    self.orig_cmpvals.insert(cmpmap_idx, cmp_values);
                } else {
                    // push into new_cmpvals
                    for j in 0..execs {
                        if let Some(val) = cmp_map.values_of(i, j) {
                            cmp_values.push(val);
                        }
                    }
                    self.new_cmpvals.insert(cmpmap_idx, cmp_values);
                }
            }
        }
    }
}

/// How many bytes the generated-mutant buffer may hold per testcase.
///
/// Upstream's `MultiMutationalStage` passes `max_count: None` to
/// [`MultiMutator::multi_mutate`], and `AFLppRedQueen` then materializes one
/// full copy of the input per candidate -- sites x hits x input positions --
/// before anything runs. On this experiment's saturated corpora (inputs up to
/// 1 MiB, a correctly-read 144 MiB cmp map) that buffer reached 166 GiB per
/// campaign and OOMed the box. AFL++'s own redqueen enumerates the same
/// candidates but executes each patch in place and keeps O(1) memory, so a
/// cap here is not a departure from AFL++, it is the batch-API tax.
///
/// A byte budget rather than a count: the cap `multi_mutate` takes is this
/// divided by the input size, so a jq-sized input (~18 KiB) keeps upstream
/// behavior in practice (~230k candidates) while a 1 MiB lame input is held
/// to ~4096 -- constant memory either way.
const REDQUEEN_MUTANT_BYTES: usize = 4 << 30;

/// Upstream's `MultiMutationalStage` with the one change described on
/// [`REDQUEEN_MUTANT_BYTES`]: `multi_mutate` gets a cap instead of `None`.
#[derive(Clone, Debug)]
pub struct CappedMultiMutationalStage<E, EM, I, M, Z> {
    name: Cow<'static, str>,
    mutator: M,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, I, Z)>,
}

/// The unique id for the capped multi mutational stage
static mut CAPPED_MULTI_MUTATIONAL_STAGE_ID: usize = 0;
/// The name for the capped multi mutational stage
pub static CAPPED_MULTI_MUTATIONAL_STAGE_NAME: &str = "cappedmultimutational";

impl<E, EM, I, M, Z> UsesState for CappedMultiMutationalStage<E, EM, I, M, Z>
where
    Z: UsesState,
{
    type State = Z::State;
}

impl<E, EM, I, M, Z> Named for CappedMultiMutationalStage<E, EM, I, M, Z> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<E, EM, I, M, Z> Stage<E, EM, Z> for CappedMultiMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Self::State>,
    EM: UsesState<State = Self::State>,
    M: MultiMutator<I, Self::State>,
    Z: Evaluator<E, EM>,
    Self::State: HasCorpus + HasRand + HasNamedMetadata,
    I: MutatedTransform<Self::Input, Self::State> + Clone + HasMutatorBytes,
{
    #[inline]
    fn should_restart(&mut self, state: &mut Self::State) -> Result<bool, Error> {
        // Make sure we don't get stuck crashing on a single testcase
        RetryCountRestartHelper::should_restart(state, &self.name, 3)
    }

    #[inline]
    fn clear_progress(&mut self, state: &mut Self::State) -> Result<(), Error> {
        RetryCountRestartHelper::clear_progress(state, &self.name)
    }

    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let mut testcase = state.current_testcase_mut()?;
        let Ok(input) = I::try_transform_from(&mut testcase, state) else {
            return Ok(());
        };
        drop(testcase);

        // The one line upstream has as `None`.
        let max_count = REDQUEEN_MUTANT_BYTES / input.bytes().len().max(1);
        let generated = self.mutator.multi_mutate(state, &input, Some(max_count))?;

        for new_input in generated {
            // Time is measured directly the `evaluate_input` function
            let (untransformed, post) = new_input.try_transform_into(state)?;
            let (_, corpus_id) = fuzzer.evaluate_input(state, executor, manager, untransformed)?;
            self.mutator.multi_post_exec(state, corpus_id)?;
            post.post_exec(state, corpus_id)?;
        }

        Ok(())
    }
}

impl<E, EM, M, Z> CappedMultiMutationalStage<E, EM, Z::Input, M, Z>
where
    Z: UsesState,
{
    /// Creates a new [`CappedMultiMutationalStage`]
    pub fn new(mutator: M) -> Self {
        // unsafe but impossible that you create two threads both instantiating this instance
        let stage_id = unsafe {
            let ret = CAPPED_MULTI_MUTATIONAL_STAGE_ID;
            CAPPED_MULTI_MUTATIONAL_STAGE_ID += 1;
            ret
        };
        Self {
            name: Cow::Owned(
                CAPPED_MULTI_MUTATIONAL_STAGE_NAME.to_owned()
                    + ":"
                    + stage_id.to_string().as_str(),
            ),
            mutator,
            phantom: PhantomData,
        }
    }
}

/// Trace with tainted input
#[derive(Clone, Debug)]
pub struct AFLppCmplogTracingStage<'a, EM, TE, Z>
where
    TE: UsesState,
{
    name: Cow<'static, str>,
    tracer_executor: TE,
    cmplog_observer_handle: Handle<AFLppCmpLogObserver<'a, <Self as UsesState>::State>>,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(EM, TE, Z)>,
}
/// The name for aflpp tracing stage
pub static AFLPP_CMPLOG_TRACING_STAGE_NAME: &str = "aflpptracing";

impl<EM, TE, Z> UsesState for AFLppCmplogTracingStage<'_, EM, TE, Z>
where
    TE: UsesState,
{
    type State = TE::State;
}

impl<EM, TE, Z> Named for AFLppCmplogTracingStage<'_, EM, TE, Z>
where
    TE: UsesState,
{
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<E, EM, TE, Z> Stage<E, EM, Z> for AFLppCmplogTracingStage<'_, EM, TE, Z>
where
    E: UsesState<State = Self::State>,
    TE: Executor<EM, Z> + HasObservers,
    Self::State:
        HasExecutions + HasCorpus + HasMetadata + UsesInput<Input = BytesInput> + HasNamedMetadata,
    EM: UsesState<State = Self::State>,
    Z: UsesState<State = Self::State>,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut TE::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        // First run with the un-mutated input
        let unmutated_input = state.current_input_cloned()?;

        if let Some(ob) = self
            .tracer_executor
            .observers_mut()
            .get_mut(&self.cmplog_observer_handle)
        {
            // This is not the original input,
            // Set it to false
            ob.set_original(true);
        }
        // I can't think of any use of this stage if you don't use AFLppCmpLogObserver
        // but do nothing ofcourse

        self.tracer_executor
            .observers_mut()
            .pre_exec_all(state, &unmutated_input)?;

        let exit_kind =
            self.tracer_executor
                .run_target(fuzzer, state, manager, &unmutated_input)?;

        self.tracer_executor
            .observers_mut()
            .post_exec_all(state, &unmutated_input, &exit_kind)?;

        // Second run with the mutated input
        let mutated_input = match state.metadata_map().get::<TaintMetadata>() {
            Some(meta) => BytesInput::from(meta.input_vec().as_ref()),
            None => return Err(Error::unknown("No metadata found")),
        };

        if let Some(ob) = self
            .tracer_executor
            .observers_mut()
            .get_mut(&self.cmplog_observer_handle)
        {
            // This is not the original input,
            // Set it to false
            ob.set_original(false);
        }
        // I can't think of any use of this stage if you don't use AFLppCmpLogObserver
        // but do nothing ofcourse

        self.tracer_executor
            .observers_mut()
            .pre_exec_all(state, &mutated_input)?;

        let exit_kind = self
            .tracer_executor
            .run_target(fuzzer, state, manager, &mutated_input)?;

        self.tracer_executor
            .observers_mut()
            .post_exec_all(state, &mutated_input, &exit_kind)?;

        Ok(())
    }

    fn should_restart(&mut self, state: &mut Self::State) -> Result<bool, Error> {
        // Tracing stage is always deterministic
        // don't restart
        RetryCountRestartHelper::no_retry(state, &self.name)
    }

    fn clear_progress(&mut self, state: &mut Self::State) -> Result<(), Error> {
        // TODO: this may need better resumption? (Or is it always used with a forkserver?)
        RetryCountRestartHelper::clear_progress(state, &self.name)
    }
}

impl<'a, EM, TE, Z> AFLppCmplogTracingStage<'a, EM, TE, Z>
where
    TE: UsesState,
{
    /// With cmplog observer
    pub fn new(
        tracer_executor: TE,
        observer_handle: Handle<AFLppCmpLogObserver<'a, TE::State>>,
    ) -> Self {
        let observer_name = observer_handle.name().clone();
        Self {
            name: Cow::Owned(
                AFLPP_CMPLOG_TRACING_STAGE_NAME.to_owned()
                    + ":"
                    + observer_name.into_owned().as_str(),
            ),
            cmplog_observer_handle: observer_handle,
            tracer_executor,
            phantom: PhantomData,
        }
    }
}
