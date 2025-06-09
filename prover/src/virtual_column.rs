// A virtual column can be used like a column, but it is not stored in the trace. Instead, it is computed a very-low degree polynomial of other columns.

use num_traits::{One, Zero};
use stwo_prover::{
    constraint_framework::EvalAtRow,
    core::{backend::simd::m31::PackedBaseField, fields::m31::BaseField},
};

use crate::{
    column::Column::{
        self, ImmC, IsAdd, IsAnd, IsAuipc, IsBeq, IsBge, IsBgeu, IsBlt, IsBltu, IsBne,
        IsCustomKeccak, IsEbreak, IsEcall, IsJal, IsJalr, IsLb, IsLbu, IsLh, IsLhu, IsLui, IsLw,
        IsMul, IsMulhu, IsOr, IsSb, IsSh, IsSll, IsSlt, IsSltu, IsSra, IsSrl, IsSub, IsSw, IsXor,
    },
    trace::{eval::trace_eval, eval::TraceEval, FinalizedTraces, TracesBuilder},
};

pub(crate) trait VirtualColumn<const N: usize> {
    /// Reading BaseField elements from the TracesBuilder during main trace filling
    ///
    /// Currently there is no automatic checks against using this method before filling in the relevant columns.
    fn read_from_traces_builder(traces: &TracesBuilder, row_idx: usize) -> [BaseField; N];
    /// Reading PackedBaseField elements from the FinalizedTraces during constraint generation
    fn read_from_finalized_traces(traces: &FinalizedTraces, vec_idx: usize)
        -> [PackedBaseField; N];
    /// Evaluating the virtual column during constraint evaluation
    fn eval<E: EvalAtRow>(trace_eval: &TraceEval<E>) -> [E::F; N];
}

/// Many virtual columns are just a sum of several columns
pub(crate) trait VirtualColumnForSum {
    /// columns to be added up
    fn columns() -> &'static [Column];
}

impl<S: VirtualColumnForSum> VirtualColumn<1> for S {
    fn read_from_traces_builder(traces: &TracesBuilder, row_idx: usize) -> [BaseField; 1] {
        let ret = S::columns().iter().fold(BaseField::zero(), |acc, &op| {
            let [is_op] = traces.column(row_idx, op);
            acc + is_op
        });
        [ret]
    }
    fn read_from_finalized_traces(
        traces: &FinalizedTraces,
        vec_idx: usize,
    ) -> [PackedBaseField; 1] {
        let ret = S::columns()
            .iter()
            .fold(PackedBaseField::zero(), |acc, &op| {
                let is_op = traces.get_base_column::<1>(op)[0].data[vec_idx];
                acc + is_op
            });
        [ret]
    }
    fn eval<E: EvalAtRow>(trace_eval: &TraceEval<E>) -> [E::F; 1] {
        let ret = S::columns().iter().fold(E::F::zero(), |acc, &op| {
            let [is_op] = trace_eval.column_eval(op);
            acc + is_op
        });
        [ret]
    }
}

pub(crate) struct IsTypeR;

impl IsTypeR {
    const TYPE_R_OPS: [Column; 12] = [
        IsAdd, IsSub, IsSlt, IsSltu, IsXor, IsOr, IsAnd, IsSll, IsSrl, IsSra, IsMul, IsMulhu,
    ];
}

// Type R cannot be made a VirtualColumnForSum because of the extra multiplication with (1 - ImmC)
impl VirtualColumn<1> for IsTypeR {
    fn read_from_traces_builder(traces: &TracesBuilder, row_idx: usize) -> [BaseField; 1] {
        let [imm_c] = traces.column(row_idx, ImmC);
        let ret = (BaseField::one() - imm_c)
            * Self::TYPE_R_OPS.iter().fold(BaseField::zero(), |acc, &op| {
                let [is_op] = traces.column(row_idx, op);
                acc + is_op
            });
        [ret]
    }
    fn read_from_finalized_traces(
        traces: &FinalizedTraces,
        vec_idx: usize,
    ) -> [PackedBaseField; 1] {
        let imm_c = traces.get_base_column::<1>(ImmC)[0].data[vec_idx];
        let ret = (PackedBaseField::one() - imm_c)
            * Self::TYPE_R_OPS
                .iter()
                .fold(PackedBaseField::zero(), |acc, &op| {
                    let is_op = traces.get_base_column::<1>(op)[0].data[vec_idx];
                    acc + is_op
                });
        [ret]
    }
    fn eval<E: EvalAtRow>(trace_eval: &TraceEval<E>) -> [E::F; 1] {
        let [imm_c] = trace_eval!(trace_eval, ImmC);
        let ret = (E::F::one() - imm_c)
            * Self::TYPE_R_OPS.iter().fold(E::F::zero(), |acc, &op| {
                let [is_op] = trace_eval.column_eval(op);
                acc + is_op
            });
        [ret]
    }
}

pub(crate) struct IsTypeU;

impl VirtualColumnForSum for IsTypeU {
    fn columns() -> &'static [Column] {
        &[IsLui, IsAuipc]
    }
}

pub(crate) struct IsAlu;

impl VirtualColumnForSum for IsAlu {
    fn columns() -> &'static [Column] {
        &[
            IsAdd, IsSub, IsSlt, IsSltu, IsXor, IsOr, IsAnd, IsSll, IsSrl, IsSra, IsMul, IsMulhu,
        ]
    }
}

pub(crate) struct IsLoad;

impl VirtualColumnForSum for IsLoad {
    fn columns() -> &'static [Column] {
        &[IsLb, IsLh, IsLw, IsLbu, IsLhu]
    }
}

pub(crate) struct IsTypeS;

impl VirtualColumnForSum for IsTypeS {
    fn columns() -> &'static [Column] {
        &[IsSb, IsSh, IsSw]
    }
}

pub(crate) struct IsTypeSys;

impl VirtualColumnForSum for IsTypeSys {
    fn columns() -> &'static [Column] {
        &[IsEcall, IsEbreak]
    }
}

/// is_alu_imm_no_shift = imm_c・(is_add + is_slt + is_sltu + is_xor + is_or + is_and)
pub(crate) struct IsAluImmNoShift;
impl IsAluImmNoShift {
    const COLS: &'static [Column] = &[IsAdd, IsSlt, IsSltu, IsXor, IsOr, IsAnd];
}

impl VirtualColumn<1> for IsAluImmNoShift {
    fn read_from_traces_builder(traces: &TracesBuilder, row_idx: usize) -> [BaseField; 1] {
        let [imm_c] = traces.column(row_idx, ImmC);

        let is_alu_imm_no_shift = imm_c
            * Self::COLS
                .iter()
                .map(|col| traces.column::<1>(row_idx, *col)[0])
                .sum::<BaseField>();

        [is_alu_imm_no_shift]
    }

    fn read_from_finalized_traces(
        traces: &FinalizedTraces,
        vec_idx: usize,
    ) -> [PackedBaseField; 1] {
        let imm_c = traces.get_base_column::<1>(ImmC)[0].data[vec_idx];

        let is_alu_imm_no_shift = imm_c
            * Self::COLS
                .iter()
                .map(|col| traces.get_base_column::<1>(*col)[0].data[vec_idx])
                .sum::<PackedBaseField>();
        [is_alu_imm_no_shift]
    }

    fn eval<E: EvalAtRow>(trace_eval: &TraceEval<E>) -> [E::F; 1] {
        let [imm_c] = trace_eval!(trace_eval, ImmC);

        let is_alu_imm_no_shift = imm_c
            * Self::COLS
                .iter()
                .map(|col| trace_eval.column_eval::<1>(*col)[0].clone())
                .reduce(|acc, x| acc + x)
                .expect("flag array is not empty");

        [is_alu_imm_no_shift]
    }
}

/// is_alu_imm_shift = imm_c・(is_sll + is_srl + is_sra)
pub(crate) struct IsAluImmShift;
impl IsAluImmShift {
    const COLS: &'static [Column] = &[IsSll, IsSrl, IsSra];
}

impl VirtualColumn<1> for IsAluImmShift {
    fn read_from_traces_builder(traces: &TracesBuilder, row_idx: usize) -> [BaseField; 1] {
        let [imm_c] = traces.column(row_idx, ImmC);

        let is_alu_imm_no_shift = imm_c
            * Self::COLS
                .iter()
                .map(|col| traces.column::<1>(row_idx, *col)[0])
                .sum::<BaseField>();

        [is_alu_imm_no_shift]
    }

    fn read_from_finalized_traces(
        traces: &FinalizedTraces,
        vec_idx: usize,
    ) -> [PackedBaseField; 1] {
        let imm_c = traces.get_base_column::<1>(ImmC)[0].data[vec_idx];

        let is_alu_imm_no_shift = imm_c
            * Self::COLS
                .iter()
                .map(|col| traces.get_base_column::<1>(*col)[0].data[vec_idx])
                .sum::<PackedBaseField>();
        [is_alu_imm_no_shift]
    }

    fn eval<E: EvalAtRow>(trace_eval: &TraceEval<E>) -> [E::F; 1] {
        let [imm_c] = trace_eval!(trace_eval, ImmC);

        let is_alu_imm_no_shift = imm_c
            * Self::COLS
                .iter()
                .map(|col| trace_eval.column_eval::<1>(*col)[0].clone())
                .reduce(|acc, x| acc + x)
                .expect("flag array is not empty");

        [is_alu_imm_no_shift]
    }
}

/// is_type_i_no_shift = is_load + is_alu_imm_no_shift + is_jalr
pub(crate) struct IsTypeINoShift;

impl VirtualColumn<1> for IsTypeINoShift {
    fn read_from_traces_builder(traces: &TracesBuilder, row_idx: usize) -> [BaseField; 1] {
        let [is_jalr] = traces.column(row_idx, IsJalr);
        let [is_load] = IsLoad::read_from_traces_builder(traces, row_idx);
        let [is_alu_imm_no_shift] = IsAluImmNoShift::read_from_traces_builder(traces, row_idx);

        let ret = is_load + is_alu_imm_no_shift + is_jalr;
        [ret]
    }

    fn read_from_finalized_traces(
        traces: &FinalizedTraces,
        vec_idx: usize,
    ) -> [PackedBaseField; 1] {
        let is_jalr = traces.get_base_column::<1>(IsJalr)[0].data[vec_idx];
        let [is_load] = IsLoad::read_from_finalized_traces(traces, vec_idx);
        let [is_alu_imm_no_shift] = IsAluImmNoShift::read_from_finalized_traces(traces, vec_idx);

        let ret = is_load + is_alu_imm_no_shift + is_jalr;
        [ret]
    }

    fn eval<E: EvalAtRow>(trace_eval: &TraceEval<E>) -> [E::F; 1] {
        let [is_jalr] = trace_eval!(trace_eval, IsJalr);
        let [is_load] = IsLoad::eval(trace_eval);
        let [is_alu_imm_no_shift] = IsAluImmNoShift::eval(trace_eval);

        let ret = is_load + is_alu_imm_no_shift + is_jalr;
        [ret]
    }
}

pub(crate) struct IsTypeJ;

impl VirtualColumnForSum for IsTypeJ {
    fn columns() -> &'static [Column] {
        &[IsJal]
    }
}

pub(crate) struct IsTypeB;

impl VirtualColumnForSum for IsTypeB {
    fn columns() -> &'static [Column] {
        &[IsBeq, IsBne, IsBlt, IsBge, IsBltu, IsBgeu]
    }
}

/// Instead of having is_pc_incremented as a separate column and having
/// `(is_alu + is_load + is_type_s + is_type_sys + is_type_u - is_pc_incremented) = 0`,
/// we can just have a virtual column is_pc_incremented. This change doesn't change the degree of any constraints.
pub(crate) struct IsPcIncremented;

impl VirtualColumn<1> for IsPcIncremented {
    fn read_from_traces_builder(traces: &TracesBuilder, row_idx: usize) -> [BaseField; 1] {
        let [is_alu] = IsAlu::read_from_traces_builder(traces, row_idx);
        let [is_load] = IsLoad::read_from_traces_builder(traces, row_idx);
        let [is_type_s] = IsTypeS::read_from_traces_builder(traces, row_idx);
        let [is_type_u] = IsTypeU::read_from_traces_builder(traces, row_idx);
        let [is_type_sys] = IsTypeSys::read_from_traces_builder(traces, row_idx);
        let [is_custom_keccak] = traces.column(row_idx, IsCustomKeccak);

        let [is_sys_halt] = traces.column(row_idx, Column::IsSysHalt);
        let ret = is_alu
            + is_load
            + is_type_s
            + is_type_sys * (BaseField::one() - is_sys_halt)
            + is_type_u
            + is_custom_keccak;
        [ret]
    }
    fn read_from_finalized_traces(
        traces: &FinalizedTraces,
        vec_idx: usize,
    ) -> [PackedBaseField; 1] {
        let is_alu = IsAlu::read_from_finalized_traces(traces, vec_idx)[0];
        let is_load = IsLoad::read_from_finalized_traces(traces, vec_idx)[0];
        let is_type_s = IsTypeS::read_from_finalized_traces(traces, vec_idx)[0];
        let is_type_u = IsTypeU::read_from_finalized_traces(traces, vec_idx)[0];
        let is_type_sys = IsTypeSys::read_from_finalized_traces(traces, vec_idx)[0];

        let is_sys_halt = traces.get_base_column::<1>(Column::IsSysHalt)[0].data[vec_idx];
        let is_custom_keccak = traces.get_base_column::<1>(Column::IsCustomKeccak)[0].data[vec_idx];
        let ret = is_alu
            + is_load
            + is_type_s
            + is_type_sys * (PackedBaseField::one() - is_sys_halt)
            + is_type_u
            + is_custom_keccak;
        [ret]
    }
    fn eval<E: EvalAtRow>(trace_eval: &TraceEval<E>) -> [E::F; 1] {
        let [is_alu] = IsAlu::eval(trace_eval);
        let [is_load] = IsLoad::eval(trace_eval);
        let [is_type_s] = IsTypeS::eval(trace_eval);
        let [is_type_u] = IsTypeU::eval(trace_eval);
        let [is_type_sys] = IsTypeSys::eval(trace_eval);

        let [is_sys_halt] = trace_eval!(trace_eval, Column::IsSysHalt);
        let [is_custom_keccak] = trace_eval!(trace_eval, Column::IsCustomKeccak);
        let ret = is_alu
            + is_load
            + is_type_s
            + is_type_sys * (E::F::one() - is_sys_halt)
            + is_type_u
            + is_custom_keccak;
        [ret]
    }
}

/// op-b-flag indicates whether or not the instruction's second operand (op-b) is a register index.
///
/// The definition of op-b-flag follows:
/// (is-sb + is-sh + is-sw + is-lb + is-lh + is-lw + is-lbu + is-lhu + is-jalr + is-add + is-sub + is-slt + is-sltu
/// + is-xor + is-or + is-and + is-sll + is-srl + is-sra+ is-beq + is-bne + is-blt + is-bge + is-bltu
/// + is-bgeu + is-ecall + is-ebreak + is-mul + is-mulh − op-b-flag) = 0
///
/// op-b-flag controls whether Reg1Address is used.
pub(crate) struct OpBFlag;

impl VirtualColumnForSum for OpBFlag {
    fn columns() -> &'static [Column] {
        &[
            IsSb, IsSh, IsSw, IsLb, IsLh, IsLw, IsLbu, IsLhu, IsJalr, IsAdd, IsSub, IsSlt, IsSltu,
            IsXor, IsOr, IsAnd, IsSll, IsSrl, IsSra, IsBeq, IsBne, IsBlt, IsBge, IsBltu, IsBgeu,
            IsMul, IsEcall, IsEbreak, IsMulhu,
        ]
    }
}

/// A virtual column that regulates the third register access
///
/// The third register access is done using ValueAEffective and Reg3Address.
/// The third access is mainly used for writing into rd (destination register).
/// The third register access is also used for reading from rs1 (first register argument) of type S and type B instructions.
pub(crate) struct Reg3Accessed;

// reg3_accessed =
// (is_type_s + is_type_b) +   // When reading from rs1
// (is_type_r + is_type_i + is_type_u + is_type_j)  + // For instructions with rd
// (is_type_sys)·(is_sys_priv_input + is_sys_heap_reset + is_sys_stack_reset) // For some syscalls
impl VirtualColumn<1> for Reg3Accessed {
    fn read_from_traces_builder(traces: &TracesBuilder, row_idx: usize) -> [BaseField; 1] {
        let [is_type_s] = IsTypeS::read_from_traces_builder(traces, row_idx);
        let [is_type_b] = IsTypeB::read_from_traces_builder(traces, row_idx);
        let [is_type_r] = IsTypeR::read_from_traces_builder(traces, row_idx);
        let [is_type_i] = IsTypeI::read_from_traces_builder(traces, row_idx);
        let [is_type_u] = IsTypeU::read_from_traces_builder(traces, row_idx);
        let [is_type_j] = IsTypeJ::read_from_traces_builder(traces, row_idx);
        let [is_type_sys] = IsTypeSys::read_from_traces_builder(traces, row_idx);
        let [is_sys_priv_input] = traces.column(row_idx, Column::IsSysPrivInput);
        let [is_sys_heap_reset] = traces.column(row_idx, Column::IsSysHeapReset);
        let [is_sys_stack_reset] = traces.column(row_idx, Column::IsSysStackReset);

        let ret = is_type_s
            + is_type_b
            + is_type_r
            + is_type_i
            + is_type_u
            + is_type_j
            + is_type_sys * (is_sys_priv_input + is_sys_heap_reset + is_sys_stack_reset);
        [ret]
    }
    fn read_from_finalized_traces(
        traces: &FinalizedTraces,
        vec_idx: usize,
    ) -> [PackedBaseField; 1] {
        let is_type_s = IsTypeS::read_from_finalized_traces(traces, vec_idx)[0];
        let is_type_b = IsTypeB::read_from_finalized_traces(traces, vec_idx)[0];
        let is_type_r = IsTypeR::read_from_finalized_traces(traces, vec_idx)[0];
        let is_type_i = IsTypeI::read_from_finalized_traces(traces, vec_idx)[0];
        let is_type_u = IsTypeU::read_from_finalized_traces(traces, vec_idx)[0];
        let is_type_j = IsTypeJ::read_from_finalized_traces(traces, vec_idx)[0];
        let is_type_sys = IsTypeSys::read_from_finalized_traces(traces, vec_idx)[0];
        let is_sys_priv_input =
            traces.get_base_column::<1>(Column::IsSysPrivInput)[0].data[vec_idx];
        let is_sys_heap_reset =
            traces.get_base_column::<1>(Column::IsSysHeapReset)[0].data[vec_idx];
        let is_sys_stack_reset =
            traces.get_base_column::<1>(Column::IsSysStackReset)[0].data[vec_idx];
        let ret = is_type_s
            + is_type_b
            + is_type_r
            + is_type_i
            + is_type_u
            + is_type_j
            + is_type_sys * (is_sys_priv_input + is_sys_heap_reset + is_sys_stack_reset);
        [ret]
    }
    fn eval<E: EvalAtRow>(trace_eval: &TraceEval<E>) -> [E::F; 1] {
        let [is_type_s] = IsTypeS::eval(trace_eval);
        let [is_type_b] = IsTypeB::eval(trace_eval);
        let [is_type_r] = IsTypeR::eval(trace_eval);
        let [is_type_i] = IsTypeI::eval(trace_eval);
        let [is_type_u] = IsTypeU::eval(trace_eval);
        let [is_type_j] = IsTypeJ::eval(trace_eval);
        let [is_type_sys] = IsTypeSys::eval(trace_eval);
        let [is_sys_priv_input] = trace_eval!(trace_eval, Column::IsSysPrivInput);
        let [is_sys_heap_reset] = trace_eval!(trace_eval, Column::IsSysHeapReset);
        let [is_sys_stack_reset] = trace_eval!(trace_eval, Column::IsSysStackReset);
        let ret = is_type_s
            + is_type_b
            + is_type_r
            + is_type_i
            + is_type_u
            + is_type_j
            + is_type_sys * (is_sys_priv_input + is_sys_heap_reset + is_sys_stack_reset);
        [ret]
    }
}
/// One on rows for type I instructions. Zero otherwise.
pub(crate) struct IsTypeI;

// is_type_i = is_load + is_jalr + is_alu_imm_no_shift + is_alu_imm_shift
impl VirtualColumn<1> for IsTypeI {
    fn read_from_traces_builder(traces: &TracesBuilder, row_idx: usize) -> [BaseField; 1] {
        let [is_load] = IsLoad::read_from_traces_builder(traces, row_idx);
        let [is_jalr] = traces.column(row_idx, IsJalr);
        let [is_alu_imm_no_shift] = IsAluImmNoShift::read_from_traces_builder(traces, row_idx);
        let [is_alu_imm_shift] = IsAluImmShift::read_from_traces_builder(traces, row_idx);

        let ret = is_load + is_jalr + is_alu_imm_no_shift + is_alu_imm_shift;
        [ret]
    }

    fn read_from_finalized_traces(
        traces: &FinalizedTraces,
        vec_idx: usize,
    ) -> [PackedBaseField; 1] {
        let [is_load] = IsLoad::read_from_finalized_traces(traces, vec_idx);
        let is_jalr = traces.get_base_column::<1>(IsJalr)[0].data[vec_idx];
        let [is_alu_imm_no_shift] = IsAluImmNoShift::read_from_finalized_traces(traces, vec_idx);
        let [is_alu_imm_shift] = IsAluImmShift::read_from_finalized_traces(traces, vec_idx);

        let ret = is_load + is_jalr + is_alu_imm_no_shift + is_alu_imm_shift;
        [ret]
    }

    fn eval<E: EvalAtRow>(trace_eval: &TraceEval<E>) -> [E::F; 1] {
        let [is_load] = IsLoad::eval(trace_eval);
        let [is_jalr] = trace_eval!(trace_eval, IsJalr);
        let [is_alu_imm_no_shift] = IsAluImmNoShift::eval(trace_eval);
        let [is_alu_imm_shift] = IsAluImmShift::eval(trace_eval);

        let ret = is_load + is_jalr + is_alu_imm_no_shift + is_alu_imm_shift;
        [ret]
    }
}
