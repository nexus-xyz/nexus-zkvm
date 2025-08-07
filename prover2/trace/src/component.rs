use std::rc::Rc;

use nexus_vm_prover_air_column::{AirColumn, PreprocessedAirColumn};
use stwo::{
    core::{fields::m31::BaseField, poly::circle::CanonicCoset, ColumnVec},
    prover::{
        backend::simd::{column::BaseColumn, m31::PackedBaseField, SimdBackend},
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use stwo_constraint_framework::{ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX};

/// Reference to a finalized column in a SIMD representation, or a constant.
#[derive(Debug, Clone)]
pub enum FinalizedColumn<'a> {
    /// Repeating constant value.
    Constant(BaseField),
    /// Reference to a finalized column.
    Column(&'a BaseColumn),
    /// Separately allocated column, not part of the component's trace.
    Virtual(Rc<BaseColumn>),
}

impl From<BaseField> for FinalizedColumn<'_> {
    fn from(value: BaseField) -> Self {
        Self::Constant(value)
    }
}

impl<'a> From<&'a BaseColumn> for FinalizedColumn<'a> {
    fn from(col: &'a BaseColumn) -> Self {
        Self::Column(col)
    }
}

impl FinalizedColumn<'_> {
    pub fn at(&self, index: usize) -> PackedBaseField {
        match self {
            Self::Constant(c) => (*c).into(),
            Self::Column(col) => col.data[index],
            Self::Virtual(col) => col.data[index],
        }
    }

    pub fn new_virtual(column: BaseColumn) -> Self {
        Self::Virtual(Rc::new(column))
    }
}

/// Intermediate representation of the component trace.
#[derive(Debug, Clone)]
pub struct ComponentTrace {
    pub log_size: u32,
    pub preprocessed_trace: Vec<BaseColumn>,
    pub original_trace: Vec<BaseColumn>,
}

impl ComponentTrace {
    pub fn log_size(&self) -> u32 {
        self.log_size
    }

    pub fn to_circle_evaluation(
        &self,
        trace_idx: usize,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let domain = CanonicCoset::new(self.log_size).circle_domain();
        let trace = match trace_idx {
            PREPROCESSED_TRACE_IDX => &self.preprocessed_trace,
            ORIGINAL_TRACE_IDX => &self.original_trace,
            _ => panic!("invalid trace index"),
        };
        let preprocessed = trace
            .iter()
            .map(|col| CircleEvaluation::new(domain, col.clone()))
            .collect();

        preprocessed
    }

    pub fn original_base_column<'a, const N: usize, C: AirColumn>(
        &'a self,
        col: C,
    ) -> [FinalizedColumn<'a>; N] {
        assert_eq!(col.size(), N, "column size mismatch");

        let offset = col.offset();
        std::array::from_fn(|i| (&self.original_trace[i + offset]).into())
    }

    pub fn preprocessed_base_column<'a, const N: usize, P: PreprocessedAirColumn>(
        &'a self,
        col: P,
    ) -> [FinalizedColumn<'a>; N] {
        assert_eq!(
            self.preprocessed_trace.len(),
            P::COLUMNS_NUM,
            "preprocessed trace length mismatch"
        );
        assert_eq!(col.size(), N, "column size mismatch");

        let offset = col.offset();
        std::array::from_fn(|i| (&self.preprocessed_trace[i + offset]).into())
    }
}

/// Returns an array of references to finalized column parts from original trace.
///
/// ```ignore
/// let [pc_0, pc_1] = original_base_column!(component_trace, Column::Pc);
/// ```
#[macro_export]
macro_rules! original_base_column {
    ($component_trace:expr, $col:expr) => {{
        $component_trace.original_base_column::<{ $col.const_size() }, _>($col)
    }};
}

/// Returns an array of references to finalized preprocessed column parts.
///
/// ```ignore
/// let [clk_0, clk_1] = preprocessed_base_column!(component_trace, PreprocessedColumn::Clk);
/// ```
#[macro_export]
macro_rules! preprocessed_base_column {
    ($component_trace:expr, $col:expr) => {{
        $component_trace.preprocessed_base_column::<{ $col.const_size() }, _>($col)
    }};
}
