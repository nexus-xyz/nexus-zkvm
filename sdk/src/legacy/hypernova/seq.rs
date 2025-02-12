use crate::legacy::compile;
use crate::legacy::traits::*;
use crate::legacy::views::UncheckedView;
use crate::traits::*;

use crate::legacy::ark_serialize_utils::{ark_de, ark_se};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

use nexus_core_legacy::nvm::interactive::{eval, parse_elf, trace};
use nexus_core_legacy::nvm::memory::MerkleTrie;
use nexus_core_legacy::nvm::NexusVM;
use nexus_core_legacy::prover::hypernova::pp::{gen_vm_pp, load_pp, save_pp};
use nexus_core_legacy::prover::hypernova::prove_seq;
use nexus_core_legacy::prover::hypernova::types::IVCProof;
use nexus_core_legacy::prover::nova::srs::{
    get_min_srs_size, load_srs,
    test_srs::{gen_test_srs, save_srs},
};

use crate::error::{BuildError, ConfigurationError, IOError, PathError};
use nexus_core_legacy::prover::hypernova::error::{NovaProofError, ProofError};

// re-exports
/// Public parameters used to prove and verify zkVM executions.
pub use nexus_core_legacy::prover::hypernova::types::PP;

use nexus_core_legacy::prover::hypernova::types::SRS as SRSi;
/// Structured reference string (SRS) used to generate public parameters.
pub struct SRS(SRSi); // for some reason the compiler doesn't like us using this directly for trait instantiation, so we use a newtype-style indirection.

use std::marker::PhantomData;

// hard-coded number of vm instructions to pack per recursion step
const K: usize = 1;

/// Errors that occur while proving using HyperNova.
#[derive(Debug, Error)]
pub enum Error {
    /// An error occurred during parameter generation, execution, proving, or proof verification for the zkVM.
    #[error(transparent)]
    ProofError(#[from] ProofError),

    /// An error occurred during srs generation or use for the zkVM.
    #[error(transparent)]
    SRSError(#[from] NovaProofError), // the srs handling comes from the nova crate

    /// An error occurred building the guest program dynamically.
    #[error(transparent)]
    BuildError(#[from] BuildError),

    /// An error occurred reading or writing to the filesystem.
    #[error(transparent)]
    HostIOError(#[from] std::io::Error),

    /// An error occurred trying to parse a path for use with the filesystem.
    #[error(transparent)]
    PathError(#[from] PathError),

    /// An error occurred reading or writing to the zkVM input/output tapes.
    #[error(transparent)]
    GuestIOError(#[from] IOError),

    /// An error occured configuring the prover.
    #[error(transparent)]
    ConfigurationError(#[from] ConfigurationError),
}

/// Prover for the Nexus zkVM using HyperNova.
pub struct HyperNova<'a, C: Compute = Local> {
    vm: NexusVM<MerkleTrie>,
    pp: Option<&'a PP>,
    srs: Option<&'a SRS>,
    _compute: PhantomData<C>,
}

/// A verifiable proof of a zkVM execution. Also contains a view capturing the output of the machine.
///
/// **Warning**: The proof contains an _unchecked_ view. Please review [`UncheckedView`].
#[derive(Serialize, Deserialize)]
pub struct Proof<'a> {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    proof: IVCProof,
    #[serde(skip)]
    view: UncheckedView,
    #[serde(skip)]
    srs: Option<&'a SRS>,
    #[serde(skip)]
    pp: Option<&'a PP>,
}

macro_rules! setup {
    ($id:ty) => {
        impl<'a> Setup<'a> for $id {
            type Reference = SRS;
            type Parameters = PP;
            type Preprocessing = ();
            type Error = Error;

            fn setup_reference<'b: 'a>(
                &mut self,
                reference: &'b Self::Reference,
            ) -> Result<(), Self::Error> {
                self.srs = Some(reference);
                Ok(())
            }

            fn setup_parameters<'b: 'a>(
                &mut self,
                parameters: &'b Self::Parameters,
            ) -> Result<(), Self::Error> {
                self.pp = Some(parameters);
                Ok(())
            }

            fn detach(&mut self) {
                self.srs = None;
                self.pp = None;
            }

            fn reference(&self) -> Result<&'a Self::Reference, Self::Error> {
                if self.srs.is_none() {
                    return Err(Error::from(ConfigurationError::NotYetConfigured));
                } else {
                    Ok(self.srs.unwrap())
                }
            }

            fn parameters(&self) -> Result<&'a Self::Parameters, Self::Error> {
                if self.pp.is_none() {
                    return Err(Error::from(ConfigurationError::NotYetConfigured));
                } else {
                    Ok(self.pp.unwrap())
                }
            }

            fn preprocessing(&self) -> Result<Self::Preprocessing, Self::Error> {
                Ok(())
            }
        }
    };
}

setup!(HyperNova<'a, Local>);
setup!(Proof<'a>);

impl<'a> LegacyProver<'a> for HyperNova<'a, Local> {
    type Proof = Proof<'a>;
    type View = UncheckedView;

    fn new(elf_bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(HyperNova::<Local> {
            vm: parse_elf::<MerkleTrie>(elf_bytes).map_err(ProofError::from)?,
            srs: None,
            pp: None,
            _compute: PhantomData,
        })
    }

    fn compile(opts: &compile::CompileOpts) -> Result<Self, Self::Error> {
        let mut iopts = opts.to_owned();

        // if the user has not set the memory limit, default to 4mb
        if iopts.memlimit.is_none() {
            iopts.set_memlimit(4);
        }

        let elf_path = iopts.build(&compile::ForProver::Default)?;

        Self::new_from_file(&elf_path)
    }

    fn run_with_input<S>(mut self, private_input: &S) -> Result<Self::View, Self::Error>
    where
        S: Serialize + Sized,
    {
        self.vm.syscalls.set_input(
            postcard::to_stdvec(private_input)
                .map_err(IOError::from)?
                .as_slice(),
        );

        eval(&mut self.vm, false, false).map_err(ProofError::from)?;

        Ok(Self::View {
            out: self.vm.syscalls.get_output(),
            logs: self
                .vm
                .syscalls
                .get_log_buffer()
                .into_iter()
                .map(String::from_utf8)
                .collect::<Result<Vec<_>, _>>()
                .map_err(IOError::from)?,
        })
    }

    fn prove_with_input<S>(mut self, private_input: &S) -> Result<Self::Proof, Self::Error>
    where
        S: Serialize + Sized,
    {
        if self.pp.is_none() {
            return Err(Error::from(ConfigurationError::NotYetConfigured));
        }

        self.vm.syscalls.set_input(
            postcard::to_stdvec(private_input)
                .map_err(IOError::from)?
                .as_slice(),
        );

        let tr = trace(&mut self.vm, K, false).map_err(ProofError::from)?;

        Ok(Self::Proof {
            proof: prove_seq(self.pp.as_ref().unwrap(), tr)?,
            srs: self.srs,
            pp: self.pp,
            view: Self::View {
                out: self.vm.syscalls.get_output(),
                logs: self
                    .vm
                    .syscalls
                    .get_log_buffer()
                    .into_iter()
                    .map(String::from_utf8)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(IOError::from)?,
            },
        })
    }
}

impl Reference for SRS {
    type Error = Error;

    fn generate() -> Result<Self, Self::Error> {
        eprintln!("Using test reference generation, not for production use!!!");
        Ok(SRS(
            gen_test_srs(get_min_srs_size(K)?).map_err(ProofError::from)?
        ))
    }

    fn load(path: &Path) -> Result<Self, Self::Error> {
        if let Some(path_str) = path.to_str() {
            return Ok(SRS(load_srs(path_str).map_err(ProofError::from)?));
        }

        Err(Self::Error::PathError(
            crate::error::PathError::EncodingError,
        ))
    }

    fn save(reference: &Self, path: &Path) -> Result<(), Self::Error> {
        if let Some(path_str) = path.to_str() {
            let srs = &reference.0;
            return Ok(save_srs(srs.clone(), path_str).map_err(ProofError::from)?);
        }

        Err(Self::Error::PathError(
            crate::error::PathError::EncodingError,
        ))
    }
}

impl Parameters for PP {
    type Ref = SRS;
    type Error = Error;

    fn generate(reference: &Self::Ref) -> Result<Self, Self::Error> {
        eprintln!("Using test parameter generation, not for production use!!!");
        let srs = &reference.0;
        Ok(gen_vm_pp(K, srs, &())?)
    }

    fn load(path: &Path) -> Result<Self, Self::Error> {
        if let Some(path_str) = path.to_str() {
            return Ok(load_pp(path_str)?);
        }

        Err(Self::Error::PathError(
            crate::error::PathError::EncodingError,
        ))
    }

    fn save(pp: &Self, path: &Path) -> Result<(), Self::Error> {
        if let Some(path_str) = path.to_str() {
            return Ok(save_pp(pp, path_str)?);
        }

        Err(Self::Error::PathError(
            crate::error::PathError::EncodingError,
        ))
    }
}

impl<'a> LegacyVerifiable<'a> for Proof<'a> {
    type View = UncheckedView;

    fn output<U: DeserializeOwned>(&self) -> Result<U, Self::Error> {
        Ok(Self::View::output::<U>(&self.view)?)
    }

    fn logs(&self) -> &Vec<String> {
        Self::View::logs(&self.view)
    }

    fn detach(&mut self) {
        self.srs = None;
        self.pp = None;
    }

    fn verify(&self) -> Result<(), Self::Error> {
        if self.pp.is_none() {
            return Err(Error::from(ConfigurationError::NotYetConfigured));
        }

        Ok(self
            .proof
            .verify(self.pp.as_ref().unwrap())
            .map_err(ProofError::from)?)
    }
}
