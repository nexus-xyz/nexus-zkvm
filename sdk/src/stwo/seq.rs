use crate::compile::Compile;
use crate::traits::*;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::marker::PhantomData;
use thiserror::Error;

use crate::error::{BuildError, ConfigurationError, IOError, PathError};

/// Errors that occur while proving using Stwo.
#[derive(Debug, Error)]
pub enum Error {
    /// An error occurred during proving a zkVM execution.
    #[error(transparent)]
    ProvingError(#[from] nexus_core::stwo::ProvingError),

    /// An error occurred verifying a claimed proof of a zkVM execution.
    #[error(transparent)]
    VerificationError(#[from] nexus_core::stwo::VerificationError),

    /// An error occurred building the guest program dynamically.
    #[error(transparent)]
    BuildError(#[from] BuildError),

    /// An error occurred reading or writing to the filesystem.
    #[error(transparent)]
    HostIOError(#[from] std::io::Error),

    /// An error occurred trying to parse a path for use with the filesystem.
    #[error(transparent)]
    PathError(#[from] PathError),

    /// An error occurred reading or writing to the zkVM input/output segments.
    #[error(transparent)]
    GuestIOError(#[from] IOError),

    /// An error occured executing the zkVM.
    #[error(transparent)]
    VMError(#[from] nexus_core::nvm::VMError),

    /// An error occured loading or parsing the ELF.
    #[error(transparent)]
    ElfError(#[from] nexus_core::nvm::ElfError),

    /// An error occured configuring the prover.
    #[error(transparent)]
    ConfigurationError(#[from] ConfigurationError),
}

/// Prover for the Nexus zkVM, when using Stwo.
pub struct Stwo<C: Compute = Local> {
    /// The program to be proven.
    pub elf: nexus_core::nvm::ElfFile,
    /// The associated data to prove with.
    pub ad: Vec<u8>,
    _compute: PhantomData<C>,
}

/// The Stwo proof, alongside machine configuration information needed for verification.
#[derive(Serialize, Deserialize)]
pub struct Proof {
    proof: nexus_core::stwo::Proof,
    memory_layout: nexus_core::nvm::internals::LinearMemoryLayout,
}

impl<C: Compute> ByGuestCompilation for Stwo<C>
where
    Stwo<C>: Prover,
    <Stwo<C> as Prover>::Error: From<BuildError>,
{
    /// Construct a new proving instance through dynamic compilation (see [`compile`](crate::compile)).
    fn compile(compiler: &mut impl Compile) -> Result<Self, <Self as Prover>::Error> {
        let elf_path = compiler.build()?;

        Self::new_from_file(&elf_path.to_string_lossy().into_owned())
    }
}

impl Prover for Stwo<Local> {
    type Proof = Proof;
    type View = nexus_core::nvm::View;
    type Error = Error;

    /// Construct a new proving instance.
    fn new(elf: &nexus_core::nvm::ElfFile) -> Result<Self, <Self as Prover>::Error> {
        Ok(Self {
            elf: elf.clone(),
            ad: Vec::new(),
            _compute: PhantomData,
        })
    }

    /// Set the associated data bytes to be bound into the proof.
    fn set_associated_data(&mut self, ad: &[u8]) -> Result<(), <Self as Prover>::Error> {
        self.ad = ad.to_vec();
        Ok(())
    }

    /// Run the zkVM on private input of type `S` and public input of type `T` and return a view of the execution output.
    fn run_with_input<S: Serialize + Sized, T: Serialize + DeserializeOwned + Sized>(
        &self,
        private_input: &S,
        public_input: &T,
    ) -> Result<Self::View, <Self as Prover>::Error> {
        let mut private_encoded = postcard::to_stdvec(&private_input).map_err(IOError::from)?;
        if !private_encoded.is_empty() {
            let private = private_input.to_owned();

            private_encoded = postcard::to_stdvec_cobs(&private).map_err(IOError::from)?;
            let private_padded_len = (private_encoded.len() + 3) & !3;

            assert!(private_padded_len >= private_encoded.len());
            private_encoded.resize(private_padded_len, 0x00); // cobs ignores 0x00 padding
        }

        let mut public_encoded = postcard::to_stdvec(&public_input).map_err(IOError::from)?;
        if !public_encoded.is_empty() {
            let public = public_input.to_owned();

            public_encoded = postcard::to_stdvec_cobs(&public).map_err(IOError::from)?;
            let public_padded_len = (public_encoded.len() + 3) & !3;

            assert!(public_padded_len >= public_encoded.len());
            public_encoded.resize(public_padded_len, 0x00); // cobs ignores 0x00 padding
        }

        let (view, _) = nexus_core::nvm::k_trace(
            self.elf.clone(),
            self.ad.as_slice(),
            public_encoded.as_slice(),
            private_encoded.as_slice(),
            1,
        )?; // todo: run without tracing?

        Ok(view)
    }

    /// Run the zkVM on private input of type `S` and public input of type `T` and return a verifiable proof, along with a view of the execution output.
    fn prove_with_input<S: Serialize + Sized, T: Serialize + DeserializeOwned + Sized>(
        self,
        private_input: &S,
        public_input: &T,
    ) -> Result<(Self::View, Self::Proof), <Self as Prover>::Error> {
        let mut private_encoded = postcard::to_stdvec(&private_input).map_err(IOError::from)?;
        if !private_encoded.is_empty() {
            let private = private_input.to_owned();

            private_encoded = postcard::to_stdvec_cobs(&private).map_err(IOError::from)?;
            let private_padded_len = (private_encoded.len() + 3) & !3;

            assert!(private_padded_len >= private_encoded.len());
            private_encoded.resize(private_padded_len, 0x00); // cobs ignores 0x00 padding
        }

        let mut public_encoded = postcard::to_stdvec(&public_input).map_err(IOError::from)?;
        if !public_encoded.is_empty() {
            let public = public_input.to_owned();

            public_encoded = postcard::to_stdvec_cobs(&public).map_err(IOError::from)?;
            let public_padded_len = (public_encoded.len() + 3) & !3;

            assert!(public_padded_len >= public_encoded.len());
            public_encoded.resize(public_padded_len, 0x00); // cobs ignores 0x00 padding
        }

        let (view, trace) = nexus_core::nvm::k_trace(
            self.elf.clone(),
            self.ad.as_slice(),
            public_encoded.as_slice(),
            private_encoded.as_slice(),
            1,
        )?;
        let proof = nexus_core::stwo::prove(&trace, &view)?;

        Ok((
            view,
            Proof {
                proof,
                memory_layout: trace.memory_layout,
            },
        ))
    }
}

impl Verifiable for Proof {
    type View = nexus_core::nvm::View;
    type Error = Error;

    fn get_memory_layout(&self) -> &nexus_core::nvm::internals::LinearMemoryLayout {
        &self.memory_layout
    }

    fn verify(&self, view: &Self::View) -> Result<(), <Self as Verifiable>::Error> {
        nexus_core::stwo::verify(self.proof.clone(), view)?;
        Ok(())
    }

    fn size_estimate(&self) -> usize {
        self.proof.size_estimate()
    }
}
