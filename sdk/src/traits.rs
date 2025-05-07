use crypto::digest::{Digest, OutputSizeUser};
use crypto_common::generic_array::{ArrayLength, GenericArray};
use nexus_common::constants::WORD_SIZE;
use serde::{de::DeserializeOwned, Serialize};
use std::path::Path;

use nexus_core::nvm::internals::*;

use crate::compile::*;
use crate::error::*;

/// A compute resource.
pub trait Compute {}

/// Use local compute to prove the zkVM.
pub enum Local {}
impl Compute for Local {}

/// A view of an execution, the correctness of which is guaranteed by the proving and checked by the verification.
pub trait CheckedView {
    /// Rebuild from constitutent parts, for use by the verifier during verification.
    fn new_from_expected(
        memory_layout: &LinearMemoryLayout,
        expected_public_input: &[u8],
        expected_exit_code: &[u8],
        expected_public_output: &[u8],
        expected_elf: &nexus_core::nvm::ElfFile,
        expected_ad: &[u8],
    ) -> Self;
}

impl CheckedView for nexus_core::nvm::View {
    fn new_from_expected(
        memory_layout: &LinearMemoryLayout,
        expected_public_input: &[u8],
        expected_exit_code: &[u8],
        expected_public_output: &[u8],
        expected_elf: &nexus_core::nvm::ElfFile,
        expected_ad: &[u8],
    ) -> Self {
        let emulator = LinearEmulator::default();

        // Replace custom instructions `rin` and `wou` with `lw` and `sw`.
        let instructions = expected_elf
            .instructions
            .iter()
            .map(|instr| convert_instruction(&emulator.executor.instruction_executor, instr))
            .collect();

        let converted_elf = nexus_core::nvm::ElfFile {
            instructions,
            ..expected_elf.clone()
        };

        let program_memory = elf_into_program_info(&converted_elf, memory_layout);

        let initial_memory = slice_into_io_entries::<MemoryInitializationEntry>(
            memory_layout.public_input_address_location(),
            &[
                memory_layout.public_input_start().to_le_bytes(),
                memory_layout.exit_code().to_le_bytes(), // the exit code is the first word of the output
            ]
            .concat(),
        )
        .iter()
        .chain(map_into_io_entries::<MemoryInitializationEntry>(&expected_elf.rom_image).iter())
        .chain(map_into_io_entries::<MemoryInitializationEntry>(&expected_elf.ram_image).iter())
        .chain(
            slice_into_io_entries::<MemoryInitializationEntry>(
                memory_layout.public_input_start(),
                &[
                    &(expected_public_input.len() as u32).to_le_bytes(),
                    expected_public_input,
                ]
                .concat(),
            )
            .iter(),
        )
        .copied()
        .collect();

        let exit_code = slice_into_io_entries::<PublicOutputEntry>(
            memory_layout.exit_code(),
            expected_exit_code,
        );

        let output_memory = slice_into_io_entries::<PublicOutputEntry>(
            memory_layout.public_output_start(),
            expected_public_output,
        );

        let static_memory_size =
            (&expected_elf.rom_image.len_bytes() + &expected_elf.ram_image.len_bytes()) * WORD_SIZE;

        Self::new(
            &Some(*memory_layout),
            &Vec::new(),
            &program_memory,
            &initial_memory,
            memory_layout.tracked_ram_size(static_memory_size),
            &exit_code,
            &output_memory,
            &expected_ad.to_vec(),
        )
    }
}

/// A view of an execution capturing the context needed for proof distribution and verification.
pub trait Viewable {
    /// Deserialize the public input used for the execution.
    fn public_input<T: Serialize + DeserializeOwned + Sized>(&self) -> Result<T, IOError>;

    /// Compute a digest over the public input used for the execution.
    fn public_input_digest<T: Serialize + DeserializeOwned + Sized, H: Digest>(
        &self,
    ) -> Result<GenericArray<u8, H::OutputSize>, IOError>
    where
        <H as OutputSizeUser>::OutputSize: ArrayLength<u8>,
    {
        Ok(H::digest(
            postcard::to_stdvec_cobs::<T>(&Self::public_input::<T>(self)?)
                .map_err(IOError::from)?
                .as_slice(),
        ))
    }

    /// Deserialize the exit code resulting from the execution.
    fn exit_code(&self) -> Result<u32, IOError>;

    /// Compute a digest over the public output resulting from the execution.
    fn exit_code_digest<H: Digest>(&self) -> Result<GenericArray<u8, H::OutputSize>, IOError>
    where
        <H as OutputSizeUser>::OutputSize: ArrayLength<u8>,
    {
        Ok(H::digest(Self::exit_code(self)?.to_le_bytes()))
    }

    /// Deserialize the public output resulting from the execution.
    fn public_output<U: Serialize + DeserializeOwned + Sized>(&self) -> Result<U, IOError>;

    /// Compute a digest over the public output resulting from the execution.
    fn public_output_digest<U: Serialize + DeserializeOwned + Sized, H: Digest>(
        &self,
    ) -> Result<GenericArray<u8, H::OutputSize>, IOError>
    where
        <H as OutputSizeUser>::OutputSize: ArrayLength<u8>,
    {
        Ok(H::digest(
            postcard::to_stdvec_cobs::<U>(&Self::public_output::<U>(self)?)
                .map_err(IOError::from)?
                .as_slice(),
        ))
    }

    /// Deserialize the associated data bound into the execution.
    fn associated_data(&self) -> Result<Vec<u8>, IOError>;

    /// Compute a digest over the associated data bound into the execution.
    fn associated_data_digest<H: Digest>(&self) -> Result<GenericArray<u8, H::OutputSize>, IOError>
    where
        <H as OutputSizeUser>::OutputSize: ArrayLength<u8>,
    {
        Ok(H::digest(Self::associated_data(self)?.as_slice()))
    }

    /// Recover any debug logs produced by the execution.
    fn logs(&self) -> Result<Vec<String>, IOError>;
}

impl Viewable for nexus_core::nvm::View {
    /// Deserialize the public input used for the execution.
    fn public_input<T: Serialize + DeserializeOwned + Sized>(&self) -> Result<T, IOError> {
        if let Some(mut bytes) = self.view_public_input() {
            Ok(postcard::from_bytes_cobs::<T>(&mut bytes).map_err(IOError::from)?)
        } else {
            Err(IOError::NotYetAvailableError)
        }
    }

    /// Deserialize the exit code resulting from the execution.
    fn exit_code(&self) -> Result<u32, IOError> {
        if let Some(bytes) = self.view_exit_code() {
            Ok(postcard::from_bytes::<u32>(&bytes).map_err(IOError::from)?)
        } else {
            Err(IOError::NotYetAvailableError)
        }
    }

    /// Deserialize the public output resulting from the execution.
    fn public_output<U: Serialize + DeserializeOwned + Sized>(&self) -> Result<U, IOError> {
        if let Some(mut bytes) = self.view_public_output() {
            Ok(postcard::from_bytes_cobs::<U>(&mut bytes).map_err(IOError::from)?)
        } else {
            Err(IOError::NotYetAvailableError)
        }
    }

    /// Deserialize the associated data bound into the execution.
    fn associated_data(&self) -> Result<Vec<u8>, IOError> {
        if let Some(bytes) = self.view_associated_data() {
            Ok(bytes)
        } else {
            Err(IOError::NotYetAvailableError)
        }
    }

    /// Recover any debug logs produced by the execution.
    fn logs(&self) -> Result<Vec<String>, IOError> {
        if let Some(bytes_vecs) = self.view_debug_logs() {
            Ok(bytes_vecs
                .iter()
                .map(|raw_log: &Vec<u8>| String::from_utf8_lossy(raw_log).to_string())
                .collect())
        } else {
            Err(IOError::NotYetAvailableError)
        }
    }
}

/// A proving instance that can be constructed through compiling a guest program.
pub trait ByGuestCompilation: Prover {
    /// Construct a new proving instance through dynamic compilation (see [`compile`](crate::compile)).
    fn compile(compiler: &mut impl Compile) -> Result<Self, Self::Error>;
}

/// A prover for the zkVM.
pub trait Prover: Sized {
    type Proof: Verifiable;
    type View: CheckedView;
    type Error: From<nexus_core::nvm::VMError>;

    /// Construct a new proving instance.
    fn new(elf: &nexus_core::nvm::ElfFile) -> Result<Self, <Self as Prover>::Error>;

    /// Construct a new proving instance from raw ELF bytes.
    fn new_from_bytes(elf_bytes: &[u8]) -> Result<Self, <Self as Prover>::Error> {
        Self::new(&nexus_core::nvm::ElfFile::from_bytes(elf_bytes)?)
    }

    /// Construct a new proving instance by reading an ELF file.
    fn new_from_file<P: AsRef<Path> + ?Sized>(path: &P) -> Result<Self, <Self as Prover>::Error> {
        Self::new(&nexus_core::nvm::ElfFile::from_path(&path)?)
    }

    /// Set the associated data bytes to be bound into the proof.
    fn set_associated_data(&mut self, ad: &[u8]) -> Result<(), <Self as Prover>::Error>;

    /// Run the zkVM and return a view of the execution output.
    fn run(&self) -> Result<Self::View, <Self as Prover>::Error> {
        Self::run_with_input::<(), ()>(self, &(), &())
    }

    /// Run the zkVM on private input of type `S` and public input of type `T` and return a view of the execution output.
    fn run_with_input<S: Serialize + Sized, T: Serialize + DeserializeOwned + Sized>(
        &self,
        private_input: &S,
        public_input: &T,
    ) -> Result<Self::View, <Self as Prover>::Error>;

    /// Run the zkVM and return a verifiable proof, along with a view of the execution output.
    fn prove(self) -> Result<(Self::View, Self::Proof), <Self as Prover>::Error>
    where
        Self: Sized,
    {
        Self::prove_with_input::<(), ()>(self, &(), &())
    }

    /// Run the zkVM on private input of type `S` and public input of type `T` and return a verifiable proof, along with a view of the execution output.
    fn prove_with_input<S: Serialize + Sized, T: Serialize + DeserializeOwned + Sized>(
        self,
        private_input: &S,
        public_input: &T,
    ) -> Result<(Self::View, Self::Proof), <Self as Prover>::Error>;
}

/// An object that can be configured with necessary parameters for proving and verification.
///
/// Currently only used by the legacy prover integrations.
pub trait Setup<'a> {
    /// Global parameters with trust assumptions.
    type Reference;
    /// Global parameters without trust assumptions.
    type Parameters;
    /// Program-specific parameters.
    type Preprocessing;
    type Error;

    /// Configure reference string.
    fn setup_reference<'b: 'a>(
        &mut self,
        reference: &'b Self::Reference,
    ) -> Result<(), Self::Error>;

    /// Configure parameters string.
    fn setup_parameters<'b: 'a>(
        &mut self,
        parameters: &'b Self::Parameters,
    ) -> Result<(), Self::Error>;

    /// Detach prover or proof from setup to make it easier to pass around without needing to manage lifetimes.
    fn detach(&mut self);

    /// Access reference through borrow.
    fn reference(&self) -> Result<&'a Self::Reference, Self::Error>;

    // todo: add support for reference digest

    /// Access parameters through borrow.
    fn parameters(&self) -> Result<&'a Self::Parameters, Self::Error>;

    // todo: add support for parameters digest

    /// Return preprocessing.
    fn preprocessing(&self) -> Result<Self::Preprocessing, Self::Error>;

    // todo: add support for preprocessing digest
}

/// A global, trust-assumption-reliant parameter set used for proving and verifying, such as a common or structured reference string (CRS/SRS).
///
/// Currently only used by the legacy prover integrations.
pub trait Reference {
    type Error;

    /// Generate reference.
    fn generate() -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Load reference from a file.
    fn load(path: &Path) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Save reference to a file.
    fn save(reference: &Self, path: &Path) -> Result<(), Self::Error>;
}

impl Reference for () {
    type Error = ConfigurationError;

    fn generate() -> Result<Self, Self::Error> {
        Err(ConfigurationError::NotApplicableOperation)
    }

    fn load(_path: &Path) -> Result<Self, Self::Error> {
        Err(ConfigurationError::NotApplicableOperation)
    }

    fn save(_reference: &Self, _path: &Path) -> Result<(), Self::Error> {
        Err(ConfigurationError::NotApplicableOperation)
    }
}

/// A global, no-trust-assumption parameter set used for proving and verifying.
///
/// Currently only used by the legacy prover integrations.
pub trait Parameters {
    type Ref: Reference;
    type Error;

    /// Generate parameters.
    fn generate(reference: &Self::Ref) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Load parameters from a file.
    fn load(path: &Path) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Save parameters to a file.
    fn save(parameters: &Self, path: &Path) -> Result<(), Self::Error>;
}

impl Parameters for () {
    type Ref = ();
    type Error = ConfigurationError;

    fn generate(_reference: &Self::Ref) -> Result<Self, Self::Error> {
        Err(ConfigurationError::NotApplicableOperation)
    }

    fn load(_path: &Path) -> Result<Self, Self::Error> {
        Err(ConfigurationError::NotApplicableOperation)
    }

    fn save(_parameters: &Self, _path: &Path) -> Result<(), Self::Error> {
        Err(ConfigurationError::NotApplicableOperation)
    }
}

/// A program-specific preprocessing parameter set.
///
/// Currently only used by the legacy prover integrations.
pub trait Preprocessing {
    type Ref: Reference;
    type Params: Parameters;
    type Error;

    /// Load preprocessing from a file.
    fn load(path: &Path) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Save preprocessing to a file.
    fn save(preprocessing: &Self, path: &Path) -> Result<(), Self::Error>;
}

impl Preprocessing for () {
    type Ref = ();
    type Params = ();
    type Error = ConfigurationError;

    fn load(_path: &Path) -> Result<Self, Self::Error> {
        Err(ConfigurationError::NotApplicableOperation)
    }

    fn save(_preprocessing: &Self, _path: &Path) -> Result<(), Self::Error> {
        Err(ConfigurationError::NotApplicableOperation)
    }
}

/// A verifiable proof of a zkVM execution.
pub trait Verifiable: Serialize + DeserializeOwned {
    type View: CheckedView;
    type Error: From<nexus_core::nvm::VMError> + From<IOError>;

    /// Get the memory layout configuration used for proving.
    fn get_memory_layout(&self) -> &LinearMemoryLayout;

    /// Verify the proof of an execution for a constructed [`CheckedView`](crate::traits::CheckedView).
    fn verify(&self, expected_view: &Self::View) -> Result<(), <Self as Verifiable>::Error>;

    /// Verify the proof of an execution.
    fn verify_expected<
        T: Serialize + DeserializeOwned + Sized,
        U: Serialize + DeserializeOwned + Sized,
    >(
        &self,
        expected_public_input: &T,
        expected_exit_code: u32,
        expected_public_output: &U,
        expected_elf: &nexus_core::nvm::ElfFile,
        expected_ad: &[u8],
    ) -> Result<(), <Self as Verifiable>::Error> {
        let mut input_encoded =
            postcard::to_stdvec(&expected_public_input).map_err(IOError::from)?;
        if !input_encoded.is_empty() {
            let input = expected_public_input.to_owned();

            input_encoded = postcard::to_stdvec_cobs(&input).map_err(IOError::from)?;
            let input_padded_len = (input_encoded.len() + 3) & !3;

            assert!(input_padded_len >= input_encoded.len());
            input_encoded.resize(input_padded_len, 0x00); // cobs ignores 0x00 padding
        }

        let mut output_encoded =
            postcard::to_stdvec(&expected_public_output).map_err(IOError::from)?;
        if !output_encoded.is_empty() {
            let output = expected_public_output.to_owned();

            output_encoded = postcard::to_stdvec_cobs(&output).map_err(IOError::from)?;
            let output_padded_len = (output_encoded.len() + 3) & !3;

            assert!(output_padded_len >= output_encoded.len());
            output_encoded.resize(output_padded_len, 0x00); // cobs ignores 0x00 padding
        }

        let view = Self::View::new_from_expected(
            self.get_memory_layout(),
            input_encoded.as_slice(),
            &expected_exit_code.to_le_bytes(),
            output_encoded.as_slice(),
            expected_elf,
            expected_ad,
        );

        self.verify(&view)
    }

    /// Verify the proof of an execution, with the elf provided as raw bytes.
    fn verify_expected_from_program_bytes<
        T: Serialize + DeserializeOwned + Sized,
        U: Serialize + DeserializeOwned + Sized,
    >(
        &self,
        expected_public_input: &T,
        expected_exit_code: u32,
        expected_public_output: &U,
        expected_elf_bytes: &[u8],
        expected_ad: &[u8],
    ) -> Result<(), <Self as Verifiable>::Error> {
        self.verify_expected(
            expected_public_input,
            expected_exit_code,
            expected_public_output,
            &nexus_core::nvm::ElfFile::from_bytes(expected_elf_bytes)?,
            expected_ad,
        )
    }

    /// Verify the proof of an execution, sourcing the program elf from a path.
    fn verify_expected_from_program_path<
        P: AsRef<Path> + ?Sized,
        T: Serialize + DeserializeOwned + Sized,
        U: Serialize + DeserializeOwned + Sized,
    >(
        &self,
        expected_public_input: &T,
        expected_exit_code: u32,
        expected_public_output: &U,
        expected_elf_path: &P,
        expected_ad: &[u8],
    ) -> Result<(), <Self as Verifiable>::Error> {
        self.verify_expected(
            expected_public_input,
            expected_exit_code,
            expected_public_output,
            &nexus_core::nvm::ElfFile::from_path(expected_elf_path)?,
            expected_ad,
        )
    }

    /// Return a size estimate for the proof, in bytes.
    fn size_estimate(&self) -> usize;
}
