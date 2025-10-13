# The Nexus zkVM

<div align="left">
    <a href="https://github.com/nexus-xyz/nexus-zkvm/graphs/contributors">
        <img src="https://img.shields.io/github/contributors/nexus-xyz/nexus-zkvm.svg"></a>
    <a href="https://x.com/NexusLabs">
        <img src="https://img.shields.io/badge/Twitter-black?logo=x&logoColor=white"/></a>
    <a href="https://nexus.xyz">
        <img src="https://img.shields.io/static/v1?label=Stage&message=Alpha&color=2BB4AB"/></a>
</div>

<p align="center">
  <p align="center">
   <img width="100%" src="assets/nexus_docs-header.png" alt="Logo">
  </p>
</p>

The Nexus zero-knowledge virtual machine is a modular, extensible, prover-optimized, fully-specified zkVM written in Rust, focused on performance and security. Built with [Stwo](https://github.com/starkware-libs/stwo) by [StarkWare](https://starkware.co/blog/starkware-new-proving-record/). Review the specification [here](./specification/zkvm-spec-3.0.pdf).

To get started with the Nexus zkVM, check out the [Getting Started](https://docs.nexus.xyz/zkvm/proving/overview) page.

*The Nexus zkVM is in an experimental stage and is not currently recommended for production use.*

### The Nexus Ethos: Assurance through Open Science

We believe a zkVM must provide an efficient proving mechanism without compromising on security and correctness. A zkVM cannot provide transparency without being transparent itself. Every component of a zkVM should be powered by fully and publicly specified cryptographic components, with careful analysis of security and performance.

The Nexus zkVM features no code obfuscation, no proprietary components, and no closed-source code.

### Modular and Extensible

The Nexus zkVM is designed to be modular and extensible, with highly optimized isolated components. Configured out of the box with thoroughly-analyzed, sensible defaults (such as the choice of prover and the memory model) that will work for most users, developers can feel confident in the security and performance of the zkVM whatever their application.

That said, the Nexus zkVM is also designed to be extensible. Source-available code and consistent development by the Nexus team enables support for new languages, new precompiles, and new provers as the state-of-the-art advances, all with no vendor lock-in.

### Learn More

See our zkVM documentation, including guides and walkthroughs, at [docs.nexus.xyz](https://docs.nexus.xyz/zkvm/nexus-zkvm).
