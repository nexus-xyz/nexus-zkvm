This is a prototype for the PCD network.
To run the code, follow these steps:

Generate the public parameters for parallel nova using the prover crate:

```
prover> cargo run -r -- gen -P
Generating public parameters to nexus-public.zst...
```

This will generate the file `nexus-public.zst`, which you can move into the
network directory for convenience.

Run the initial pcdnode: this node will use the default port of 8080:

```
network> cargo run -r -- -w
```

In separate terminals you can run a number of PCD nodes:

```
network> cargo run -r -- -l 127.0.0.1:0 -p
```

Or MSM nodes:

```
network> cargo run -r -- -l 127.0.0.1:0 -m
```

Once running you can use the basic client program to submit
a program and query its status. Note, the debug version will
connect to localhost, and the release version will try to
connect to the public PCD coordinator running in the cloud.

```
network> cargo run --bin client -- -p elf_file
network> cargo run --bin client -- -q proof_hash
```
