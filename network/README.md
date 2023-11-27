## Implementation notes

This is an initial structure for the PCD network. To run the code, follow these
steps:

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
Loading public parameters from nexus-public.zst...
Got public parameters in 71.741037344s
Primary Circuit 340971 x 374479
Secondary Circuit 2870 x 3024
Listening on http://127.0.0.1:8080
```

In separate terminals you can run a number of PCD nodes:

```
network> cargo run -- -p
Loading public parameters from nexus-public.zst...
Got public parameters in 84.434546734s
Primary Circuit 340971 x 374479
Secondary Circuit 2870 x 3024
connected to 127.0.0.1:8080/pcd
Listening on http://127.0.0.1:37053
```

Or MSM nodes:

```
network> cargo run -- -m
Loading public parameters from nexus-public.zst...
Got public parameters in 100.986110779s
Primary Circuit 340971 x 374479
Secondary Circuit 2870 x 3024
connected to 127.0.0.1:8080/msm
Listening on http://127.0.0.1:39993
```

Once running you can visit the webserver of the initial node at
http://127.0.0.1:8080 and press the "Submit Fake Proof Request" button to start
a simulated proof. You should see the various nodes printing which PCD nodes
and MSMs they are computing. Once complete the primary node will check the
proof and print "proof complete" if everything works properly.
