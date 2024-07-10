var searchIndex = JSON.parse('{\
"nexus_sdk":{"doc":"An SDK.","t":"IQQQEQQIQQIILLAKLLLALKALLAKKKLLAKKKKLLLKLCDMLLLLLLLLLLLMLLLLLLLLLENNNNNELLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLANEQIDNGDNGNMMLLLLLLMLLLLLLLMLLLLLLLLLLLLKLLLLLLLLLLLLMLMLLMMLLLLLLLLLLLLLLLNENDDNNLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLANEQINDGDNNMMLLLLLLLLLLLLLMLLLLLLLLLLLLKLLLLLLLLLLLLMMLMLLMMLLLLLLLLLLLLLLL","n":["Compute","Error","Error","Error","Local","Memory","Output","Parameters","Params","Params","Prover","Verifiable","borrow","borrow_mut","compile","compile","deref","deref_mut","drop","error","from","generate_for_testing","hypernova","init","into","jolt","load","logs","new","new_from_file","new_from_file","nova","output","prove","run","save","try_from","try_into","type_id","verify","vzip","BuildError","CompileOpts","binary","borrow","borrow_mut","clone","clone_into","deref","deref_mut","drop","from","init","into","new","package","set_debug_build","set_memlimit","set_native_build","set_unique_build","to_owned","try_from","try_into","type_id","vzip","BuildError","CompilerError","EncodingError","IOError","InvalidMemoryConfiguration","SerializationError","TapeError","borrow","borrow","borrow_mut","borrow_mut","deref","deref","deref_mut","deref_mut","drop","drop","fmt","fmt","fmt","fmt","from","from","from","from","from","init","init","into","into","source","source","to_string","to_string","try_from","try_from","try_into","try_into","type_id","type_id","vzip","vzip","seq","BuildError","Error","Error","Generate","HyperNova","IOError","PP","Proof","ProofError","SRS","TapeError","_setup_params","_step_circuit","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","ck","compile","deref","deref","deref","deref_mut","deref_mut","deref_mut","digest","drop","drop","drop","fmt","fmt","from","from","from","from","from","from","from","generate","generate","generate_for_testing","init","init","init","into","into","into","load","logs","new","output","pp_secondary","prove","ro_config","run","save","shape","shape_secondary","source","to_string","try_from","try_from","try_from","try_into","try_into","try_into","type_id","type_id","type_id","verify","vzip","vzip","vzip","BuildError","Error","IOError","Jolt","Proof","ProofError","TapeError","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","compile","deref","deref","deref","deref_mut","deref_mut","deref_mut","drop","drop","drop","fmt","fmt","from","from","from","from","from","from","from","init","init","init","into","into","into","prove","source","to_string","try_from","try_from","try_from","try_into","try_into","try_into","type_id","type_id","type_id","verify","vzip","vzip","vzip","seq","BuildError","Error","Error","Generate","IOError","Nova","PP","Proof","ProofError","TapeError","_setup_params","_step_circuit","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","compile","deref","deref","deref","deref_mut","deref_mut","deref_mut","digest","drop","drop","drop","fmt","fmt","from","from","from","from","from","from","from","generate","generate","generate_for_testing","init","init","init","into","into","into","load","logs","new","output","pp","pp_secondary","prove","ro_config","run","save","shape","shape_secondary","source","to_string","try_from","try_from","try_from","try_into","try_into","try_into","type_id","type_id","type_id","verify","vzip","vzip","vzip"],"q":[[0,"nexus_sdk"],[41,"nexus_sdk::compile"],[65,"nexus_sdk::error"],[107,"nexus_sdk::hypernova"],[108,"nexus_sdk::hypernova::seq"],[183,"nexus_sdk::jolt"],[237,"nexus_sdk::nova"],[238,"nexus_sdk::nova::seq"],[312,"core::result"],[313,"core::marker"],[314,"std::path"],[315,"alloc::string"],[316,"std::path"],[317,"serde::ser"],[318,"serde::de"],[319,"core::any"],[320,"core::fmt"],[321,"core::fmt"],[322,"alloc::string"],[323,"core::error"],[324,"nexus_core::prover::hypernova::error"],[325,"nexus_jolt::error"],[326,"nexus_core::prover::nova::error"]],"d":["A compute resource.","","","","Indicator type that local compute will be used for proving …","","","A parameter set used for proving and verifying.","","","A prover (and runner) for the zkVM.","A verifiable proof of a zkVM execution. Also contains a …","","","Configure the dynamic compilation of guest programs.","Construct a new proving instance through dynamic …","","","","Contains error types for SDK-specific interfaces.","Returns the argument unchanged.","Generate testing parameters.","Interface into proving with HyperNova.","","Calls <code>U::from(self)</code>.","Experimental interface into proving with Jolt.","Load parameters from a file.","Get the logging output of the zkVM.","Construct a new proving instance from raw ELF bytes.","Construct a new proving instance by reading an ELF file.","Construct a new proving instance by reading an ELF file.","Interface into proving with Nova.","Get the contents of the output tape written by the zkVM …","Prove the zkVM on input of type <code>T</code> and return a verifiable …","Run the zkVM on input of type <code>T</code> and return a view of the …","Save parameters to a file.","","","","Verify the proof of an execution.","","","Options for dynamic compilation of guest programs.","The binary produced by the build that should be loaded …","","","","","","","","Returns the argument unchanged.","","Calls <code>U::from(self)</code>.","Setup options for dynamic compilation.","The (in-workspace) package to build.","Set dynamic compilation to build the guest program in a …","Set the amount of memory available to the guest program. …","Set dynamic compilation to build for the native (host …","Set dynamic compilation to run a unique build that neither …","","","","","","Errors that occur during dynamic compilation of guest …","The compilation process failed.","Error parsing logging tape.","An error occured reading or writing to the file system.","The compile options are invalid for the memory limit.","Error serializing to or deserializing from the zkVM …","Errors that occur while reading from or writing to the …","","","","","","","","","","","","","","","Returns the argument unchanged.","","","Returns the argument unchanged.","","","","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","","","","","","","","","","","","","Sequential (non-parallelized, non-distributed) proving for …","An error occured building the guest program dynamically.","Errors that occur while proving using Nova.","","Generate a deployment-ready parameter set used for proving …","Prover for the Nexus zkVM using HyperNova.","An error occured reading or writing to the file system.","Public parameters used to prove and verify zkVM executions.","A verifiable proof of a zkVM execution. Also contains a …","An error occured during parameter generation, execution, …","Structured reference string (SRS) used to generate public …","An error occured reading or writing to the zkVM …","","","","","","","","","","","","","","","","","","","","","","","Returns the argument unchanged.","Returns the argument unchanged.","","","","","Returns the argument unchanged.","Generate parameters.","","","","","","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","","","","","","","","","","","","","","","","","","","","","","","","","","","An error occured building the guest program dynamically.","Errors that occur while proving using Jolt.","An error occured reading or writing to the file system.","Prover for the Nexus zkVM using Jolt.","A Jolt proof (and auxiliary information needed for …","An error occured during parameter generation, execution, …","An error occured reading or writing to the zkVM …","","","","","","","Construct a new proving instance through dynamic …","","","","","","","","","","","","Returns the argument unchanged.","Returns the argument unchanged.","","Returns the argument unchanged.","","","","","","","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Prove the zkVM and return a verifiable proof.","","","","","","","","","","","","Verify the proof of an execution.","","","","Sequential (non-parallelized, non-distributed) proving for …","An error occured building the guest program dynamically.","Errors that occur while proving using Nova.","","Generate a deployment-ready parameter set used for proving …","An error occured reading or writing to the file system.","Prover for the Nexus zkVM using Nova.","Public parameters used to prove and verify zkVM executions.","A verifiable proof of a zkVM execution. Also contains a …","An error occured during parameter generation, execution, …","An error occured reading or writing to the zkVM …","","","","","","","","","","","","","","","","","","","","","","Returns the argument unchanged.","Returns the argument unchanged.","","","Returns the argument unchanged.","","","Generate parameters.","","","","","","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","","","","","","","","","","","","","","","","","","","","","","","","","","",""],"i":[0,42,43,12,0,42,12,0,42,12,0,0,26,26,0,42,26,26,26,0,26,43,0,26,26,0,43,12,42,42,42,0,12,42,42,43,26,26,26,12,26,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,18,21,18,18,21,0,18,21,18,21,18,21,18,21,18,21,18,18,21,21,18,18,21,21,21,18,21,18,21,18,21,18,21,18,21,18,21,18,21,18,21,0,28,0,44,0,0,28,0,0,28,0,28,31,31,27,32,28,27,32,28,31,27,27,32,28,27,32,28,31,27,32,28,28,28,27,32,28,28,28,28,28,44,31,31,27,32,28,27,32,28,31,32,27,32,31,27,31,27,31,31,31,28,28,27,32,28,27,32,28,27,32,28,32,27,32,28,34,0,34,0,0,34,34,33,36,34,33,36,34,33,33,36,34,33,36,34,33,36,34,34,34,33,36,34,34,34,34,34,33,36,34,33,36,34,33,34,34,33,36,34,33,36,34,33,36,34,36,33,36,34,0,38,0,45,0,38,0,0,0,38,38,40,40,37,41,38,37,41,38,37,37,41,38,37,41,38,40,37,41,38,38,38,37,41,38,38,38,38,38,45,40,40,37,41,38,37,41,38,40,41,37,41,40,40,37,40,37,40,40,40,38,38,37,41,38,37,41,38,37,41,38,41,37,41,38],"f":[0,0,0,0,0,0,0,0,0,0,0,0,[-1,-2,[],[]],[-1,-2,[],[]],0,[1,[[2,[-1]]],3],[4,-1,[]],[4,-1,[]],[4,5],0,[-1,-1,[]],[[],[[2,[-1]]],3],0,[[],4],[-1,-2,[],[]],0,[6,[[2,[-1]]],3],[-1,7,[]],[[[9,[8]]],[[2,[-1]]],3],[10,[[2,[-1]]],3],[10,[[2,[-1]]],3],0,[-1,[],[]],[[-1,[11,[-2]]],[[2,[[0,[12]]]]],[],[13,3]],[[-1,[11,[-2]]],[[2,[[0,[-3]]]]],[],[13,3],14],[[-1,6],[[2,[5]]],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,15,[]],[-1,[[2,[5]]],[]],[-1,-2,[],[]],0,0,0,[-1,-2,[],[]],[-1,-2,[],[]],[1,1],[[-1,-2],5,[],[]],[4,-1,[]],[4,-1,[]],[4,5],[-1,-1,[]],[[],4],[-1,-2,[],[]],[[16,16],1],0,[[1,17],5],[[1,4],5],[[1,17],5],[[1,17],5],[-1,-2,[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,15,[]],[-1,-2,[],[]],0,0,0,0,0,0,0,[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[4,-1,[]],[4,-1,[]],[4,-1,[]],[4,-1,[]],[4,5],[4,5],[[18,19],20],[[18,19],20],[[21,19],20],[[21,19],20],[-1,-1,[]],[22,18],[23,21],[-1,-1,[]],[24,21],[[],4],[[],4],[-1,-2,[],[]],[-1,-2,[],[]],[18,[[11,[25]]]],[21,[[11,[25]]]],[-1,7,[]],[-1,7,[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,15,[]],[-1,15,[]],[-1,-2,[],[]],[-1,-2,[],[]],0,0,0,0,0,0,0,0,0,0,0,0,0,0,[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],0,[1,[[2,[[27,[26]]]]]],[4,-1,[]],[4,-1,[]],[4,-1,[]],[4,-1,[]],[4,-1,[]],[4,-1,[]],0,[4,5],[4,5],[4,5],[[28,19],20],[[28,19],20],[-1,-1,[]],[-1,-1,[]],[18,28],[21,28],[22,28],[29,28],[-1,-1,[]],[30,[[2,[-1]]],3],[30,[[2,[31]]]],[[],[[2,[31]]]],[[],4],[[],4],[[],4],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[6,[[2,[31]]]],[[[32,[-1]]],7,14],[[[9,[8]]],[[2,[[27,[26]]]]]],[[[32,[-1]]],[],14],0,[[[27,[26]],[11,[-1]]],[[2,[[32,[-2]]]]],[13,3],14],0,[[[27,[26]],[11,[-1]]],[[2,[[0,[-2]]]]],[13,3],14],[[31,6],[[2,[5]]]],0,0,[28,[[11,[25]]]],[-1,7,[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,15,[]],[-1,15,[]],[-1,15,[]],[[[32,[-1]]],[[2,[5]]],14],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],0,0,0,0,0,0,0,[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[1,[[2,[[33,[26]],34]]]],[4,-1,[]],[4,-1,[]],[4,-1,[]],[4,-1,[]],[4,-1,[]],[4,-1,[]],[4,5],[4,5],[4,5],[[34,19],20],[[34,19],20],[-1,-1,[]],[-1,-1,[]],[35,34],[-1,-1,[]],[18,34],[21,34],[22,34],[[],4],[[],4],[[],4],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[[[33,[26]]],[[2,[36,34]]]],[34,[[11,[25]]]],[-1,7,[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,15,[]],[-1,15,[]],[-1,15,[]],[36,[[2,[5,34]]]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],0,0,0,0,0,0,0,0,0,0,0,0,0,[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[1,[[2,[[37,[26]]]]]],[4,-1,[]],[4,-1,[]],[4,-1,[]],[4,-1,[]],[4,-1,[]],[4,-1,[]],0,[4,5],[4,5],[4,5],[[38,19],20],[[38,19],20],[-1,-1,[]],[-1,-1,[]],[21,38],[22,38],[-1,-1,[]],[18,38],[39,38],[[],[[2,[-1]]],3],[[],[[2,[40]]]],[[],[[2,[40]]]],[[],4],[[],4],[[],4],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[6,[[2,[40]]]],[[[41,[-1]]],7,14],[[[9,[8]]],[[2,[[37,[26]]]]]],[[[41,[-1]]],[],14],0,0,[[[37,[26]],[11,[-1]]],[[2,[[41,[-2]]]]],[13,3],14],0,[[[37,[26]],[11,[-1]]],[[2,[[0,[-2]]]]],[13,3],14],[[40,6],[[2,[5]]]],0,0,[38,[[11,[25]]]],[-1,7,[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,15,[]],[-1,15,[]],[-1,15,[]],[[[41,[-1]]],[[2,[5]]],14],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]]],"c":[],"p":[[3,"CompileOpts",41],[4,"Result",312],[8,"Sized",313],[15,"usize"],[15,"tuple"],[3,"Path",314],[3,"String",315],[15,"u8"],[15,"slice"],[3,"PathBuf",314],[4,"Option",316],[8,"Verifiable",0],[8,"Serialize",317],[8,"DeserializeOwned",318],[3,"TypeId",319],[15,"str"],[15,"bool"],[4,"BuildError",65],[3,"Formatter",320],[6,"Result",320],[4,"TapeError",65],[3,"Error",321],[3,"FromUtf8Error",315],[4,"Error",322],[8,"Error",323],[4,"Local",0],[3,"HyperNova",108],[4,"Error",108],[4,"ProofError",324],[6,"SRS",108],[6,"PP",108],[3,"Proof",108],[3,"Jolt",183],[4,"Error",183],[4,"Error",325],[3,"Proof",183],[3,"Nova",238],[4,"Error",238],[4,"ProofError",326],[6,"PP",238],[3,"Proof",238],[8,"Prover",0],[8,"Parameters",0],[8,"Generate",108],[8,"Generate",238]],"b":[[82,"impl-Display-for-BuildError"],[83,"impl-Debug-for-BuildError"],[84,"impl-Display-for-TapeError"],[85,"impl-Debug-for-TapeError"],[88,"impl-From%3CFromUtf8Error%3E-for-TapeError"],[90,"impl-From%3CError%3E-for-TapeError"],[139,"impl-Debug-for-Error"],[140,"impl-Display-for-Error"],[143,"impl-From%3CBuildError%3E-for-Error"],[144,"impl-From%3CTapeError%3E-for-Error"],[145,"impl-From%3CError%3E-for-Error"],[146,"impl-From%3CProofError%3E-for-Error"],[206,"impl-Display-for-Error"],[207,"impl-Debug-for-Error"],[210,"impl-From%3CError%3E-for-Error"],[212,"impl-From%3CBuildError%3E-for-Error"],[213,"impl-From%3CTapeError%3E-for-Error"],[214,"impl-From%3CError%3E-for-Error"],[267,"impl-Display-for-Error"],[268,"impl-Debug-for-Error"],[271,"impl-From%3CTapeError%3E-for-Error"],[272,"impl-From%3CError%3E-for-Error"],[274,"impl-From%3CBuildError%3E-for-Error"],[275,"impl-From%3CNovaProofError%3E-for-Error"]]}\
}');
if (typeof window !== 'undefined' && window.initSearch) {window.initSearch(searchIndex)};
if (typeof exports !== 'undefined') {exports.searchIndex = searchIndex};
