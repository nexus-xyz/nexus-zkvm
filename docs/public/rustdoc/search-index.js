var searchIndex = JSON.parse('{\
"nexus_sdk":{"doc":"An SDK.","t":"IQQQEQQQIQQIIILLAKLLLALKALLAKKKKLLAKKKKKLLLKLCDMLLLLLLLLLLLMLLLLLLLLLENNNNNELLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLANEQIDNGDNGNDMMLLLLLLLLMLLLLLLLLLMLLLLLLLLLLLLLLKLLLLLLLLLLLLLLLLMLMLLMMLLLLLLLLLLLLLLLLLLLNENDDNNLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLANEQINDGDNNDMMLLLLLLLLLLLLLLLLLMLLLLLLLLLLLLLLKLLLLLLLLLLLLLLLLMMLMLLMMLLLLLLLLLLLLLLLLLLL","n":["Compute","Error","Error","Error","Local","Memory","Output","Output","Parameters","Params","Params","Prover","Verifiable","Viewable","borrow","borrow_mut","compile","compile","deref","deref_mut","drop","error","from","generate_for_testing","hypernova","init","into","jolt","load","logs","logs","new","new_from_file","new_from_file","nova","output","output","prove","run","save","try_from","try_into","type_id","verify","vzip","BuildError","CompileOpts","binary","borrow","borrow_mut","clone","clone_into","deref","deref_mut","drop","from","init","into","new","package","set_debug_build","set_memlimit","set_native_build","set_unique_build","to_owned","try_from","try_into","type_id","vzip","BuildError","CompilerError","EncodingError","IOError","InvalidMemoryConfiguration","SerializationError","TapeError","borrow","borrow","borrow_mut","borrow_mut","deref","deref","deref_mut","deref_mut","drop","drop","fmt","fmt","fmt","fmt","from","from","from","from","from","init","init","into","into","source","source","to_string","to_string","try_from","try_from","try_into","try_into","type_id","type_id","vzip","vzip","seq","BuildError","Error","Error","Generate","HyperNova","IOError","PP","Proof","ProofError","SRS","TapeError","View","_setup_params","_step_circuit","borrow","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","borrow_mut","ck","compile","deref","deref","deref","deref","deref_mut","deref_mut","deref_mut","deref_mut","digest","drop","drop","drop","drop","fmt","fmt","from","from","from","from","from","from","from","from","generate","generate","generate_for_testing","init","init","init","init","into","into","into","into","load","logs","logs","new","output","output","pp_secondary","prove","ro_config","run","save","shape","shape_secondary","source","to_string","try_from","try_from","try_from","try_from","try_into","try_into","try_into","try_into","type_id","type_id","type_id","type_id","verify","vzip","vzip","vzip","vzip","BuildError","Error","IOError","Jolt","Proof","ProofError","TapeError","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","compile","deref","deref","deref","deref_mut","deref_mut","deref_mut","drop","drop","drop","fmt","fmt","from","from","from","from","from","from","from","init","init","init","into","into","into","prove","source","to_string","try_from","try_from","try_from","try_into","try_into","try_into","type_id","type_id","type_id","verify","vzip","vzip","vzip","seq","BuildError","Error","Error","Generate","IOError","Nova","PP","Proof","ProofError","TapeError","View","_setup_params","_step_circuit","borrow","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","borrow_mut","compile","deref","deref","deref","deref","deref_mut","deref_mut","deref_mut","deref_mut","digest","drop","drop","drop","drop","fmt","fmt","from","from","from","from","from","from","from","from","generate","generate","generate_for_testing","init","init","init","init","into","into","into","into","load","logs","logs","new","output","output","pp","pp_secondary","prove","ro_config","run","save","shape","shape_secondary","source","to_string","try_from","try_from","try_from","try_from","try_into","try_into","try_into","try_into","type_id","type_id","type_id","type_id","verify","vzip","vzip","vzip","vzip"],"q":[[0,"nexus_sdk"],[45,"nexus_sdk::compile"],[69,"nexus_sdk::error"],[111,"nexus_sdk::hypernova"],[112,"nexus_sdk::hypernova::seq"],[202,"nexus_sdk::jolt"],[256,"nexus_sdk::nova"],[257,"nexus_sdk::nova::seq"],[346,"core::result"],[347,"core::marker"],[348,"std::path"],[349,"alloc::string"],[350,"std::path"],[351,"serde::ser"],[352,"core::any"],[353,"core::fmt"],[354,"core::fmt"],[355,"alloc::string"],[356,"core::error"],[357,"nexus_core::prover::hypernova::error"],[358,"serde::de"],[359,"nexus_jolt::error"],[360,"nexus_core::prover::nova::error"]],"d":["A compute resource.","","","","Indicator that local compute will be used for proving the …","","","","A parameter set used for proving and verifying.","","","A prover (and runner) for the zkVM.","A verifiable proof of a zkVM execution. Also contains a …","A view capturing the output of a zkVM execution.","","","Configure the dynamic compilation of guest programs.","Construct a new proving instance through dynamic …","","","","Contains error types for SDK-specific interfaces.","Returns the argument unchanged.","Generate testing parameters.","Interface into proving with HyperNova.","","Calls <code>U::from(self)</code>.","Experimental interface into proving with Jolt.","Load parameters from a file.","Get the logging output of the zkVM.","Get the logging output of the zkVM.","Construct a new proving instance from raw ELF bytes.","Construct a new proving instance by reading an ELF file.","Construct a new proving instance by reading an ELF file.","Interface into proving with Nova.","Get the contents of the output tape written by the zkVM …","Get the contents of the output tape written by the zkVM …","Prove the zkVM on input of type <code>T</code> and return a verifiable …","Run the zkVM on input of type <code>T</code> and return a view of the …","Save parameters to a file.","","","","Verify the proof of execution.","","","Options for dynamic compilation of guest programs.","The binary produced by the build that should be loaded …","","","","","","","","Returns the argument unchanged.","","Calls <code>U::from(self)</code>.","Setup options for dynamic compilation.","The (in-workspace) package to build.","Set dynamic compilation to build guest program in a debug …","Set the amount of memory available to the guest program. …","Set dynamic compilation to build for the native (host …","Set dynamic compilation to run a unique build that neither …","","","","","","Errors that occur during dynamic compilation of guest …","The compilation process failed.","Error parsing logging tape.","An error occured reading or writing to the file system.","The compile options are invalid for the memory limit.","Error serializing to or deserializing from the zkVM …","Errors that occur while reading from or writing to the …","","","","","","","","","","","","","","","Returns the argument unchanged.","","Returns the argument unchanged.","","","","","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","","","","","","","","","","","","","Sequential (non-parallelized, non-distributed) proving.","An error occured building the guest program dynamically","","","","","An error occured reading or writing to the file system","","","An error occured during parameter generation, execution, …","","An error occured reading or writing to the VM input/output …","","","","","","","","","","","","","","","","","","","","","","","","","","","","","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","","","","","","","","","","","","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","An error occured building the guest program dynamically","","An error occured reading or writing to the file system","","","An error occured during parameter generation, execution, …","An error occured reading or writing to the VM input/output …","","","","","","","","","","","","","","","","","","","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","","","","","","","","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","","","","","","","","","","","","","","","","","Sequential (non-parallelized, non-distributed) proving.","An error occured building the guest program dynamically","","","","An error occured reading or writing to the file system","","","","An error occured during parameter generation, execution, …","An error occured reading or writing to the VM input/output …","","","","","","","","","","","","","","","","","","","","","","","","","","","","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","","","","","","","","","","","","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","",""],"i":[0,45,46,12,0,45,14,12,0,45,12,0,0,0,26,26,0,45,26,26,26,0,26,46,0,26,26,0,46,14,12,45,45,45,0,14,12,45,45,46,26,26,26,12,26,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,18,21,18,18,21,0,18,21,18,21,18,21,18,21,18,21,18,18,21,21,18,18,21,21,21,18,21,18,21,18,21,18,21,18,21,18,21,18,21,18,21,0,28,0,47,0,0,28,0,0,28,0,28,0,31,31,27,32,34,28,27,32,34,28,31,27,27,32,34,28,27,32,34,28,31,27,32,34,28,28,28,27,32,34,28,28,28,28,28,47,31,31,27,32,34,28,27,32,34,28,31,32,34,27,32,34,31,27,31,27,31,31,31,28,28,27,32,34,28,27,32,34,28,27,32,34,28,34,27,32,34,28,36,0,36,0,0,36,36,35,38,36,35,38,36,35,35,38,36,35,38,36,35,38,36,36,36,35,38,36,36,36,36,36,35,38,36,35,38,36,35,36,36,35,38,36,35,38,36,35,38,36,38,35,38,36,0,40,0,48,0,40,0,0,0,40,40,0,42,42,39,43,44,40,39,43,44,40,39,39,43,44,40,39,43,44,40,42,39,43,44,40,40,40,39,43,44,40,40,40,40,40,48,42,42,39,43,44,40,39,43,44,40,42,43,44,39,43,44,42,42,39,42,39,42,42,42,40,40,39,43,44,40,39,43,44,40,39,43,44,40,44,39,43,44,40],"f":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,[-1,-2,[],[]],[-1,-2,[],[]],0,[1,[[2,[-1]]],3],[4,-1,[]],[4,-1,[]],[4,5],0,[-1,-1,[]],[[],[[2,[-1]]],3],0,[[],4],[-1,-2,[],[]],0,[6,[[2,[-1]]],3],[-1,7,[]],[-1,7,[]],[[[9,[8]]],[[2,[-1]]],3],[10,[[2,[-1]]],3],[10,[[2,[-1]]],3],0,[-1,[],[]],[-1,[],[]],[[-1,[11,[-2]]],[[2,[[0,[12]]]]],[],[13,3]],[[-1,[11,[-2]]],[[2,[[0,[14]]]]],[],[13,3]],[[-1,6],[[2,[5]]],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,15,[]],[-1,[[2,[5]]],[]],[-1,-2,[],[]],0,0,0,[-1,-2,[],[]],[-1,-2,[],[]],[1,1],[[-1,-2],5,[],[]],[4,-1,[]],[4,-1,[]],[4,5],[-1,-1,[]],[[],4],[-1,-2,[],[]],[[16,16],1],0,[[1,17],5],[[1,4],5],[[1,17],5],[[1,17],5],[-1,-2,[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,15,[]],[-1,-2,[],[]],0,0,0,0,0,0,0,[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[4,-1,[]],[4,-1,[]],[4,-1,[]],[4,-1,[]],[4,5],[4,5],[[18,19],20],[[18,19],20],[[21,19],20],[[21,19],20],[-1,-1,[]],[22,18],[-1,-1,[]],[23,21],[24,21],[[],4],[[],4],[-1,-2,[],[]],[-1,-2,[],[]],[18,[[11,[25]]]],[21,[[11,[25]]]],[-1,7,[]],[-1,7,[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,15,[]],[-1,15,[]],[-1,-2,[],[]],[-1,-2,[],[]],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],0,[1,[[2,[[27,[26]]]]]],[4,-1,[]],[4,-1,[]],[4,-1,[]],[4,-1,[]],[4,-1,[]],[4,-1,[]],[4,-1,[]],[4,-1,[]],0,[4,5],[4,5],[4,5],[4,5],[[28,19],20],[[28,19],20],[-1,-1,[]],[-1,-1,[]],[-1,-1,[]],[-1,-1,[]],[18,28],[21,28],[29,28],[22,28],[30,[[2,[-1]]],3],[30,[[2,[31]]]],[[],[[2,[31]]]],[[],4],[[],4],[[],4],[[],4],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[6,[[2,[31]]]],[[[32,[-1]]],7,33],[[[34,[-1]]],7,33],[[[9,[8]]],[[2,[[27,[26]]]]]],[[[32,[-1]]],[],33],[[[34,[-1]]],[],33],0,[[[27,[26]],[11,[-1]]],[[2,[[34,[-2]]]]],[13,3],33],0,[[[27,[26]],[11,[-1]]],[[2,[[32,[-2]]]]],[13,3],33],[[31,6],[[2,[5]]]],0,0,[28,[[11,[25]]]],[-1,7,[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,15,[]],[-1,15,[]],[-1,15,[]],[-1,15,[]],[[[34,[-1]]],[[2,[5]]],33],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],0,0,0,0,0,0,0,[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[1,[[2,[[35,[26]],36]]]],[4,-1,[]],[4,-1,[]],[4,-1,[]],[4,-1,[]],[4,-1,[]],[4,-1,[]],[4,5],[4,5],[4,5],[[36,19],20],[[36,19],20],[-1,-1,[]],[-1,-1,[]],[-1,-1,[]],[37,36],[22,36],[21,36],[18,36],[[],4],[[],4],[[],4],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[[[35,[26]]],[[2,[38,36]]]],[36,[[11,[25]]]],[-1,7,[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,15,[]],[-1,15,[]],[-1,15,[]],[38,[[2,[5,36]]]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],0,0,0,0,0,0,0,0,0,0,0,0,0,0,[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[1,[[2,[[39,[26]]]]]],[4,-1,[]],[4,-1,[]],[4,-1,[]],[4,-1,[]],[4,-1,[]],[4,-1,[]],[4,-1,[]],[4,-1,[]],0,[4,5],[4,5],[4,5],[4,5],[[40,19],20],[[40,19],20],[-1,-1,[]],[-1,-1,[]],[-1,-1,[]],[-1,-1,[]],[22,40],[21,40],[18,40],[41,40],[[],[[2,[-1]]],3],[[],[[2,[42]]]],[[],[[2,[42]]]],[[],4],[[],4],[[],4],[[],4],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[6,[[2,[42]]]],[[[43,[-1]]],7,33],[[[44,[-1]]],7,33],[[[9,[8]]],[[2,[[39,[26]]]]]],[[[43,[-1]]],[],33],[[[44,[-1]]],[],33],0,0,[[[39,[26]],[11,[-1]]],[[2,[[44,[-2]]]]],[13,3],33],0,[[[39,[26]],[11,[-1]]],[[2,[[43,[-2]]]]],[13,3],33],[[42,6],[[2,[5]]]],0,0,[40,[[11,[25]]]],[-1,7,[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,[[2,[-2]]],[],[]],[-1,15,[]],[-1,15,[]],[-1,15,[]],[-1,15,[]],[[[44,[-1]]],[[2,[5]]],33],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]]],"c":[],"p":[[3,"CompileOpts",45],[4,"Result",346],[8,"Sized",347],[15,"usize"],[15,"tuple"],[3,"Path",348],[3,"String",349],[15,"u8"],[15,"slice"],[3,"PathBuf",348],[4,"Option",350],[8,"Verifiable",0],[8,"Serialize",351],[8,"Viewable",0],[3,"TypeId",352],[15,"str"],[15,"bool"],[4,"BuildError",69],[3,"Formatter",353],[6,"Result",353],[4,"TapeError",69],[3,"Error",354],[3,"FromUtf8Error",349],[4,"Error",355],[8,"Error",356],[4,"Local",0],[3,"HyperNova",112],[4,"Error",112],[4,"ProofError",357],[6,"SRS",112],[6,"PP",112],[3,"View",112],[8,"DeserializeOwned",358],[3,"Proof",112],[3,"Jolt",202],[4,"Error",202],[4,"Error",359],[3,"Proof",202],[3,"Nova",257],[4,"Error",257],[4,"ProofError",360],[6,"PP",257],[3,"View",257],[3,"Proof",257],[8,"Prover",0],[8,"Parameters",0],[8,"Generate",112],[8,"Generate",257]],"b":[[86,"impl-Display-for-BuildError"],[87,"impl-Debug-for-BuildError"],[88,"impl-Debug-for-TapeError"],[89,"impl-Display-for-TapeError"],[93,"impl-From%3CFromUtf8Error%3E-for-TapeError"],[94,"impl-From%3CError%3E-for-TapeError"],[149,"impl-Debug-for-Error"],[150,"impl-Display-for-Error"],[155,"impl-From%3CBuildError%3E-for-Error"],[156,"impl-From%3CTapeError%3E-for-Error"],[157,"impl-From%3CProofError%3E-for-Error"],[158,"impl-From%3CError%3E-for-Error"],[225,"impl-Display-for-Error"],[226,"impl-Debug-for-Error"],[230,"impl-From%3CError%3E-for-Error"],[231,"impl-From%3CError%3E-for-Error"],[232,"impl-From%3CTapeError%3E-for-Error"],[233,"impl-From%3CBuildError%3E-for-Error"],[292,"impl-Debug-for-Error"],[293,"impl-Display-for-Error"],[298,"impl-From%3CError%3E-for-Error"],[299,"impl-From%3CTapeError%3E-for-Error"],[300,"impl-From%3CBuildError%3E-for-Error"],[301,"impl-From%3CNovaProofError%3E-for-Error"]]}\
}');
if (typeof window !== 'undefined' && window.initSearch) {window.initSearch(searchIndex)};
if (typeof exports !== 'undefined') {exports.searchIndex = searchIndex};
