mod test {
    #[nexus_rt_macros::main]
    unsafe extern "C" fn main(a: &u32) -> String {
        String::new()
    }
}

fn main() {}
