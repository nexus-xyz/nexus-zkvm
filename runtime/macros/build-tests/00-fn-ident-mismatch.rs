// build tests require main function, namespaces are necessary

mod test {
    #[nexus_rt_macros::main]
    fn foo() {}
}


fn main() {}
