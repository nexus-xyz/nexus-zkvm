mod test1 {
    #[nexus_rt_macros::main]
    async fn main() {}
}

mod test2 {
    #[nexus_rt_macros::main]
    fn main<'a, T1, T2>() {}
}

mod test3 {
    #[nexus_rt_macros::main]
    fn main() where (): Send {}
}


fn main() {}
