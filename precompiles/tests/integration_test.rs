#[cfg(test)]
mod tests {
    use nexus_precompile_macros::use_precompiles;
    use_precompiles!(::dummy_div::DummyDiv as MyDummyDiv);

    #[test]
    fn test_precompile_macro() {
        assert_eq!(MyDummyDiv::div(10, 2), 5);
    }
}
