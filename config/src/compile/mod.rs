use std::{
    path::{Path, PathBuf},
    fs,
};

use super::{CARGO_MANIFEST_DIR, CONFIG_ENV_PREFIX, config_env_path};

mod error;
pub use error::CompileError;

fn config_bases_path() -> PathBuf {
    Path::new(CARGO_MANIFEST_DIR).join("bases")
}

const CONFIG_FILES: &[&str] = &["vm.toml"];

pub fn compile_to_env_from_bases() -> Result<(), CompileError> {
    let flat_config = compile_flat_config_from_bases()?;

    let env_out = flat_config
        .into_iter()
        .fold(String::new(), |mut acc, (key, value)| {
            acc.push_str(&format!("{key}={value}\n"));
            acc
        });
    fs::write(config_env_path(), env_out)?;

    Ok(())
}

fn compile_flat_config_from_bases() -> Result<Vec<(String, String)>, CompileError> {
    let mut flat_config = Vec::new();

    for base in CONFIG_FILES {
        let config_path = config_bases_path().join(base);
        let raw_file = fs::read_to_string(&config_path)?;

        let mut config = compile_flat_config(CONFIG_ENV_PREFIX, &raw_file)?;
        flat_config.append(&mut config);
    }

    Ok(flat_config)
}

fn compile_flat_config(
    prefix: &str,
    raw_table: &str,
) -> Result<Vec<(String, String)>, CompileError> {
    let mut values = Vec::new();
    let toml_config: toml::Table = toml::from_str(&raw_table)?;

    parse_table(prefix, &toml_config, &mut values);
    Ok(values)
}

fn parse_table(prefix: &str, table: &toml::Table, out: &mut Vec<(String, String)>) {
    for (key, value) in table {
        let key = key.to_ascii_uppercase();
        let prefix = format!("{prefix}_{key}");
        let str_value = match value {
            toml::Value::Table(t) => {
                parse_table(&prefix, t, out);
                continue;
            }
            toml::Value::String(s) => s.clone(),
            toml::Value::Integer(i) => i.to_string(),
            toml::Value::Boolean(b) => b.to_string(),
            _ => unimplemented!(),
        };

        out.push((prefix, str_value));
    }
}

#[cfg(test)]
pub(crate) fn load_env() {
    let flat_config = compile_flat_config_from_bases().unwrap();

    for (key, value) in flat_config {
        std::env::set_var(key, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_works() {
        const TABLE: &str = r#"
            ip = '127.0.0.1'
        
            [db]
            url = "test.url"
            conn_limit = 10
            
            [db.inner]
            url = "test.url.1"
        "#;
        let env = compile_flat_config("PREFIX", TABLE).unwrap();

        let expected = [
            ("PREFIX_IP", "127.0.0.1"),
            ("PREFIX_DB_URL", "test.url"),
            ("PREFIX_DB_CONN_LIMIT", "10"),
            ("PREFIX_DB_INNER_URL", "test.url.1"),
        ];
        assert_eq!(env.len(), expected.len());

        for (key, value) in expected {
            assert!(env.contains(&(key.into(), value.into())));
        }
    }

    #[test]
    fn kek() {
        compile_to_env_from_bases().unwrap();
    }
}
