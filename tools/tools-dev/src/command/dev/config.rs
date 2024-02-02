use std::{
    fs,
    io::{self, Write},
    path::Path,
};

use clap::{Args, Subcommand};
use nexus_config::constants::{CONFIG_ENV_PATH, CONFIG_ENV_PREFIX, CONFIG_SEPARATOR};

use crate::LOG_TARGET;

#[derive(Debug, Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    command: Option<ConfigAction>,
}

#[derive(Debug, Subcommand)]
enum ConfigAction {
    /// Compiles configuration layout into env file, overwriting previous one.
    Compile,
}

pub(crate) fn handle_command(args: ConfigArgs) -> anyhow::Result<()> {
    let _ = args.command.unwrap_or(ConfigAction::Compile);

    compile_to_env_from_bases(true)?;
    tracing::info!(
        target: LOG_TARGET,
        "compiled workspace configuration",
    );
    Ok(())
}

macro_rules! config_dir {
    () => {
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../config")
    };
}

const CONFIG_BASE_DIR: &str = concat!(config_dir!(), "/bases");
const CONFIG_BASE_FILES: &[&str] = &["network.toml", "vm.toml"];

pub(crate) fn compile_to_env_from_bases(force: bool) -> anyhow::Result<()> {
    let mut flat_config = Vec::new();

    for base in CONFIG_BASE_FILES {
        let config_path = Path::new(CONFIG_BASE_DIR).join(base);
        let raw_file = fs::read_to_string(&config_path)?;

        let mut config = compile_flat_config(CONFIG_ENV_PREFIX, &raw_file)?;
        flat_config.append(&mut config);
    }

    let env_out = flat_config
        .into_iter()
        .fold(String::new(), |mut acc, (key, value)| {
            acc.push_str(&format!("{key}={value}\n"));
            acc
        });

    let path = Path::new(CONFIG_ENV_PATH);

    let result = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(CONFIG_ENV_PATH);
    if let Err(err) = &result {
        if err.kind() == io::ErrorKind::AlreadyExists {
            if force {
                tracing::debug!(
                    target: LOG_TARGET,
                    "path {} already exists, overwriting",
                    path.display()
                );
                fs::write(CONFIG_ENV_PATH, env_out)?;
            }
            return Ok(());
        }
    }

    let mut file = result?;
    file.write_all(env_out.as_bytes())?;
    tracing::debug!(
        target: LOG_TARGET,
        "saved config to {}",
        path.display()
    );

    Ok(())
}

fn compile_flat_config(prefix: &str, raw_table: &str) -> anyhow::Result<Vec<(String, String)>> {
    let mut values = Vec::new();
    let toml_config: toml::Table = toml::from_str(&raw_table)?;

    parse_table(prefix, &toml_config, &mut values);
    Ok(values)
}

fn parse_table(prefix: &str, table: &toml::Table, out: &mut Vec<(String, String)>) {
    for (key, value) in table {
        let key = key.to_ascii_uppercase();
        let prefix = [prefix, &key].join(CONFIG_SEPARATOR);
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
            ("PREFIX__IP", "127.0.0.1"),
            ("PREFIX__DB__URL", "test.url"),
            ("PREFIX__DB__CONN_LIMIT", "10"),
            ("PREFIX__DB__INNER__URL", "test.url.1"),
        ];
        assert_eq!(env.len(), expected.len());

        for (key, value) in expected {
            assert!(env.contains(&(key.into(), value.into())));
        }
    }
}
