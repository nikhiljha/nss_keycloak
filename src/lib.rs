extern crate libc;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate libnss;

use anyhow::{Context, Result};
use keycloak::{KeycloakAdmin, KeycloakTokenSupplier};
use libnss::{
    interop::Response,
    passwd::{Passwd, PasswdHooks},
};
use std::{fs, os::unix::fs::MetadataExt};

struct KCPassthroughTokenSupplier {
    keycloak_oidc_token: String,
}

#[async_trait::async_trait]
impl KeycloakTokenSupplier for KCPassthroughTokenSupplier {
    async fn get(&self, _url: &str) -> Result<String, keycloak::KeycloakError> {
        Ok(self.keycloak_oidc_token.clone())
    }
}

struct Config {
    keycloak_oidc_token: String,
    keycloak_url: String,
    keycloak_realm: String,
}

impl Config {
    /// Read the variables from the environment (TODO: does this work)?
    fn from_config_file() -> Result<Self> {
        let config_contents = std::env::var("KEYCLOAK_NSS_CONFIG")?;
        let config: serde_json::Value = serde_json::from_str(&config_contents)?;

        let keycloak_oidc_token = config["keycloak_oidc_token"]
            .as_str()
            .context("no oidc token")?
            .to_string();
        let keycloak_url = config["keycloak_url"]
            .as_str()
            .context("no keycloak url")?
            .to_string();
        let keycloak_realm = config["keycloak_realm"]
            .as_str()
            .context("no realm")?
            .to_string();

        Ok(Config {
            keycloak_oidc_token,
            keycloak_url,
            keycloak_realm,
        })
    }
}

fn get_keycloak_client(config: &Config) -> KeycloakAdmin<KCPassthroughTokenSupplier> {
    let client = reqwest::Client::new();
    let token = KCPassthroughTokenSupplier {
        keycloak_oidc_token: config.keycloak_oidc_token.clone(),
    };
    KeycloakAdmin::new(&config.keycloak_url, token, client)
}

fn serialize_passwd_entry(passwd: &Passwd) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}:{}",
        passwd.name, passwd.passwd, passwd.uid, passwd.gid, passwd.gecos, passwd.dir, passwd.shell
    )
}

fn deserialize_passwd_entry(entry: &str) -> Passwd {
    let parts: Vec<&str> = entry.split(':').collect();
    Passwd {
        name: parts[0].to_string(),
        passwd: parts[1].to_string(),
        uid: parts[2].parse().unwrap(),
        gid: parts[3].parse().unwrap(),
        gecos: parts[4].to_string(),
        dir: parts[5].to_string(),
        shell: parts[6].to_string(),
    }
}

fn user_to_passwd(user: keycloak::types::UserRepresentation) -> Option<Passwd> {
    let attributes = user.attributes?;
    let username = user.username?;

    Some(Passwd {
        name: username.clone(),
        passwd: "x".to_string(),
        uid: attributes
            .get("unix_uid")?
            .as_array()?
            .first()?
            .as_str()?
            .parse()
            .ok()?,
        gid: attributes
            .get("unix_gid")?
            .as_array()?
            .first()?
            .as_str()?
            .parse()
            .ok()?,
        gecos: format!("{} {}", user.first_name?, user.last_name?),
        dir: format!("/home/{}", username),
        shell: "/bin/bash".to_string(),
    })
}

#[tokio::main(flavor = "current_thread")]
async fn get_all_entries() -> Response<Vec<Passwd>> {
    // Read the user list from the cache at /var/cache/keycloak-nss/passwd
    let cache_file = "/tmp/keycloak-nss-passwd";
    let cache_contents = fs::read_to_string(cache_file);
    if let Ok(cache_contents) = cache_contents {
        // Make sure the cache is owned by the current user
        let metadata = fs::metadata(cache_file).unwrap();
        if metadata.uid() != unsafe { libc::getuid() } {
            eprintln!("Cache file is not owned by the current user, unsafe!");
            return Response::NotFound;
        }
        let entries: Vec<Passwd> = cache_contents
            .lines()
            .map(|line| deserialize_passwd_entry(line))
            .collect();
        return Response::Success(entries);
    }

    let config = match Config::from_config_file() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error reading config: {:?}", e);
            return Response::NotFound;
        }
    };

    let keycloak = get_keycloak_client(&config);
    let users = match keycloak
        .realm_users_get(
            &config.keycloak_realm,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
    {
        Ok(users) => users,
        Err(e) => {
            eprintln!("Error getting users: {:?}", e);
            return Response::NotFound;
        }
    };

    let users: Vec<Passwd> = users
        .iter()
        .filter_map(|user| user_to_passwd(user.clone()))
        .collect();

    // Serialize out the users to the cache file
    let cache_contents = users
        .iter()
        .map(|user| serialize_passwd_entry(user))
        .collect::<Vec<String>>()
        .join("\n");
    fs::write(cache_file, cache_contents).unwrap();

    Response::Success(users)
}

pub struct KeycloakPasswd;
libnss_passwd_hooks!(keycloak, KeycloakPasswd);

impl PasswdHooks for KeycloakPasswd {
    fn get_all_entries() -> Response<Vec<Passwd>> {
        get_all_entries()
    }

    fn get_entry_by_uid(uid: libc::uid_t) -> Response<Passwd> {
        match KeycloakPasswd::get_all_entries() {
            Response::Success(v) => v
                .into_iter()
                .find(|entry| entry.uid == uid)
                .map(Response::Success)
                .unwrap_or(Response::NotFound),
            _ => Response::NotFound,
        }
    }

    fn get_entry_by_name(name: String) -> Response<Passwd> {
        match KeycloakPasswd::get_all_entries() {
            Response::Success(v) => v
                .into_iter()
                .find(|entry| entry.name == name)
                .map(Response::Success)
                .unwrap_or(Response::NotFound),
            _ => Response::NotFound,
        }
    }
}
