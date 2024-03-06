extern crate libc;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate libnss;

use anyhow::{Context, Result};
use keycloak::{types::UserRepresentation, KeycloakAdmin, KeycloakTokenSupplier};
use libnss::{
    group::{Group, GroupHooks},
    interop::Response,
    passwd::{Passwd, PasswdHooks},
};
use std::{fs, os::unix::fs::MetadataExt};

// See libnss for how this works...
pub struct KeycloakPasswd;
libnss_passwd_hooks!(keycloak, KeycloakPasswd);

pub struct KeycloakGroup;
libnss_group_hooks!(keycloak, KeycloakGroup);

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

fn serialize_users(users: Vec<UserRepresentation>) -> Option<String> {
    serde_json::to_string(&users).ok()
}

fn deserialize_users(users: &str) -> Option<Vec<UserRepresentation>> {
    serde_json::from_str(users).ok()
}

fn serialize_group(group: Group) -> String {
    // manually serialize into the format of /etc/group
    format!(
        "{}:{}:{}:{}",
        group.name,
        group.passwd,
        group.gid,
        group.members.join(",")
    )
}

fn deserialize_group(group: &str) -> Option<Group> {
    let parts: Vec<&str> = group.split(':').collect();
    if parts.len() != 4 {
        return None;
    }

    Some(Group {
        name: parts[0].to_string(),
        passwd: parts[1].to_string(),
        gid: parts[2].parse().ok()?,
        members: parts[3].split(',').map(|s| s.to_string()).collect(),
    })
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

fn group_to_nss(
    group: keycloak::types::GroupRepresentation,
    users: Vec<UserRepresentation>,
) -> Option<Group> {
    let attributes = group.attributes?;
    let name = group.name?;

    Some(Group {
        name: name.clone(),
        passwd: "x".to_string(),
        gid: attributes
            .get("unix_gid")?
            .as_array()?
            .first()?
            .as_str()?
            .parse()
            .ok()?,
        members: users
            .iter()
            .filter_map(|user| {
                if let Some(user_groups) = user.groups.clone() {
                    if user_groups.contains(&name) {
                        return user.username.clone();
                    }
                }
                None
            })
            .collect(),
    })
}

async fn get_all_keycloak_users() -> Vec<UserRepresentation> {
    let cache_file = "/tmp/keycloak-nss-users.json";
    let cache_contents = fs::read_to_string(cache_file);
    if let Ok(cache_contents) = cache_contents {
        // Make sure the cache is owned by the current user
        let metadata = fs::metadata(cache_file).unwrap();
        if metadata.uid() != unsafe { libc::getuid() } {
            eprintln!("Cache file is not owned by the current user, unsafe!");
            return vec![];
        }

        // Deserialize the cache file
        return match deserialize_users(&cache_contents) {
            Some(users) => users,
            None => vec![],
        };
    }

    let config = match Config::from_config_file() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error reading config: {:?}", e);
            return vec![];
        }
    };

    let keycloak = get_keycloak_client(&config);
    let kc_users = match keycloak
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
            return vec![];
        }
    };

    // Serialize out the users to the cache file, don't care if it fails.
    let _ = serialize_users(kc_users.clone()).map(|u| fs::write(cache_file, u));

    kc_users
}

async fn get_all_passwd_entries() -> Response<Vec<Passwd>> {
    let kc_users = get_all_keycloak_users().await;
    let passwd_entries: Vec<Passwd> = kc_users
        .iter()
        .filter_map(|user| user_to_passwd(user.clone()))
        .collect();

    Response::Success(passwd_entries)
}

async fn get_all_groups() -> Response<Vec<Group>> {
    // Try to load groups cache
    let cache_file = "/tmp/keycloak-nss-groups";
    let cache_contents = fs::read_to_string(cache_file);
    if let Ok(cache_contents) = cache_contents {
        // Make sure the cache is owned by the current user
        let metadata = fs::metadata(cache_file).unwrap();
        if metadata.uid() != unsafe { libc::getuid() } {
            eprintln!("Cache file is not owned by the current user, unsafe!");
            return Response::NotFound;
        }

        // Deserialize the cache file line by line
        return Response::Success(
            cache_contents
                .lines()
                .filter_map(|line| deserialize_group(line))
                .collect(),
        );
    }

    let config = match Config::from_config_file() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error reading config: {:?}", e);
            return Response::NotFound;
        }
    };

    let keycloak = get_keycloak_client(&config);
    let groups = match keycloak
        .realm_groups_get(&config.keycloak_realm, None, None, None, None, None, None)
        .await
    {
        Ok(groups) => groups,
        Err(e) => {
            eprintln!("Error getting groups: {:?}", e);
            return Response::NotFound;
        }
    };

    let users = get_all_keycloak_users().await;
    let groups: Vec<Group> = groups
        .iter()
        .flat_map(|group| group_to_nss(group.clone(), users.clone()))
        .collect();

    // Serialize out the groups to the cache file, don't care if it fails.
    let group_ser = groups
        .iter()
        .map(|group| serialize_group(group.clone()))
        .collect::<Vec<String>>()
        .join("\n");
    let _ = fs::write(cache_file, group_ser);

    Response::Success(groups)
}

/// Shim function to allow async functions to be called from the NSS hooks
#[tokio::main(flavor = "current_thread")]
async fn passwd_get_all_entries() -> Response<Vec<Passwd>> {
    get_all_passwd_entries().await
}

impl PasswdHooks for KeycloakPasswd {
    fn get_all_entries() -> Response<Vec<Passwd>> {
        passwd_get_all_entries()
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

/// Shim function to allow async functions to be called from the NSS hooks
#[tokio::main(flavor = "current_thread")]
async fn groups_get_all_entries() -> Response<Vec<Group>> {
    get_all_groups().await
}

impl GroupHooks for KeycloakGroup {
    fn get_all_entries() -> Response<Vec<libnss::group::Group>> {
        groups_get_all_entries()
    }

    fn get_entry_by_gid(gid: libc::gid_t) -> Response<libnss::group::Group> {
        match groups_get_all_entries() {
            Response::Success(v) => v
                .into_iter()
                .find(|entry| entry.gid == gid)
                .map(Response::Success)
                .unwrap_or(Response::NotFound),
            _ => Response::NotFound,
        }
    }

    fn get_entry_by_name(name: String) -> Response<libnss::group::Group> {
        match groups_get_all_entries() {
            Response::Success(v) => v
                .into_iter()
                .find(|entry| entry.name == name)
                .map(Response::Success)
                .unwrap_or(Response::NotFound),
            _ => Response::NotFound,
        }
    }
}
