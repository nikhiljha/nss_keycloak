use nss_keycloak::{KeycloakGroup, KeycloakPasswd};
use libnss::{group::GroupHooks, passwd::PasswdHooks};

fn main() {
    println!("# passwds");
    let passwds = KeycloakPasswd::get_all_entries();
    match passwds {
        libnss::interop::Response::TryAgain => todo!(),
        libnss::interop::Response::Unavail => todo!(),
        libnss::interop::Response::NotFound => todo!(),
        libnss::interop::Response::Success(passwds) => {
            for passwd in passwds {
                println!(
                    "{}:{}:{}:{}:{}:{}:{}",
                    passwd.name,
                    passwd.passwd,
                    passwd.uid,
                    passwd.gid,
                    passwd.gecos,
                    passwd.dir,
                    passwd.shell
                );
            }
        },
        libnss::interop::Response::Return => todo!(),
    }

    println!("# groups");
    let groups = KeycloakGroup::get_all_entries();
    match groups {
        libnss::interop::Response::TryAgain => todo!(),
        libnss::interop::Response::Unavail => todo!(),
        libnss::interop::Response::NotFound => todo!(),
        libnss::interop::Response::Success(groups) => {
            for group in groups {
                println!(
                    "{}:{}:{}:{}",
                    group.name,
                    group.passwd,
                    group.gid,
                    group.members.join(",")
                );
            }
        },
        libnss::interop::Response::Return => todo!(),
    }
}
