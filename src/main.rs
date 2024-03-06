use nss_keycloak::KeycloakPasswd;
use libnss::passwd::PasswdHooks;

fn main() {
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
}
