# nss_keycloak

This project is a simple nss module that pulls `passwd` and `groups` from Keycloak. This is useful for setups where you don't have LDAP, but need to dynamically provision users.

## Quirks

This was written fairly quickly and is not feature complete. It is fairly simple to fix any/all of the below, and I will review any PRs that do so.

- It assumes you have an OIDC token on first use. This is a strange assumption that's only really valid for my use case.
- The caching behavior just writes to a hardcoded file name in `/tmp` and makes sure permissions are good. This is probably insecure on a multi user system. I haven't really thought about it.
  - Why do I need nss on a single user system? How did we get here? Good question.
- Also, I never tested what happens when this program prints an error. Where do the errors go? Maybe I should have written them to a log instead? If this causes funny behavior send a screenshot because I wanna see.

## Usage

Every user must have `unix_uid` and `unix_gid` as attributes. Every group must have `unix_gid` as an attribute. All IDs must be unique. I don't know what happens if they're not unique but this is not handled.
