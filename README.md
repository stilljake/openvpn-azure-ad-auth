
OpenVPN Azure Active Directory Auth
===================================

This is a helper script intended for use with OpenVPN to add support for authentication
and authorization using Azure Active Directory.

Installation and Configuration
------------------------------

This is a standalone script which relies on the [ADAL](https://github.com/AzureAD/azure-activedirectory-library-for-python), [PyYAML](http://pyyaml.org), and [requests](http://docs.python-requests.org/en/master/) libraries.

Configuration is simple! After [creating a "native" application](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-integrating-applications#adding-an-application) in Azure Active Directory, take note of its Application ID.

Create a `config.yaml` file according to the following example, and place it alongside the script:

```yaml
tenant_id: {{Your AAD tenant ID}}
client_id: {{Your new AAD Application's ID}}
permitted_groups: # optional; defaults to allow-all
  - {{AAD group displayName}}
log_level: DEBUG  # optional; defaults to INFO. valid levels are CRITICAL, ERROR, WARNING, INFO, DEBUG (from `logging`)
token_cache_file: {{token_cache_filename}} # optional; if absent, tokens will not be cached. See Token Caching below
```

OpenVPN Configuration
---------------------

Configure your OpenVPN server to use the `auth-user-pass-verify` option. The `method` must be set to `via-env`, so that the server will pass interactively-entered credentials to the script via environment variables. This script does not support file mode. The `script-security` option must be set to `3`.

An example OpenVPN config file stub is:
```
auth-user-pass-verify openvpn-azure-ad-auth.py via-env
script-security 3 execve
```

User Consent
------------

In order to use this application, end users must consent to the application accessing the Graph API on the user's behalf. Because this script is called by the OpenVPN server process in the background, there is no opportunity to interactively request consent.

To make gathering consent a little bit easier, the script accepts a `--consent` flag. The `config.yaml` file must exist and have the `tenant_id` and `client_id` values populated, but these values are not secrets to be protected. When run, the script looks like this:
```bash
$ ./openvpn-azure-ad-auth.py --consent
To sign in, use a web browser to open the page https://aka.ms/devicelogin and enter the code xxxxxxxxx to authenticate.
$
```

Token Caching
-------------

If token caching is enabled, JWTs will be written to the specified file and the file will be checked for not-yet-expired tokens for the Graph API. If an unexpired token is found, the authentication is considered successful and the login process either succeeds or group checks begin.

This has some security implications! By avoiding a trip to AAD, a disabled user can still connect until its token expires. You can invalidate all tokens by deleting the cache. These tokens should also be protected. The default mode is expected to be 0o0600.

A note on concurrency: no great care has been taken to avoid writes getting clobbered. The token cache reads its state from disk, and then may write that same state to disk, plus updates. If the state file changes between reading and writing, cached tokens can be lost. We also happily clobber the cache file if loading it fails, e.g. in the case of corruption.

Return Value
------------

The script returns `0` on success, and `1` on failure.
