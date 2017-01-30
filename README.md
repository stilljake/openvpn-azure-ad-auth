
OpenVPN Azure Active Directory Auth
===================================

This is a helper script intended for use with OpenVPN to add support for authentication
and authorization using Azure Active Directory.

Installation and Configuration
------------------------------

This is a standalone script which relies on the [ADAL](https://github.com/AzureAD/azure-activedirectory-library-for-python), [PyYAML](http://pyyaml.org), and [requests](http://docs.python-requests.org/en/master/) libraries.

Configuration is simple! After [creating a "native" application](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-integrating-applications#adding-an-application) in Azure Active Directory, take note of its Application ID.

Create a `config.yaml` file according to the following example:

```yaml
tenant_id: {{Your AAD tenant ID}}
client_id: {{Your new AAD Application's ID}}
permitted_groups: # this list is optional!
  - {{AAD group displayName}}
```

OpenVPN Configuration
---------------------

Configure your OpenVPN server to use the `auth-user-pass-verify` option. The `method` must be set to `via-env`, so that the server will pass interactively-entered credentials to the script via environment variables. This script does not support file mode. The `script-security` option must be set to `3`.

An example OpenVPN config file stub is:
```
auth-user-pass-verify openvpn-azure-ad-auth.py via-env
script-security 3 execve
```
