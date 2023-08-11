#!/usr/bin/env python

'''
This script will accept a username and password from OpenVPN, and use them to obtain
an authentication token from Azure AD.
'''

#pylint: disable=invalid-name

import binascii
#import hashlib
#from hmac import compare_digest
from backports.pbkdf2 import pbkdf2_hmac, compare_digest
import logging
import os
import sys

import adal
import requests
import yaml

loggerName = __name__
logging.basicConfig(
    format='%(asctime) 25s openvpn-azure-aad-auth %(levelname) 7s %(pathname)s %(module)s: %(message)s'
)
logger = logging.getLogger(loggerName)

def success():
    ''' The user has authenticated and is authorized '''
    sys.exit(0)

def failure():
    ''' The user failed to authenticate or authorize. Exit with an error code '''
    sys.exit(1)

CONFIG_FILE = 'config.yaml'

def main(config_file):
    try:
        username = os.environ['username']
        password = os.environ['password']
    except KeyError:
        logger.error("Environment variables `username` and `password` must be set")
        failure()

    try:
        with open(config_file) as cfg:
            config = yaml.load(cfg.read(), Loader=yaml.Loader)
    except IOError as err:
        logger.critical("Could not open config file %s", config_file)
        failure()
    except yaml.scanner.ScannerError as err:
        logger.critical("Config file %s failed to load: %s", config_file, err)
        failure()

    set_log_level(getattr(logging, config.get('log_level', "INFO").upper()))

    try:
        tenant_id = config['tenant_id']
        authority_url = "https://login.microsoftonline.com/{}".format(tenant_id)
        client_id = config['client_id']
        resource = config['resource'] if 'resource' in config else 'https://graph.windows.net'
    except KeyError as err:
        logger.error("invalid config file! could not find %s", err)
        failure()

    token_cache_file = config.get('token_cache_file')
    token_cache = read_token_cache(token_cache_file)
    context = adal.AuthenticationContext(authority_url, cache=token_cache)

    if len(sys.argv) == 2 and sys.argv[1] == "--consent":
        if obtain_consent(context, resource, client_id):
            success()
        else:
            failure()

    logger.info("request recieved to authenticate user %s", username)

    token, save_cache = get_token(context, resource, username, password, client_id)
    if token is None:
        failure()

    if 'permitted_groups' not in config or \
            check_group_membership(token, tenant_id, config['permitted_groups']):
        if save_cache:
            save_token_cache(token_cache_file, context.cache)
        success()

    logger.info("User %s not authorized", username)
    failure()


def set_log_level(log_level):
    logger.setLevel(log_level)
    adal.set_logging_options({'level': log_level})

def read_token_cache(token_cache_file):
    if token_cache_file is None:
        return None
    token_cache = None
    try:
        logger.debug("reading token cache from %s", token_cache_file)
        token_cache_fd = os.open(token_cache_file, os.O_CREAT, 0o600)
        with os.fdopen(token_cache_fd, 'r') as token_cache_fh:
            token_cache = adal.TokenCache(state=token_cache_fh.read())
    except IOError as err:
        logger.error(
            "could not open token cache file %s: %s. continuing without cache",
            token_cache_file, err)
        os.close(token_cache_fd)
    except ValueError as err:
        logger.error("could not load cache from disk: %s", err)
    return token_cache


def save_token_cache(token_cache_file, token_cache):
    if token_cache is None or token_cache_file is None:
        return
    try:
        token_cache_fd = os.open(
            token_cache_file,
            os.O_TRUNC | os.O_CREAT | os.O_WRONLY,
            0o600
        )
        with os.fdopen(token_cache_fd, 'w') as token_cache_fh:
            token_cache_fh.write(token_cache.serialize())
            logger.debug("wrote token cache info to %s", token_cache_file)
    except IOError as err:
        logger.warning(
            "could not write to token cache file %s: %s",
            token_cache_file, err)
        os.close(token_cache_fd)

def obtain_consent(context, resource, client_id):
    try:
        code = context.acquire_user_code(resource, client_id)
        print(code['message'])
        _ = context.acquire_token_with_device_code(resource, code, client_id)
    except adal.adal_error.AdalError as err:
        logger.error("Failed to get consent %s", err)
        return False
    except KeyboardInterrupt:
        context.cancel_request_to_get_token_with_device_code(code)
        logger.info("Cancelled code request")
        return False
    else:
        return True


def get_token(context, resource, username, password, client_id):
    """

    Get a JWT as evidence of authentication.

    Using the provided ADAL authentication context, attempt to get a JWT from the cache (if
    enabled). If the cache misses or the cached refresh token cannot be exchanged, interrogate
    AAD for a new JWT.

    Returns: Either a valid token bundle or None, and a flag indicating that the cache is stale
               and should be updated.

    Side-effects: the token bundle that is returned is a reference to the token inside the
                    context's cache member. As such, this function modifies `context`.

    """
    try:
        # Get a token from the cache (avoids a round-trip to AAD if the cached token hasn't expired)
        try:
            token = context.acquire_token(resource, username, client_id)
        except adal.adal_error.AdalError as err: # see issue #3
            token = None
        if token is not None:
            password_hmac = hash_password(token, password)
            if compare_digest(bytes(password_hmac), bytes(token['passwordHash'])):
                return token, False
                logger.info("authenticated user %s from cache", username)

        logger.debug("could not get a token from cache; acquiring from AAD")
        token = context.acquire_token_with_username_password(
            resource,
            username,
            password,
            client_id
        )
    except adal.adal_error.AdalError as err:
        logger.info("User %s failed to authenticate: %s", username, err)
        return None, False
    token['passwordHash'] = hash_password(token, password)
    logger.info("authenticated user %s from AAD request", username)
    return token, True


def hash_password(token, password):
    # return binascii.hexlify(pbkdf2_hmac('sha512', password, token['accessToken'], 128000))
    password_bytes = bytearray(password.encode('utf-8'))
    salt_bytes = bytearray(token['accessToken'].encode('utf-8'))
    value = pbkdf2_hmac('sha512', password_bytes, salt_bytes, 128000)
    return binascii.hexlify(value)

def check_group_membership(token, tenant_id, permitted_groups):
    graph_url = "https://graph.windows.net/me/memberOf?api-version=1.6"

    while True:
        header = {
            "Authorization": "Bearer {}".format(token['accessToken']),
            "Content-Type": "application/json"
        }
        try:
            logger.debug("requesting a batch of group info")
            resp = requests.get(
                graph_url,
                headers=header
            )
            resp.encoding = "utf-8-sig"
            data = resp.json()
        except Exception as err: #pylint: disable=broad-except
            logger.error("Graph API request unsuccessful: %s", err)
            return False

        if 'odata.error' in data:
            logger.error("could not get graph data: %s", data)
            return False

        try:
            # Exit early if we've found a permitted group
            for group in [v['displayName'] for v in data['value']]:
                if group in permitted_groups:
                    return True
        except KeyError as err:
            if err.message == 'value':
                logger.debug("no 'value' key in returned group data %s", resp.text)
            elif err.message == 'displayName':
                logger.debug("no 'displayName' in group value: %s", v)
            else:
                logger.error("Unhandled KeyError getting '%s' out of response '%s'", err, resp.text)
                return False

        if "odata.nextLink" in data:
            graph_url = "https://graph.windows.net/{}/{}&api-version=1.6".format(
                tenant_id,
                data["odata.nextLink"]
            )
        else:
            break
    return False


if __name__ == "__main__":
    main(CONFIG_FILE)
