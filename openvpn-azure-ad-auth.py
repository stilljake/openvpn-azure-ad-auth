#!/usr/bin/env python

'''
This script will accept a username and password from OpenVPN, and use them to obtain
an authentication token from Azure AD.
'''

#pylint: disable=invalid-name

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

config_file = 'config.yaml'

try:
    with open(config_file) as cfg:
        config = yaml.load(cfg.read())
except IOError as err:
    logger.critical("Could not open config file %s", config_file)
    failure()
except yaml.scanner.ScannerError as err:
    logger.critical("Config file %s failed to load: %s", config_file, err)
    failure()

log_level = getattr(logging, config['log_level'].upper(), None) if 'log_level' in config else logging.INFO
logger.setLevel(log_level)
adal.set_logging_options({'level': log_level})

try:
    tenant_id = config['tenant_id']
    authority_url = "https://login.microsoftonline.com/{}".format(tenant_id)
    client_id = config['client_id']
    resource = config['resource'] if 'resource' in config else 'https://graph.windows.net'
except KeyError as err:
    logger.error("invalid config file! could not find %s", err)
    failure()

context = adal.AuthenticationContext(authority_url)

if len(sys.argv) == 2 and sys.argv[1] == "--consent":
    try:
        code = context.acquire_user_code(resource, client_id)
        print code['message']
        token = context.acquire_token_with_device_code(resource, code, client_id)
    except adal.adal_error.AdalError as err:
        logger.error("Failed to get consent %s", err)
        failure()
    except KeyboardInterrupt:
        context.cancel_request_to_get_token_with_device_code(code)
        logger.info("Cancelled code request")
        failure()
    else:
        success()


try:
    username = os.environ['username']
    password = os.environ['password']
except KeyError:
    logger.error("Environment variables `username` and `password` must be set")
    failure()


try:
    token = context.acquire_token_with_username_password(
        resource,
        username,
        password,
        client_id
    )
except adal.adal_error.AdalError as err:
    logger.info("User %s failed to authenticate: %s", username, err)
    failure()

if 'permitted_groups' not in config:
    success()

groups = []

graph_url = "https://graph.windows.net/me/memberOf?api-version=1.6"

while True:
    header = {
        "Authorization": "Bearer {}".format(token['accessToken']),
        "Content-Type": "application/json"
    }
    try:
        resp = requests.get(
            graph_url,
            headers=header
        )
        resp.encoding = "utf-8-sig"
        data = resp.json()
    except Exception as err: #pylint: disable=broad-except
        logger.error("Graph API request unsuccessful: %s", err)
        failure()

    if 'odata.error' in data:
        logger.error("User %s could not get graph data: %s", username, data)
        failure()

    try:
        # Exit early if we've found a permitted group
        for group in [v['displayName'] for v in data['value']]:
            if group in config['permitted_groups']:
                success()
    except KeyError as err:
        if err.message == 'value':
            logger.debug("no 'value' key in returned group data %s", resp.text)
        elif err.message == 'displayName':
            logger.debug("no 'displayName' in group value: %s", v)
        else:
            logger.error("Unhandled KeyError getting '%s' out of response '%s'", err, resp.text)
            failure()

    if "odata.nextLink" in data:
        graph_url = "https://graph.windows.net/{}/{}&api-version=1.6".format(
            tenant_id,
            data["odata.nextLink"]
        )
    else:
        break


logger.info("User %s not authorized", username)
failure()
