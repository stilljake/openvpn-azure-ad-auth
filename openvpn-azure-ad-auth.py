#!/usr/bin/env python

'''
This script will accept a username and password from OpenVPN, and use them to obtain
an authentication token from Azure AD.
'''

#pylint: disable=invalid-name

import os
import sys

import adal
import requests
import yaml

#import logging
#logging.basicConfig(level=logging.DEBUG)

def success():
    ''' The user has authenticated and is authorized '''
    sys.exit(0)

def failure(msg):
    ''' The user failed to authenticate or authorize. Emit the msg and exit with an error code '''
    print msg
    sys.exit(1)

config_file = 'config.yaml'

try:
    with open(config_file) as cfg:
        config = yaml.load(cfg.read())
except IOError as e:
    failure("Could not open config file {}".format(config_file))

try:
    tenant_id = config['tenant_id']
    authority_url = "https://login.microsoftonline.com/{}".format(tenant_id)
    client_id = config['client_id']
    resource = config['resource'] if 'resource' in config else 'https://graph.windows.net'
except KeyError as err:
    failure("invalid config file! could not find {}".format(err))

context = adal.AuthenticationContext(authority_url)

if len(sys.argv) == 2 and sys.argv[1] == "--consent":
    try:
        code = context.acquire_user_code(resource, client_id)
        print code['message']
        token = context.acquire_token_with_device_code(resource, code, client_id)
    except adal.adal_error.AdalError as err:
        failure("Failed to get consent! {}".format(err))
    except KeyboardInterrupt:
        context.cancel_request_to_get_token_with_device_code(code)
        failure("Cancelled code request")
    else:
        success()

try:
    username = os.environ['username']
    password = os.environ['password']
except KeyError:
    failure("Environment variables `username` and `password` must be set")


try:
    token = context.acquire_token_with_username_password(
        resource,
        username,
        password,
        client_id
    )
except adal.adal_error.AdalError as err:
    failure("Could not authenticate! {}".format(err))

if 'permitted_groups' not in config:
    success()

groups = []

graph_url = "https://graph.windows.net/me/memberOf?api-version=1.6"

while True:
    header = {
        "Authorization": "Bearer {}".format(token['accessToken']),
        "Content-Type": "application/json"
    }
    resp = requests.get(
        graph_url,
        headers=header
    )
    resp.encoding = "utf-8-sig"
    data = resp.json()

    if 'odata.error' in data:
        failure("Could not get graph data! {}".format(data))

    try:
        # Exit early if we've found a permitted group
        for group in [v['displayName'] for v in data['value']]:
            if group in config['permitted_groups']:
                success()
    except KeyError as err:
        if err.message == 'value':
            raise RuntimeError("no 'value' key in returned group data {}".format(resp.text))
        elif err.message == 'displayName':
            print "no 'displayName' for value v: {}".format(v)
        else:
            raise err

    if "odata.nextLink" in data:
        graph_url = "https://graph.windows.net/{}/{}&api-version=1.6".format(
            tenant_id,
            data["odata.nextLink"]
        )
    else:
        break

failure("User not authorized!")
