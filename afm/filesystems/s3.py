#
# Copyright 2020 IBM Corp.
# SPDX-License-Identifier: Apache-2.0
#
from urllib.parse import urlparse, quote
import requests
from fybrik_python_logging import logger, Error, DataSetID, ForUser
from pyarrow.fs import S3FileSystem
from fybrik_python_vault import get_jwt_from_file, get_raw_secret_from_vault
import afm.utils.tls as tls
from afm.environment.environment import *

import ssl

def create_ssl_context(tls_min_version=None):
        context = ssl.create_default_context()
        if tls_min_version != None:
            context.minimum_version = tls_min_version
        return context
    
# adapted from https://stackoverflow.com/questions/42981429/ssl-failure-on-windows-using-python-requests/50215614
class SSLContextAdapter(requests.adapters.HTTPAdapter):
        
    def __init__(self, ssl_context=None, **kwargs):
        self.ssl_context = ssl_context
        super().__init__(**kwargs)
        
    def init_poolmanager(self, *args, **kwargs):
        kwargs['ssl_context'] = self.ssl_context
        return super(SSLContextAdapter, self).init_poolmanager(*args, **kwargs)


def get_jwt_from_file(file_name):
    """
    Getting a jwt from a file.
    Typically, an SA token, which would be at: /var/run/secrets/kubernetes.io/serviceaccount/token
    """
    with open(file_name) as f:
        return f.read()


def vault_jwt_auth(jwt, vault_address, vault_path, role, datasetID, verify=None, cert=None):
    """Authenticate against Vault using a JWT token (i.e., k8s sa token)"""
    full_auth_path = vault_address + vault_path
    logger.trace('authenticating against vault using a JWT token',
        extra={'full_auth_path': str(full_auth_path),
               DataSetID: datasetID})
    json = {"jwt": jwt, "role": role}
    headers = {
        'Content-Type' : 'application/json'
    }
    
    tls_minimum_version = get_min_tls_version()      
    context = create_ssl_context(tls_minimum_version)
        
    s = requests.Session()
    s.mount("https://vault", SSLContextAdapter(context))
    ca_cert_path = tls.get_cacert_path()
    verify = None
    if ca_cert_path != "":
        logger.debug("set cacert path to "+ ca_cert_path)
        verify = ca_cert_path
        
    cert = None
    certs_tuple = tls.get_certs()
    if certs_tuple:
        logger.debug("set certs tuple", certs_tuple)
        cert = certs_tuple

    response = s.post(full_auth_path, data=json, headers=headers, verify=verify, cert=cert)

    if response.status_code == 200:
        return response.json()
    """_summary_

    Returns:
        _type_: _description_
    """    logger.error("vault authentication failed",
        extra={Error: str(response.status_code) + ': ' + str(response.json()),
               DataSetID: datasetID, ForUser: True})
    return None

def get_raw_secret_from_vault(jwt, secret_path, vault_address, vault_path, role, datasetID, verify=None, cert=None):
    """Get a raw secret from vault by providing a valid jwt token"""
    logger.trace('getting vault credentials',
        extra={'vault_address': str(vault_address),
               'secret_path': str(secret_path),
               'vault_path': str(vault_path),
               'role': str(role),
               DataSetID: datasetID,
               ForUser: True})
    vault_auth_response = vault_jwt_auth(jwt, vault_address, vault_path, role, datasetID)
    if vault_auth_response is None:
        logger.error("Empty vault authorization response",
                     extra={DataSetID: datasetID, ForUser: True})
        return None
    if not "auth" in vault_auth_response or not "client_token" in vault_auth_response["auth"]:
        logger.error("Malformed vault authorization response",
                     extra={DataSetID: datasetID, ForUser: True})
        return None
    client_token = vault_auth_response["auth"]["client_token"]
    secret_full_path = vault_address + secret_path
    response = requests.get(secret_full_path, headers={"X-Vault-Token" : client_token}, verify=verify, cert=cert)
    logger.debug('Response received from vault when accessing credentials: ' + str(response.status_code),
        extra={'credentials_path': str(secret_full_path),
               DataSetID: datasetID, ForUser: True})
    if response.status_code == 200:
        response_json = response.json()
        if 'data' in response_json:
            return response_json['data']
        else:
            logger.error("Malformed secret response. Expected the 'data' field in JSON",
                         extra={DataSetID: datasetID, ForUser: True})
    else:
        logger.error("Error reading credentials from vault",
            extra={Error: str(response.status_code) + ': ' + str(response.json()),
                   DataSetID: datasetID, ForUser: True})
    return None

def get_s3_credentials_from_vault(vault_credentials, datasetID):
    jwt_file_path = vault_credentials.get('jwt_file_path', '/var/run/secrets/kubernetes.io/serviceaccount/token')
    jwt = get_jwt_from_file(jwt_file_path)
    vault_address = vault_credentials.get('address', 'https://localhost:8200')
    secret_path = vault_credentials.get('secretPath', '/v1/secret/data/cred')
    vault_auth = vault_credentials.get('authPath', '/v1/auth/kubernetes/login')
    role = vault_credentials.get('role', 'demo')
    
    credentials = get_raw_secret_from_vault(jwt, secret_path, vault_address, vault_auth, role, datasetID)
    if not credentials:
        raise ValueError("Vault credentials are missing")
    if 'access_key' in credentials and 'secret_key' in credentials:
        if credentials['access_key'] and credentials['secret_key']:
            return credentials['access_key'], credentials['secret_key']
        else:
            if not credentials['access_key']:
                logger.error("'access_key' must be non-empty",
                             extra={DataSetID: datasetID, ForUser: True})
            if not credentials['secret_key']:
                logger.error("'secret_key' must be non-empty",
                             extra={DataSetID: datasetID, ForUser: True})
    logger.error("Expected both 'access_key' and 'secret_key' fields in vault secret",
                 extra={DataSetID: datasetID, ForUser: True})
    raise ValueError("Vault credentials are missing")

def s3filesystem_from_config(s3_config, datasetID):
    endpoint = s3_config.get('endpoint_url')
    region = s3_config.get('region')

    credentials = s3_config.get('credentials', {})
    access_key = credentials.get('accessKey')
    secret_key = credentials.get('secretKey')

    secret_provider = credentials.get('secretProvider')

    if 'vault_credentials' in s3_config:
        logger.trace("reading s3 configuration from vault",
                     extra={DataSetID: datasetID})
        access_key, secret_key = get_s3_credentials_from_vault(
                s3_config.get('vault_credentials'), datasetID)
    elif secret_provider:
        logger.trace("reading s3 configuration from secret provider",
                     extra={DataSetID: datasetID})
        r = requests.get(secret_provider)
        r.raise_for_status()
        response = r.json()
        endpoint = response.get('endpoint_url') or endpoint
        region = response.get('region') or region
        access_key = response.get('access_key') or access_key
        secret_key = response.get('secret_key') or secret_key

    scheme, endpoint_override = _split_endpoint(endpoint)
    anonymous = not access_key

    return S3FileSystem(
        region=region,
        endpoint_override=endpoint_override,
        scheme=scheme,
        access_key=access_key,
        secret_key=secret_key,
        anonymous=anonymous
    )


def _split_endpoint(endpoint):
    if endpoint:
        parsed_endpoint = urlparse(endpoint)
        return parsed_endpoint.scheme, parsed_endpoint.netloc
    return None, None
