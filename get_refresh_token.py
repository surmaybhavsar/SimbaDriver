# ==================================================================================================
# get_refresh_token.py
#
# Simba Technologies Inc.
# Copyright (C) 2023 Simba Technologies Incorporated
#
# Generate Google OAuth 2.0 refresh token for use in a connection string. This script is used to
# generate a refresh token for use with the BigQuery ODBC driver. Provides a command line interface
# for changing the fields used for the exchange.
#
# Example usage:
#   - Print usage:
#     - <python3_exec> get_refresh_token.py --help
#   - Get a token with default client id/secret
#     - <python3_exec> get_refresh_token.py
#   - Get a token for a specific id/secret:
#     - <python3_exec> get_refresh_token.py --client_id=<client_id> --client_secret=<client_secret>
#   - Get a token with Google Drive scope for default id/secret:
#     - <python3_exec> get_refresh_token.py --use_gdrive_scope=True
#   - Get a token with custom scope for a default id/secret:
#     - <python3_exec> get_refresh_token.py --scope=<custom_scope_1> --scope=<custom_scope_2>
#
# ==================================================================================================

import sys
if sys.version_info[0] < 3:
    raise Exception("Must execute this script with Python 3.")

import argparse
import base64
import hashlib
import http.client
import json
import os
import re
import socket
import webbrowser

INVALID_SIGN_IN_RESPONSE = \
    "HTTP/1.1 400 Bad Request\r\n" \
    "Content-Length: 95\r\n" \
    "Connection: close\r\n" \
    "Content-Type: text/html; charset=utf-8\r\n\r\n" \
    "<!DOCTYPE html>" \
    "<html><body>The request could not be understood by the server!</p></body></html>"
"""str: The static sign-in response for a failed sign-in operation."""

VALID_SIGN_IN_RESPONSE =\
    "HTTP/1.1 303 See Other\nLocation: https://cloud.google.com/bigquery/docs/reference/odbc-jdbc-drivers\n\n"
"""str: The redirect HTTP command to the Google's download page for the BigQuery ODBC/JDBC drivers."""


args_parser = argparse.ArgumentParser(
    description='Gets a refresh token for use with the BigQuery ODBC driver by exchanging authorization credentials.'
                ' This script requires a sign-in through a browser.'
)
args_parser.add_argument(
    '--client_id',
    help='Optional. The application client ID. If this is not provided, the Google Client Tools credentials will be'
         ' used by default.',
    required=False,
    default='977385342095.apps.googleusercontent.com')
args_parser.add_argument(
    '--client_secret',
    required=False,
    help='Optional. The application client secret. If this is not provided, the Google Client Tools credentials will be'
         ' used by default.',
    default='wbER7576mc_1YOII0dGk7jEE')
args_parser.add_argument(
    '--use_gdrive_scope',
    required=False,
    help='Optional. A flag indicating whether a sign-in operation should request access to Google Drive resources in'
         ' addition to the general Cloud Platform resources and APIs.',
    type=bool,
    default=False
)
args_parser.add_argument(
    '--scope',
    required=False,
    help='Optional. A scope to authenticate with. You can specify this field multiple times, and each scope will be'
         ' added to the final list of authentication scopes. If none is specified, then Cloud Platform scope will be'
         ' used.',
    action='append',
    dest='scopes'
)
args = args_parser.parse_args()

BIGQUERY_SCOPE = 'https://www.googleapis.com/auth/bigquery'
"""str: The scope for access to BigQuery services."""

DEFAULT_SCOPE = BIGQUERY_SCOPE
"""str: The default scope to use when generating an auth code if no scopes have been specified in the command line
arguments."""

GDRIVE_SCOPE = 'https://www.googleapis.com/auth/drive'
"""str: The scope required for access to Google Drive services."""

listen_port = 0
"""int: The port on which the auth code listener will listen."""


def read_auth_code_from_response(in_response: bytes, first: bytes, last: bytes) -> bytes:
    """
    Reads the given byte string between the given indexes and returns the resultant byte substring.
    Args:
        in_response: The byte string to read.
        first: The byte string index that begins the read sequence. Can be a multibyte substring.
        last: The byte string index that ends the read sequence. Can be a multibyte substring.

    Returns:
        The byte substring between the indexes, if found. An empty byte string otherwise.
    """
    try:
        start = in_response.index(first) + len(first)
        end = in_response.index(last, start)
        return in_response[start:end]
    except ValueError:
        return b''


def generate_code_challenge(code_verifier: str) -> str:
    """
    Generates a code challenge using the given code verifier, and returns the challenge.

    Returns:
        The code challenge.
    """
    code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8')
    return code_challenge.replace('=', '')


def generate_code_verifier() -> str:
    """
    Generates a code verifier and returns it.

    Returns:
        The code verifier.
    """
    code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8')
    return re.sub('[^a-zA-Z0-9]+', '', code_verifier)


class AuthCodeGetter:
    """
    Defines an abstraction of a class with the express purpose of getting an authentication code.
    """

    class AuthCodeUrl:
        """
        Convenience class for generating an auth code URL with all of its relevant components.
        """
        def __init__(self):
            self.__scheme = 'https://'
            self.__baseUrl = 'accounts.google.com'
            self.__serviceEndpoint = '/o/oauth2/auth'
            self.__clientId = ''
            self.__redirectUri = ''
            self.__useGDriveScope = False
            self.__scopes = set()
            self.__code_verifier = generate_code_verifier()
            self.__code_challenge = generate_code_challenge(self.__code_verifier)

        def get_redirect_uri(self) -> str:
            return self.__redirectUri

        def get_code_challenge(self) -> str:
            return self.__code_challenge

        def get_code_verifier(self) -> str:
            return self.__code_verifier

        def add_scope(self, in_scope: str) -> None:
            self.__scopes.add(in_scope)

        def set_scheme(self, in_scheme: str) -> None:
            self.__scheme = in_scheme

        def set_base_url(self, in_url: str) -> None:
            self.__baseUrl = in_url

        def set_endpoint(self, in_endpoint: str) -> None:
            self.__serviceEndpoint = in_endpoint

        def set_client_id(self, in_client_id: str) -> None:
            self.__clientId = in_client_id

        def set_redirect_uri(self, in_redirect_uri: str) -> None:
            self.__redirectUri = in_redirect_uri

        def set_scopes(self, in_scopes: list) -> None:
            self.__scopes = set(in_scopes)

        def set_use_gdrive_scope(self, in_use_gdrive_scope: bool) -> None:
            self.__useGDriveScope = in_use_gdrive_scope

        def get_complete_url(self) -> str:
            url = self.__scheme + self.__baseUrl + self.__serviceEndpoint + '?'
            url += 'response_type=code'
            url += '&client_id=' + self.__clientId
            url += '&redirect_uri=' + self.__redirectUri
            url += '&code_challenge_method=S256'
            url += '&code_challenge=' + self.__code_challenge
            if self.__useGDriveScope:
                self.add_scope(GDRIVE_SCOPE)
            if self.__scopes:
                url += '&scope=' + ' '.join(self.__scopes)  # Convert the scopes into a space-separated list of scopes.
            return url

    __authCode = ""  # The authentication code to return to the user.
    __url = AuthCodeUrl()

    def __init__(self) -> None:
        """
        Constructor.
        """
        super().__init__()

    def add_scope(self, in_scope: str) -> None:
        """
        Adds a scope to this auth code getter.
        Args:
            in_scope: The scope to add.
        """
        self.__url.add_scope(in_scope)

    def get_auth_code(self) -> str:
        """
        Get the auth code. This will execute a sign-in flow to retrieve the auth code.
        Returns:
            The authentication code.
        """
        try:
            self.sign_in()
        except socket.error as message:
            print('Error encountered on the socket: {' + message[0] + '} ' + message[1])
            sys.exit()

        return self.__authCode

    def get_redirect_uri(self) -> str:
        """
        Get the redirect URI for this auth code getter.
        Returns:
            The auth code getter.
        """
        return self.__url.get_redirect_uri()

    def set_base_url(self, base_url: str) -> None:
        """
        Sets the base URL to which the sign-in request is sent.
        Args:
            base_url: The base URL of the sign-in request.
        """
        self.__url.set_base_url(base_url)

    def set_client_id(self, client_id: str) -> None:
        """
        Set the client ID for the sign in request.
        Args:
            client_id: The application client ID.
        """
        self.__url.set_client_id(client_id)

    def set_scopes(self, in_scopes: list) -> None:
        """
        Sets the authentication scopes to be used with the auth request.
        Args:
            in_scopes: The list of auth scopes to add.
        """
        self.__url.set_scopes(in_scopes)

    def set_sign_in_endpoint(self, endpoint: str) -> None:
        """
        Sets the URL endpoint of the sign-in service for our sign-in request.
        Args:
            endpoint: The service endpoint of the sign-in request.
        """
        self.__url.set_endpoint(endpoint)

    def set_use_gdrive_scope(self, in_use_gdrive_scope: bool) -> None:
        """
        Sets the flag for adding Google Drive scope to the auth request.
        Args:
            in_use_gdrive_scope: Whether to enable Google Drive access in the authentication.
        """
        self.__url.set_use_gdrive_scope(in_use_gdrive_scope)

    def sign_in(self) -> None:
        """
        Performs a sign-in operation and assigns the auth code to this getter.
        """

        # First set up a socket for listening on the localhost.
        host = "127.0.0.1"

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((host, 0))

        sock_address = sock.getsockname()
        global listen_port  # Allow modification of port
        listen_port = sock_address[1]
        listen_sock_scheme = 'http://'

        # Modify the global redirect URI for use in the get_refresh_token_from_auth_code
        redirect_uri = listen_sock_scheme + sock_address[0] + ':' + str(sock_address[1])
        self.__url.set_redirect_uri(redirect_uri)

        complete_url = self.__url.get_complete_url()
        print("Sign in on your web browser. The following page has been opened: " + complete_url)

        try:
            if not webbrowser.open(self.__url.get_complete_url()):
                print(
                    "This script requires a local web browser to facilitate the sign-in process. Install a web browser"
                    " and re-run the script, or re-run this script on a system with a web browser installed.")
        except webbrowser.Error:
            print("This script requires a local web browser to facilitate the sign-in process. Install a web browser"
                  " and re-run the script, or re-run this script on a system with a web browser installed.")

        sock.listen(9)

        conn, address = sock.accept()
        data = conn.recv(4000)
        if not data:
            # If we fail to get data, however, fallback to the OOB flow.
            conn.send(INVALID_SIGN_IN_RESPONSE.encode('utf-8'))
            print(
                "This script requires a local web browser to facilitate the sign-in process. Install a web browser"
                " and re-run the script, or re-run this script on a system with a web browser installed.")

        # Send the static "this worked" sign-in page.
        conn.send(VALID_SIGN_IN_RESPONSE.encode('utf-8'))

        self.__authCode = read_auth_code_from_response(data, b'code=', b'&').decode('utf-8')

        print("Received auth code: " + self.__authCode)

    def get_code_verifier(self) -> str:
        return self.__url.get_code_verifier()


def get_refresh_token_from_auth_code(
        in_client_id: str,
        in_client_secret: str,
        in_auth_code: str,
        in_redirect_uri: str,
        in_code_verifier: str) -> str:
    """
    Exchanges the given authentication code for the refresh token.
    Args:
        in_client_id: The application client ID.
        in_client_secret: The application client secret.
        in_auth_code: The auth code to exchange.
        in_redirect_uri: The full redirect URI from which the auth code was obtained.
        in_code_verifier: The code verifier which is used to verify the code challenge.
    Returns:
        The generated refresh token.
    """
    request_headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    request_params = 'code=' + in_auth_code + '&'
    request_params += 'client_id=' + in_client_id + '&'
    request_params += 'client_secret=' + in_client_secret + '&'
    request_params += 'redirect_uri=' + in_redirect_uri + '&'
    request_params += 'code_verifier=' + in_code_verifier + '&'
    request_params += 'grant_type=authorization_code'

    https_conn = http.client.HTTPSConnection("oauth2.googleapis.com")
    https_conn.request("POST", "/token", request_params, request_headers)
    response_data = https_conn.getresponse().read()

    json_str = response_data.decode('utf-8')
    parsed_fields = json.loads(json_str)
    if 'refresh_token' not in parsed_fields:
        print("No refresh token in the response.")
        print(json_str)
        sys.exit()

    return parsed_fields['refresh_token']


if __name__ == '__main__':
    auth_code_listener = AuthCodeGetter()
    auth_code_listener.set_client_id(args.client_id)
    use_gdrive_scope = str(args.use_gdrive_scope).casefold()
    auth_code_listener.set_use_gdrive_scope((use_gdrive_scope == "true") or (use_gdrive_scope == "1"))

    if not args.scopes:
        auth_code_listener.add_scope(DEFAULT_SCOPE)
    else:
        auth_code_listener.set_scopes(args.scopes)

    print("Refresh token obtained: " +
          get_refresh_token_from_auth_code(
              args.client_id,
              args.client_secret,
              auth_code_listener.get_auth_code(),
              auth_code_listener.get_redirect_uri(),
              auth_code_listener.get_code_verifier()))
