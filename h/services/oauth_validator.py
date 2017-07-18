# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import datetime

from oauthlib.oauth2 import InvalidClientIdError, RequestValidator
from sqlalchemy.exc import StatementError

from h import models
from h.util.db import lru_cache_in_transaction

AUTHZ_CODE_TTL = datetime.timedelta(minutes=10)
DEFAULT_SCOPES = ['annotation:read', 'annotation:write']


class OAuthValidatorService(RequestValidator):
    """
    Validates OAuth requests

    This implements the ``oauthlib.oauth2.RequestValidator`` interface.
    """

    def __init__(self, session):
        self.session = session

        self._cached_find_client = lru_cache_in_transaction(self.session)(self._find_client)

    def client_authentication_required(self, request, *args, **kwargs):
        """
        Client authentication is generally not required.

        This is mostly due to the nature of our clients running in a Browser JavaScript environment
        where we can't safely store the `client_secret`.
        """

        client = self.find_client(request.client_id)
        print('client', client)
        if client is None:
            # `authenticate_client_id` will not authenticate a missing client.
            return False

        print('client.secret', client.secret)
        return (client.secret is not None)

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        """Authenticates a client_id, returns True if the client_id exists."""

    def find_client(self, id_):
        return self._cached_find_client(id_)

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        """Returns the ``redirect_uri`` stored on the client with the given id."""

        client = self.find_client(client_id)
        if client is not None:
            return client.redirect_uri

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        """Return the default scopes for the provided client."""
        return DEFAULT_SCOPES

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        client = self.find_client(client_id)
        if client is None:
            raise InvalidClientIdError()

        codestr = code.get('code')
        expires = utcnow() + AUTHZ_CODE_TTL
        authzcode = models.AuthzCode(user=request.user,
                                     authclient=client,
                                     expires=expires,
                                     code=codestr)
        self.session.add(authzcode)
        return authzcode

    def validate_client_id(self, client_id, request, *args, **kwargs):
        """Checks if the provided client_id belongs to a valid AuthClient."""

        client = self.find_client(client_id)
        return (client is not None)

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        """Validate that the provided ``redirect_uri`` matches the one stored on the client."""

        client = self.find_client(client_id)
        if client is not None:
            return (client.redirect_uri == redirect_uri)
        return False

    def validate_response_type(self, client_id, response_type, request, *args, **kwargs):
        """Validate that the provided ``response_type`` matches the one stored on the client."""

        client = self.find_client(client_id)
        if client is not None:
            return (client.response_type.value == response_type)
        return False

    def validate_scopes(self, client_id, scopes, request, *args, **kwargs):
        """Validate that the provided `scope(s)` matches the ones stored on the client."""

        # We only allow the (dummy) default scopes for now.
        default_scopes = self.get_default_scopes(client_id, request, *args, **kwargs)
        return (scopes == default_scopes)

    def _find_client(self, id_):
        if id_ is None:
            return None

        try:
            return self.session.query(models.AuthClient).get(id_)
        except StatementError:
            return None


def oauth_validator_service_factory(context, request):
    """Return a OAuthValidator instance for the passed context and request."""
    return OAuthValidatorService(request.db)


def utcnow():
    return datetime.datetime.utcnow()
