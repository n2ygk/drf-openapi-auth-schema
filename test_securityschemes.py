import pytest
from django.test import RequestFactory, override_settings
from rest_condition import And, Not, Or
from rest_framework import VERSION as DRFVERSION
from rest_framework.authentication import BasicAuthentication, SessionAuthentication
from rest_framework.permissions import (
    AllowAny,
    DjangoModelPermissions,
    IsAdminUser,
    IsAuthenticated
)
from rest_framework.request import Request

from rest_framework_json_api.optional import OAuth2Authentication, TokenMatchesOASRequirements

from example import views

drf_version = tuple(int(x) for x in DRFVERSION.split('.'))

if drf_version >= (3, 10):
    from rest_framework_json_api.schemas.openapi import AutoSchema, SchemaGenerator


def create_request(path):
    factory = RequestFactory()
    request = Request(factory.get(path))
    return request


def create_view_with_kw(view_cls, method, request, initkwargs):
    generator = SchemaGenerator()
    view = generator.create_view(view_cls.as_view(initkwargs), method, request)
    return view


@pytest.mark.skipif(TokenMatchesOASRequirements is None, reason="requires oauth")
class OauthProtectedAuthorViewSet(views.AuthorViewSet):
    authentication_classes = (OAuth2Authentication, BasicAuthentication,
                              SessionAuthentication)
    permission_classes = (TokenMatchesOASRequirements, IsAuthenticated)
    required_alternate_scopes = {
        'GET': [['scope1', 'scope2'], ['scope3', 'scope4']],
    }


oauth2_server = 'oauth.example.com'
oauth2_config = {
    'authorization_endpoint': oauth2_server + '/authorize',
    'token_endpoint': oauth2_server + '/token',
    'scopes_supported': ['scope1', 'scope2', 'scope3', 'scope4'],
    'grant_types_supported': ['implicit', 'authorization_code', 'client_credentials',
                              'password'],
}


@pytest.mark.skipif(TokenMatchesOASRequirements is None, reason="requires oauth")
def test_schema_security_list():
    """
    Checks for security objects
    """

    path = '/authors/'
    method = 'GET'

    view = create_view_with_kw(
        OauthProtectedAuthorViewSet,
        method,
        create_request(path),
        {'get': 'list'}
    )
    inspector = AutoSchema()
    inspector.view = view

    with override_settings(OAUTH2_CONFIG=oauth2_config):
        operation = inspector.get_operation(path, method)

    assert 'security' in operation
    assert len(operation['security']) == 4
    assert operation['security'][0] == {'oauth': ['scope1', 'scope2']}
    assert operation['security'][1] == {'oauth': ['scope3', 'scope4']}
    assert operation['security'][2] == {'basicAuth': []}
    assert operation['security'][3] == {'cookieAuth': []}


@pytest.mark.skipif(TokenMatchesOASRequirements is None, reason="requires oauth")
def test_schema_security_drf_condition():
    """
    Checks for security objects with DRF bitwise conditional operators
    """
    class DRF_Cond_ViewSet(OauthProtectedAuthorViewSet):
        # this is a crazy example just to make sure all the recursive code is covered
        permission_classes = [
            (IsAuthenticated & DjangoModelPermissions) |
            ~(TokenMatchesOASRequirements & AllowAny),
            ~AllowAny | (IsAdminUser & IsAuthenticated),
            (TokenMatchesOASRequirements & AllowAny) |
            (IsAuthenticated & DjangoModelPermissions),
            ~TokenMatchesOASRequirements
        ]

    path = '/authors/'
    method = 'GET'

    view = create_view_with_kw(
        DRF_Cond_ViewSet,
        method,
        create_request(path),
        {'get': 'list'}
    )
    inspector = AutoSchema()
    inspector.view = view

    with override_settings(OAUTH2_CONFIG=oauth2_config):
        operation = inspector.get_operation(path, method)

    assert 'security' in operation
    assert {'oauth': ['scope1', 'scope2']} in operation['security']
    assert {'oauth': ['scope3', 'scope4']} in operation['security']
    assert {'basicAuth': []} in operation['security']
    assert {'cookieAuth': []} in operation['security']


@pytest.mark.skipif(TokenMatchesOASRequirements is None, reason="requires oauth")
def test_schema_security_rest_condition():
    """
    Checks for security objects with rest_condition operator methods
    """
    class Rest_Cond_ViewSet(OauthProtectedAuthorViewSet):
        permission_classes = [
            Or(
                And(IsAuthenticated, DjangoModelPermissions),
                And(Not(TokenMatchesOASRequirements), AllowAny)),
        ]

    path = '/authors/'
    method = 'GET'

    view = create_view_with_kw(
        Rest_Cond_ViewSet,
        method,
        create_request(path),
        {'get': 'list'}
    )
    inspector = AutoSchema()
    inspector.view = view

    with override_settings(OAUTH2_CONFIG=oauth2_config):
        operation = inspector.get_operation(path, method)

    assert 'security' in operation
    assert {'oauth': ['scope1', 'scope2']} in operation['security']
    assert {'oauth': ['scope3', 'scope4']} in operation['security']
    assert {'basicAuth': []} in operation['security']
    assert {'cookieAuth': []} in operation['security']
