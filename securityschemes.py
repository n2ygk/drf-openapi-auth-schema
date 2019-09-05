from django.conf import settings
from rest_framework.authentication import BasicAuthentication, SessionAuthentication
from rest_framework.permissions import AND, NOT, OR

from rest_framework_json_api.optional import (
    Condition,
    OAuth2Authentication,
    TokenMatchesOASRequirements
)


def _get_security(self, path, method):
    # TODO: flesh this out and move to DRF openapi.
    content = []
    for auth_class in self.view.authentication_classes:
        if issubclass(auth_class, BasicAuthentication):
            content.append({'basicAuth': []})
            if 'securitySchemes' not in self.openapi_schema['components']:
                self.openapi_schema['components']['securitySchemes'] = {}
            self.openapi_schema['components']['securitySchemes']['basicAuth'] = {
                'type': 'http',
                'scheme': 'basic',
                'description': 'Basic Authentication'
            }
            continue
        if issubclass(auth_class, SessionAuthentication):
            content.append({'cookieAuth': []})
            if 'securitySchemes' not in self.openapi_schema['components']:
                self.openapi_schema['components']['securitySchemes'] = {}
            self.openapi_schema['components']['securitySchemes']['cookieAuth'] = {
                'type': 'apiKey',
                'in': 'cookie',
                'name': 'JSESSIONID',
                'description': 'Session authentication'
            }
            continue
        if OAuth2Authentication and issubclass(auth_class, OAuth2Authentication):
            content += self._get_oauth_security(path, method)
            continue
    return content


def _get_oauth_security(self, path, method):
    """
    Creates `#components/securitySchemes/oauth` and returns `.../security/oauth`
    when using Django OAuth Toolkit.
    """
    # openIdConnect type not currently supported by Swagger-UI
    # 'openIdConnectUrl': settings.OAUTH2_SERVER + '/.well-known/openid-configuration'
    if not hasattr(settings, 'OAUTH2_CONFIG'):
        return []
    if 'securitySchemes' not in self.openapi_schema['components']:
        self.openapi_schema['components']['securitySchemes'] = {}
    self.openapi_schema['components']['securitySchemes']['oauth'] = {
        'type': 'oauth2',
        'description': 'oauth2.0 service',
    }
    flows = {}
    if 'authorization_code' in settings.OAUTH2_CONFIG['grant_types_supported']:
        flows['authorizationCode'] = {
            'authorizationUrl': settings.OAUTH2_CONFIG['authorization_endpoint'],
            'tokenUrl': settings.OAUTH2_CONFIG['token_endpoint'],
            'refreshUrl': settings.OAUTH2_CONFIG['token_endpoint'],
            'scopes': {s: s for s in settings.OAUTH2_CONFIG['scopes_supported']}
        }
    if 'implicit' in settings.OAUTH2_CONFIG['grant_types_supported']:
        flows['implicit'] = {
            'authorizationUrl': settings.OAUTH2_CONFIG['authorization_endpoint'],
            'scopes': {s: s for s in settings.OAUTH2_CONFIG['scopes_supported']}
        }
    if 'client_credentials' in settings.OAUTH2_CONFIG['grant_types_supported']:
        flows['clientCredentials'] = {
            'tokenUrl': settings.OAUTH2_CONFIG['token_endpoint'],
            'refreshUrl': settings.OAUTH2_CONFIG['token_endpoint'],
            'scopes': {s: s for s in settings.OAUTH2_CONFIG['scopes_supported']}
        }
    if 'password' in settings.OAUTH2_CONFIG['grant_types_supported']:
        flows['password'] = {
            'tokenUrl': settings.OAUTH2_CONFIG['token_endpoint'],
            'refreshUrl': settings.OAUTH2_CONFIG['token_endpoint'],
            'scopes': {s: s for s in settings.OAUTH2_CONFIG['scopes_supported']}
        }
    self.openapi_schema['components']['securitySchemes']['oauth']['flows'] = flows
    # TODO: add JWT and SAML2 bearer
    content = []
    # permission_classes can be a direct list of classes, or instances of Operands, etc.
    for perm in self.view.permission_classes:
        if (
                isinstance(perm(), TokenMatchesOASRequirements) or
                self._drf_conditional_contains(perm(), TokenMatchesOASRequirements) or
                self._rest_cond_contains(perm(), TokenMatchesOASRequirements)
        ):
            alt_scopes = self.view.required_alternate_scopes
            if method not in alt_scopes:
                continue
            for scopes in alt_scopes[method]:
                content.append({'oauth': scopes})
    return content


def _drf_conditional_contains(self, perm_inst, the_class):
    """
    Recursively check if DRF conditional operands were specified.
    If there's any reference to `the_class` then return True.
    Don't care what the boolean logic is, just if there's an instance of the_class.
    """
    binary = (AND, OR)
    unary = (NOT,)
    ops = binary + unary

    if not isinstance(perm_inst, ops):
        return False

    if isinstance(perm_inst, binary):
        if isinstance(perm_inst.op1, the_class):
            return True
        if isinstance(perm_inst.op2, the_class):
            return True
        if isinstance(perm_inst.op1, ops):
            if self._drf_conditional_contains(perm_inst.op1, the_class):
                return True
        if isinstance(perm_inst.op2, ops):
            if self._drf_conditional_contains(perm_inst.op2, the_class):
                return True
    elif isinstance(perm_inst, unary):
        if isinstance(perm_inst.op1, the_class):
            return True
        if isinstance(perm_inst.op1, ops):
            if self._drf_conditional_contains(perm_inst.op1, the_class):
                return True
    return False


def _rest_cond_contains(self, perm_inst, the_class):
    """
    Recursively check if rest_condition conditional operands were specified.
    If there's any reference to `the_class` then return True.
    Don't care what the boolean logic is, just if there's an instance of the_class.
    """
    if Condition is None or not isinstance(perm_inst, Condition):
        return False

    for cond in perm_inst.perms_or_conds:
        if isinstance(cond(), the_class):
            return True
        if isinstance(cond(), Condition):
            if self._rest_cond_contains(cond, the_class):
                return True
    return False
