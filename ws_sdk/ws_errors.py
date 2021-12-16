class WsSdkError(Exception):
    """Parent Exception Class"""


class WsSdkTokenError(WsSdkError):
    def __init__(self, token):
        self.message = f"Invalid token: '{token}'"
        super().__init__(self.message)


# Server
class WsSdkServerError(WsSdkError):
    """Parent Exception Class for WS Application errors"""


class WsSdkServerMissingTokenError(WsSdkServerError):
    """Raised when token is missing"""
    def __init__(self, token, token_type):
        self.message = f"Token {token} does not exist in this {token_type}"
        super().__init__(self.message)


class WsSdkServerTokenTypeError(WsSdkServerError):
    def __init__(self, token):
        self.message = f"Unable to discover Token Type of token {token}"
        super().__init__(self.message)


class WsSdkServerMissingGroupError(WsSdkServerError):
    def __init__(self, name):
        self.message = f"Group {name} does not exist"
        super().__init__(self.message)


class WsSdkServerInactiveOrg(WsSdkServerError):
    def __init__(self, token):
        self.message = f"Organization {token} is inactive"
        super().__init__(self.message)


class WsSdkServerGenericError(WsSdkServerError):
    def __init__(self, token, error):
        self.message = f"Generic error on token: {token}. Error: {error}"
        super().__init__(self.message)


class WsSdkServerInsufficientPermissions(WsSdkServerError):
    def __init__(self, token):
        self.message = f"User token: {token} has insufficient permissions"
        super().__init__(self.message)


# Client
class WsSdkClientError(WsSdkError):
    """Parent Exception Class for WS Client errors"""


class WsSdkClientGenericError(WsSdkClientError):
    def __init__(self, error_t: tuple):
        self.message = f"Generic error running Unified Agent: {error_t[1]}. Return Code: {error_t[0]}"
        super().__init__(self.message)


class WsSdkClientPolicyViolation(WsSdkClientError):
    def __init__(self, error_t: tuple):
        self.message = f"Policy Violation discovered when running Unified Agent: {error_t[1]}. Return Code: {error_t[0]}"
        super().__init__(self.message)
