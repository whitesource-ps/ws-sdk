class WsSdkError(Exception):
    """Parent Exception Class"""


# Server
class WsSdkServerError(WsSdkError):
    """Parent Exception Class for WS Application errors"""


class MissingTokenError(WsSdkServerError):
    """Raised when token is missing"""
    def __init__(self, token, token_type):
        self.message = f"Token {token} does not exist in this {token_type}"
        super().__init__(self.message)


class TokenTypeError(WsSdkServerError):
    def __init__(self, token):
        self.message = f"Unable to discover Token Type of token {token}"
        super().__init__(self.message)


class WsSdkServerInactiveOrg(WsSdkServerError):
    def __init__(self, token):
        self.message = f"Organization {token} is inactive"
        super().__init__(self.message)


class WsSdkServerGenericError(WsSdkServerError):
    def __init__(self, token, error):
        self.message = f"Generic error on token: {token}. Error: {error}"
        super().__init__(self.message)


# Client
class WsSdkClientError(WsSdkError):
    """Parent Exception Class for WS Client errors"""


class WsSdkClientGenericError(WsSdkClientError):
    def __init__(self, return_code, error):
        self.message = f"Generic error running Unified Agent: {error}. Return Code: {return_code}"
        super().__init__(self.message)


class WsSdkClientPolicyViolation(WsSdkClientError):
    def __init__(self, return_code, error):
        self.message = f"Policy Violation discovered when running Unified Agent: {error}. Return Code: {return_code}"
        super().__init__(self.message)
