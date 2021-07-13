class WsSdkError(Exception):
    """Parent Exception Class"""


class MissingTokenError(WsSdkError):
    """Raised when token is missing"""
    def __init__(self, token, token_type):
        self.message = f"Token {token} does not exist in this {token_type}"
        super().__init__(self.message)


class TokenTypeError(WsSdkError):
    def __init__(self, token):
        self.message = f"Unable to discover Token Type of token {token}"
        super().__init__(self.message)


class WsServerError(Exception):
    """Parent Exception Class for WS Application errors"""


class WsServerInactiveOrg(WsServerError):
    def __init__(self, token):
        self.message = f"Organization {token} is inactive"
        super().__init__(self.message)


class WsServerGenericError(WsServerError):
    def __init__(self, token, error):
        self.message = f"Generic error on token: {token}. Error: {error}"
        super().__init__(self.message)
