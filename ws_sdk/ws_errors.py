class WsSdkError(Exception):
    """Parent Exception Class"""


class MissingTokenError(WsSdkError):
    """Raised when token is missing"""
    def __init__(self, token, token_type):
        self.message = f"Token {token} does not exist in this {token_type}"
        super().__init__(self.message)


class TokenTypeError(WsSdkError):
    def __init__(self, token):
        self.message = "Unable to discover Token Type"
        super().__init__(self.message)
