class WsSdkError(Exception):
    """Parent Exception Class"""


class MissingTokenError(WsSdkError):
    """Raised when token is missing"""
    def __init__(self, token):
        self.message = f"Token {token} does not exist"
        super().__init__(self.message)


class TokenTypeError(WsSdkError):
    def __init__(self, token):
        self.message = "Unable to discover Token Type"
        super().__init__(self.message)
