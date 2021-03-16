def is_token(token: str) -> bool:
    return True if len(token) == 64 and token.isalnum() else False
