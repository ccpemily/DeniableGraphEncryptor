from functools import wraps

__authenticated = False

def authenticate():
    __authenticated = True

def requires_auth(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if(__authenticated):
            return func(*args, **kwargs)
        else:
            return None
    return wrapper





