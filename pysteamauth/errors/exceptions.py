from pysteamauth.errors import STEAM_ERROR_CODES


_CUSTOM_ERROR_EXCEPTIONS = {}


class SteamError(Exception):

    def __init__(self, error_code: int):
        self.error_code = error_code

    def __str__(self) -> str:
        if self.error_code in _CUSTOM_ERROR_EXCEPTIONS:
            error = _CUSTOM_ERROR_EXCEPTIONS[self.error_code]
        else:
            error = STEAM_ERROR_CODES.get(self.error_code, self.error_code)
        return str({
            'error': error,
            'code': self.error_code,
        })


class UnknownSteamError(SteamError):
    ...


def custom_error_exception(errors):
    global _CUSTOM_ERROR_EXCEPTIONS
    if isinstance(errors, tuple):
        custom_errors = errors
    elif isinstance(errors, dict):
        custom_errors = errors.items()
    else:
        raise TypeError(f'The error argument should be dict or tuple')

    for _error, _exception in custom_errors:
        if not isinstance(_error, int):
            raise TypeError('Error should be an integer')
        if not issubclass(_exception, SteamError):
            raise TypeError('Exception should be inherited from SteamError')
        if _error not in STEAM_ERROR_CODES:
            raise TypeError(f'Unknown error code {_error}')
        _CUSTOM_ERROR_EXCEPTIONS[_error] = _exception
