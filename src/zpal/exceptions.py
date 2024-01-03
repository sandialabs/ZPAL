class ZpalException(Exception):
    '''
    Basic ZPAL Exception.
    '''

    pass


class AuthenticationError(ZpalException):
    '''
    Unable to authenticate to device.
    '''

    pass


class AuthorizationError(ZpalException):
    '''
    Unable to perform requested operation.
    '''

    pass

class JSONError(ZpalException):
    '''
    Encountered error processing JSON data.
    '''

    pass