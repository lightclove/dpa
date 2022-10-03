import cgi

from Authorizer import BaseAuthorizer, _StorageMixIn


class BaseHTTPAuthorizer(BaseAuthorizer): pass


class BaseHTTPHeaderAuthorizer(BaseHTTPAuthorizer):

  def __init__(self, headerName='role'):
    if not isinstance(headerName, str) or not headerName:
      raise ValueError, "'headerName' must be not empty string"
    self.headerName = headerName.lower() # ignore case

  def extractRole(self, data):
    # will return None if not found
    req, resp = data
    return req.headers[self.headerName]


class BaseHTTPQueryAuthorizer(BaseHTTPAuthorizer):

  def __init__(self, fieldName='role'):
    if not isinstance(fieldName, str) or not fieldName:
      raise ValueError, "'fieldName' must be not empty string"
    self.fieldName = fieldName.lower() # ignore case

  def extractRole(self, data):
    res = None # return None if not found
    req, resp = data
    if req.query:
      for key, value in cgi.parse_qsl(req.query):
        if key.lower() == self.fieldName:
          res = value
          break
    return res


class HTTPHeaderAuthorizer(_StorageMixIn, BaseHTTPHeaderAuthorizer):

  def __init__(self, roleStorage, headerName='role'):
    _StorageMixIn.__init__(self, roleStorage)
    BaseHTTPHeaderAuthorizer.__init__(self, headerName)


class HTTPQueryAuthorizer(_StorageMixIn, BaseHTTPQueryAuthorizer):

  def __init__(self, roleStorage, fieldName='role'):
    _StorageMixIn.__init__(self, roleStorage)
    BaseHTTPQueryAuthorizer.__init__(self, fieldName)
