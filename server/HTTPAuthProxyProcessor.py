from cgi import parse_qsl
from urllib import urlencode
from threading import local

from dpa.client.AuthManager import BaseAuthManager

from AuthInfo import getAuthInfo
from HTTPProxyProcessor import HTTPProxyProcessor

class _Credentials(local):

  user = None
  role = None
  password = None

  def  __setattr__(self, name, value):
    if name in ('user', 'role', 'password'):
      super(_Credentials, self).__setattr__(name, value)
    else:
      raise AttributeError, "can't set attribute"


_credentials = None


class _ProxyAuthManager(BaseAuthManager):

  def _makeCacheKey(self, host, port, realm):
    ai = getAuthInfo()
    return (host, port, realm, ai.user, ai.role)

  def requestLoginAndPassword(self, host, port, realm):
    global _credentials
    return (_credentials.user, _credentials.password)


class BaseHTTPAuthProxyProcessor(HTTPProxyProcessor):

  def preProcess(self, request, response):
    super(BaseHTTPAuthProxyProcessor, self).preProcess(request, response)
    user, role, password = self.getOriginalCredentials(request)
    global _credentials
    _credentials = _Credentials()
    _credentials.user = user
    _credentials.role = role
    _credentials.password = password
    del request.headers['Authorization']
    self.changeAuthorityInfo(request)

  def postProcess(self, request, response):
    super(BaseHTTPAuthProxyProcessor, self).postProcess(request, response)
    global _credentials
    _credentials = None

  def changeAuthorityInfo(self, request):
    raise NotImplementedError, "'changeAuthorityInfo' method not implemented"

  def getOriginalCredentials(self, request):
    raise NotImplementedError, "'getOriginalCredentials' method not implemented"


class BaseHTTPQueryAuthProxyProcessor(BaseHTTPAuthProxyProcessor):

  def __init__(self, connectionPool=None, fieldName='role'):
    super(BaseHTTPQueryAuthProxyProcessor, self).__init__(connectionPool)
    if not isinstance(fieldName, str) or not fieldName:
      raise ValueError, "'fieldName' must be not empty string"
    self.fieldName = fieldName.lower() # ignore case
    self.connectionPool.authManager = _ProxyAuthManager()

  def changeAuthorityInfo(self, request):
    if request.query:
      try:
        qDict = {}
        for key, value in parse_qsl(request.query):
          qDict[key] = value
          if key.lower() != self.fieldName:
            qDict[key] = value
        global _credentials
        qDict[self.fieldName] = _credentials.role
        request.query = urlencode(qDict)
      except:
        pass


class BaseHTTPHeaderAuthProxyProcessor(BaseHTTPAuthProxyProcessor):

  def __init__(self, connectionPool=None, headerName='role'):
    super(BaseHTTPHeaderAuthProxyProcessor, self).__init__(connectionPool)
    if not isinstance(headerName, str) or not headerName:
      raise ValueError, "'headerName' must be not empty string"
    self.headerName = headerName.lower() # ignore case
    self.connectionPool.authManager = _ProxyAuthManager()

  def changeAuthorityInfo(self, request):
    del request.headers[self.headerName]
    global _credentials
    request.headers[self.headerName] = _credentials.role
