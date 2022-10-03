import base64

from AuthRealm import BaseAuthRealm, _StorageMixIn

from dpa.lib.makeProperty import makeProperty


atUNDEFINED = 0
atORIGIN = 1
atPROXY = 2


class BaseHTTPAuthRealm(BaseAuthRealm):

  authType = atUNDEFINED

  @makeProperty()
  def authorizer():
    def prepare(self, value):
      from HTTPAuthorizer import BaseHTTPAuthorizer
      if value is None or isinstance(value, BaseHTTPAuthorizer):
        return value
      else:
        raise TypeError, "'authorizer' must be BaseHTTPAuthorizer instance or None"
 

class BaseHTTPBasicAuthRealm(BaseHTTPAuthRealm):

  authType = atORIGIN
  authorizationHeader = 'Authorization'
  authenticateHeader = 'WWW-Authenticate'
  authFailCode = 401


  def extractUserAndCredentials(self, data):
    req, resp = data
    user, password = None, None
    cr = req.headers[self.authorizationHeader]
    if cr is None:
      user = '' # no attempt to authenticate
    else:
      cr = cr.strip()
      pos = cr.find(' ')
      if pos != -1 and cr[:pos].lower() == 'basic':
        cr = base64.decodestring(cr[pos+1:].strip())
        pos = cr.find(':')
        if pos == -1:
          user = cr
          password = ''
        else:
          user = cr[:pos]
          password = cr[pos+1:]
    return user, password

  def authenticate(self, data):
    req, resp = data
    user = super(BaseHTTPBasicAuthRealm, self).authenticate(data)
    if not user:
      resp.headers[self.authenticateHeader] = 'Basic realm="%s"' % self.realm
      resp.code = self.authFailCode
      user = None
    return user


class BaseHTTPProxyBasicAuthRealm(BaseHTTPBasicAuthRealm):

  authType = atPROXY
  authorizationHeader = 'Proxy-Authorization'
  authenticateHeader = 'Proxy-Authenticate'
  authFailCode = 407


class HTTPBasicAuthRealm(_StorageMixIn, BaseHTTPBasicAuthRealm): pass
class HTTPProxyBasicAuthRealm(_StorageMixIn, BaseHTTPProxyBasicAuthRealm): pass
