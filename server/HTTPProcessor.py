from dpa.lib.IOBuffer import IOBuffer
from dpa.lib.makeProperty import makeProperty

from AuthInfo import getAuthInfo
from AuthRealm import AuthRealmOperationalError
from Authorizer import AuthorizerOperationalError

atUNDEFINED = 0
atORIGIN = 1
atPROXY = 2


class _FinishProcess(Exception): pass


# Use this exception if you want to generate 503 (service unavailable) error
class ServiceUnavailableError(Exception):
  pass


class BaseHTTPProcessor(object):

  authType = atUNDEFINED

  def __init__(self):
    self.authRealm = None

  @makeProperty()
  def authRealm():
    def prepare(self, value):
      from HTTPAuthRealm import BaseHTTPAuthRealm
      if value is not None:
        if not isinstance(value, BaseHTTPAuthRealm):
          raise TypeError, "'authRealm' must be BaseHTTPAuthRealm instance"
        elif self.authType != value.authType:
          raise TypeError,  "Bad 'authType' for this realm"
      return value

  def verifyRequest(self, request, response):
    try:
      self.verifyAuthentity(request, response)
      self.verifyAuthority(request, response)
      self.verifyCommand(request, response)
      self.verifyHeaders(request, response)
      self.sendContinueIfNeed(request, response)
    except _FinishProcess:
      pass

  def verifyAuthentity(self, request, response):
    if self.authRealm:
      try:
        user = self.authRealm.authenticate((request, response))
      except AuthRealmOperationalError, oe:
        raise ServiceUnavailableError, str(oe)
      if user:
        getAuthInfo().user = user
      else:
        self.sendError(response, response.code)

  def verifyAuthority(self, request, response):
    if self.authRealm and self.authRealm.authorizer:
      ai = getAuthInfo()
      try:
        role = self.authRealm.authorizer.authorize(self.authRealm.realm, ai.user, (request, response))
      except AuthorizerOperationalError, oe:
        raise ServiceUnavailableError, str(oe)
      if role:
        ai.role = role
      else:
        self.sendError(response, 403)

  def verifyCommand(self, request, response):
    pass

  def verifyHeaders(self, request, response):
    pass

  def sendContinueIfNeed(self, request, response):
    if request.expectContinue and self.wantReadBody(request):
      self.sendError(response, 100, "Continue")

  def wantReadBody(self, request):
    # Can be redefined in childrens
    # Can analize request.command and request.headers
    return True

  def preProcess(self, request, response):
    pass

  def processRequest(self, request, response):
    raise NotImplementedError, "'processRequest' method not implemented"

  def postProcess(self, request, response):
    if response.stream is not None:
      response.stream.close()

  def sendError(self, response, code, message=None):
    response.code = code
    if message:
      response.message = message
    response.error = True
    self.finishProcess()

  def finishProcess(self):
    raise _FinishProcess

class HTTPProcessor(BaseHTTPProcessor):

  authType = atORIGIN

  def processRequest(self, request, response):
    method = getattr(self, 'do_%s' % request.command)
    try:
      method(request, response)
    except _FinishProcess:
      pass

  def verifyCommand(self, request, response):
    if not hasattr(self, 'do_%s' % request.command):
      self.sendError(response, 501, "Unsupported method '%s'" % request.command)

  def do_OPTIONS(self, request, response):
    methods = []
    for attr in dir(self):
      if attr.startswith('do_') and callable(getattr(self, attr)):
        methods.append(attr[3:])
    response.headers["Allow"] = ",".join(methods)
    response.headers["Content-Length"] = "0"
    response.headers["Content-Type"] = "text/html"
    response.stream = IOBuffer()
