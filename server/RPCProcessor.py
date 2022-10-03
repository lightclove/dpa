import traceback

from dpa.lib.makeProperty import makeProperty
from dpa.lib import log
from dpa.lib.SharedLock import SharedLock


import PermissionChecker
from AuthInfo import getAuthInfo
from Service import BaseService


class RPCProcessorError(Exception): pass

class MethodNotSupported(RPCProcessorError): pass

class PermissionDenied(RPCProcessorError): pass

class PermissionCheckerOperationalError(RPCProcessorError): pass

esSERVER = 0
esAPPLICATION = 1

class BaseRPCProcessor(object):

  def __init__(self):
    super(BaseRPCProcessor, self).__init__()
    self._serviceAPIs = {}
    self._lock = SharedLock()
    self.permissionChecker = None
    self.callLoggerName = 'rpcCalls'
    self.errorLoggerName = 'unhandledExceptions'

  @makeProperty(PermissionChecker.BasePermissionChecker, None)
  def permissionChecker():
    pass

  @makeProperty(str)
  def callLoggerName():
    pass

  @makeProperty(str)
  def errorLoggerName():
    pass

  def addServiceAPI(self, service, nameOfAPI, prefix=None):
    if not isinstance(prefix, str) and prefix is not None:
      raise TypeError, "'prefix' must be string or None"
    if not isinstance(service, BaseService):
      raise TypeError, "'service' must be instance of 'BaseService' class"
    if not prefix:
      prefix = ''
    if prefix != '':
      for item in prefix.split('.'):
        if not item or not item.isalnum():
          raise ValueError,  "Incorect 'prefix' value"
    if self._serviceAPIs.has_key(prefix):
      raise ValueError, "service with prefix '%s' already registered" % prefix
    methods = service.getAPI(nameOfAPI)
    if methods is None:
      raise ValueError,  "API '%s' not declared by service" % nameOfAPI
    self._lock.acquireWrite()
    self._serviceAPIs[prefix] = methods
    self._lock.release()

  def deleteServiceAPI(self, prefix):
    self._lock.acquireWrite()
    try:
      del self._serviceAPIs[prefix]
    except:
      pass
    self._lock.release()

  def getServiceAPI(self, prefix):
    self._lock.acquireRead()
    try:
      s = self._serviceAPIs[prefix]
    except:
      s = None
    self._lock.release()
    return s

  def enumerateServiceAPIs(self):
    self._lock.acquireRead()
    s = self._serviceAPIs.keys()
    self._lock.release()
    return s

  def findMethod(self, methodName):
    pos = methodName.rfind('.')
    if pos == -1:
      prefix = ''
      method = methodName
    else:
      prefix = methodName[:pos]
      method = methodName[pos+1:]
    methods = self.getServiceAPI(prefix)
    if not methods:
      raise MethodNotSupported, 'Method "%s" is not supported' % methodName
    try:
      return methods[method]
    except KeyError:
      raise MethodNotSupported, 'Method "%s" is not supported' % methodName

  def logInternalError(self):
    exc = '\n  '.join(traceback.format_exc().split('\n'))
    log.error(self.errorLoggerName, "Unhandled exception:\n  %s\n", exc)

  def logCall(self, request, methodName, errMsg=None):
    ai = getAuthInfo()
    u = ai.user or '-'
    r = ai.role or '-'
    m = methodName or '-'
    if errMsg:
      prty = log.LOG_ERR
      msg = errMsg
    else:
      prty = log.LOG_INFO
      msg = 'OK'
    log.log(self.callLoggerName, prty, '%s %s %s %s %s', request.clientHost, u, r, m, msg)

  def checkPermissions(self, methodName):
    if self.permissionChecker:
      try:
        permission = getattr(getAuthInfo(), self.permissionChecker.authInfoField)
        if not self.permissionChecker.checkPermissions(methodName, permission):
          raise PermissionDenied, "No permissions to execute '%s'" % methodName
      except PermissionChecker.PermissionCheckerOperationalError, oe:
        raise PermissionCheckerOperationalError, str(oe)

  def makeRPCCall(self, request, response):
    try:
      methodName, requestEncoding = None, None # don't want AttributeError
      methodName, params, requestEncoding = self.parseRequest(request)
      self.checkPermissions(methodName)
      method = self.findMethod(methodName)
    except Exception, e:
      result, errMsg = self.processError(e, esSERVER)
    else:
      try:
        result = method(*params)
        errMsg = None
      except Exception, e:
        result, errMsg = self.processError(e, esAPPLICATION)
    try:
      self.generateResponse(response, result, requestEncoding)
      self.logCall(request, methodName, errMsg)
    except Exception, e:  # process response generation errors
      result, errMsg = self.processError(e, esSERVER)
      self.generateResponse(response, result, requestEncoding) # must generate correct response
      self.logCall(request, methodName, errMsg)

  def parseRequest(self, request):
    # must return tuple: (method, params, requestEncoding)
    # method - string (with dots)
    raise NotImplementedError, "'parseRequest' method is not defined"

  def generateResponse(self, response, result, encoding=None):
    raise NotImplementedError, "'generateResponse' method is not defined"

  def processError(self, exception, errorSource):
    # must return tuple: (method, errorResult, logMessage)
    raise NotImplementedError, "'processError' method is not defined"
