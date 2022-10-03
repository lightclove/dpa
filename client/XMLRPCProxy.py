import sys, copy, traceback
import threading
from time import time, sleep
from posixpath import normpath, dirname


from dpa.lib.XMLRPCTools import XMLRPCParser, XMLRPCGenerator
from dpa.lib.XMLRPCTools import Fault as _Fault
from dpa.lib.HTTPTools import HTTPHeaders
from dpa.lib.IOBuffer import IOBuffer
from dpa.lib.makeProperty import makeProperty
from dpa.lib import log
from dpa.client.AuthManager import BaseAuthManager
from dpa.client.HTTPConnection import HTTPConnection, HTTPRequest
from dpa.client.HTTPConnection import AddressError as _AddressError, \
                  AuthenticationError as _AuthenticationError, \
                  ResponseError as _ResponseError, \
                  UserInterrupt as _UserInterrupt, \
                  TimeoutError as _TimeoutError, \
                  ConnectionRefusedError as _ConnectionRefusedError, \
                  ServerUnreachableError as _ServerUnreachableError, \
                  NetworkError as _NetworkError, \
                  InternalError as _InternalError
from dpa.client.HTTPConnectionPool import HTTPConnectionPool


class XMLRPCProxyError(Exception):
  pass


class XMLRPCParseError(XMLRPCProxyError):
  """Indicates a broken response"""

  def __repr__(self):
    return "<XMLRPCParseError: %s>" % self.args[0]

  __str__ = __repr__


class NetworkError(XMLRPCProxyError):
  """Indicates an HTTP protocol error."""

  def __init__(self, code, reason):
    XMLRPCProxyError.__init__(self)
    self.code = code
    self.reason = reason

  def __repr__(self):
    return "<NetworkError %s: %s>" % (self.code, self.reason)

  __str__ = __repr__


class AddressError(NetworkError):
  """Indicates bad address error."""

  def __repr__(self):
    return "<AddressError %s: %s>" % (self.code, self.reason)

  __str__ = __repr__


class AuthenticationError(NetworkError):
  """Indicates an HTTP authentication error."""

  def __repr__(self):
    return "<AuthenticationError %s: %s>" % (self.code, self.reason)

  __str__ = __repr__


class AuthorizationError(NetworkError):
  """Indicates an authorization error."""

  def __repr__(self):
    return "<AuthorizationError %s: %s>" % (self.code, self.reason)

  __str__ = __repr__


class TimeoutError(NetworkError):
  """Indicates an HTTP timeout error."""

  def __repr__(self):
    return "<TimeoutError %s: %s>" % (self.code, self.reason)

  __str__ = __repr__


class ConnectionRefusedError(NetworkError):

  def __repr__(self):
    return "<ConnectionRefusedError %s: %s>" % (self.code, self.reason)

  __str__ = __repr__


class ServerUnreachableError(NetworkError):

  def __repr__(self):
    return "<ServerUnreachableError %s: %s>" % (self.code, self.reason)

  __str__ = __repr__


class ServerError(XMLRPCProxyError):
  """Internal server error"""

  def __init__(self, code, reason):
    XMLRPCProxyError.__init__(self)
    self.code = code
    self.reason = reason

  def __repr__(self):
    return "<ServerError %s: %s>" % (self.code, self.reason)

  __str__ = __repr__


class InternalError(XMLRPCProxyError):

  def __init__(self, code, reason):
    XMLRPCProxyError.__init__(self)
    self.code = code
    self.reason = reason

  def __repr__(self):
    return "<InternalError %s: %s>" % (self.code, self.reason)

  __str__ = __repr__



class UserInterrupt(XMLRPCProxyError):
  """Request interrupted by user."""
  pass


class Fault(XMLRPCProxyError):
  """Indicates an XML-RPC fault package."""

  def __init__(self, faultCode, faultString=''):
    XMLRPCProxyError.__init__(self)
    self.faultCode = faultCode
    self.faultString = faultString

  def __repr__(self):
    return "<Fault %s: %s>" % (self.faultCode, str(self.faultString))

  __str__ = __repr__


class _DummyMethod(object):

  def __init__(self, callFunc, name):
    self.__callFunc = callFunc
    self.__name = name

  def __getattr__(self, name):
    return _DummyMethod(self.__callFunc, "%s.%s" % (self.__name, name))

  def __call__(self, *args):
    return self.__callFunc(self.__name, *args)


class BaseXMLRPCProxy(object):

  def __init__(self, host, proxyHost=None, path=None, appPrefix=None, encoding=None,
               uploadCallback=None, downloadCallback=None,
               parserClass=None, generatorClass=None):
    if '_connectionObj' not in self.__dict__:
      raise NotImplementedError, "'BaseXMLRPCProxy' is abstract class"

    self.errorLoggerName = 'unhandledExceptions'

    if '_host' not in self.__dict__:
      self._setHost(host)

    if '_proxyHost' not in self.__dict__:
      self._setProxyHost(proxyHost)

    if path is None:
      path = '/'
    elif isinstance(path, str):
      path = path.strip()
      if not path:
        path = '/'
      if path != '/': # '/' is good path
        if path[-1] != '/':
          path = path + '/'
        pth = path[:-1]
        if path[0] != '/' or normpath(path) != pth or dirname(path) != pth:
          raise ValueError, \
              "'path' value must be string, contained normalized absolute directory path"
    else:
      raise ValueError, "'path' must be string or None"

    self._path = path
    self._request = HTTPRequest('POST', path)

    if appPrefix is None:
      self._appPrefix = ''
    elif not isinstance(appPrefix, str):
      raise ValueError, "'appPrefix' must be string or None"
    else:
      self._appPrefix = appPrefix.strip()

    if encoding is not None and not isinstance(encoding, str):
      raise ValueError, "'encoding' must be string or None"
    if encoding: # check encoding is not None
      encoding = encoding.strip()
    if encoding:
      self._encoding = encoding
    else:
      self._encoding = sys.getdefaultencoding()

    if uploadCallback is not None and not callable(uploadCallback):
      raise TypeError, "'uploadCallback' must be callable or None"
    else:
     self._uploadCallback = uploadCallback

    if downloadCallback is not None and not callable(downloadCallback):
      raise TypeError, "'downloadCallback' must be callable or None"
    else:
     self._downloadCallback = downloadCallback

    if parserClass is not None and not issubclass(parserClass, XMLRPCParser):
      raise TypeError, "'parserClass' must be subclass of 'XMLRPCParser' or None"
    if parserClass:
      self._parserClass = parserClass
    else:
      self._parserClass = XMLRPCParser
    if generatorClass is not None and \
                               not issubclass(generatorClass, XMLRPCGenerator):
      raise TypeError, \
        "'generatorClass' must be subclass of 'XMLRPCGenerator' or None"
    if generatorClass:
      self._generatorClass = generatorClass
    else:
      self._generatorClass = XMLRPCGenerator

  @makeProperty(str)
  def errorLoggerName():
    pass

  @makeProperty(str, None)
  def query():
    def prepare(self, value):
      if value:
        value = value.strip()
      if not value:
        value = ''
      self._request.query = value
      return value

  @makeProperty(HTTPHeaders, None)
  def headers():
    def prepare(self, value):
      if value:
        headers = copy.copy(value)
        del headers["Content-type"]
      else:
        headers = HTTPHeaders()
      headers["Content-type"] = "text/xml"
      self._request.headers = headers
      return headers


  @makeProperty(BaseAuthManager, None)
  def authManager():
    def fset(self, value):
      self._authManager_property_value = value
      self._connectionObj.authManager = value

  @makeProperty(int)
  def socketTimeout():
    def fset(self, value):
      if value <= 0:
        raise ValueError, "'socketTimeout' must be positive integer"
      self._socketTimeout_property_value = value
      self._connectionObj.socketTimeout = value

  @makeProperty(int)
  def requestTimeout():
    def fset(self, value):
      if value <= 0:
        raise ValueError, "'requestTimeout' must be positive integer"
      self._requestTimeout_property_value = value
      self._connectionObj.requestTimeout = value

  @makeProperty(int)
  def continueTimeout():
    def fset(self, value):
      if value <= 0:
        raise ValueError, "'continueTimeout' must be positive integer"
      self._continueTimeout_property_value = value
      self._connectionObj.continueTimeout = value

  def setDefaultConnectionParams(self):
    self.query = ''
    self.headers = None
    self.authManager = None
    self.socketTimeout = 120
    self.requestTimeout = 300
    self.continueTimeout = 30

  def logInternalError(self):
    excStr = '\n  '.join(traceback.format_exc().split('\n'))
    log.error(self.errorLoggerName, "Unhandled exception:\n  %s\n", excStr)

  def callXMLRPC(self, method, *args):
    try:
      req = copy.copy(self._request)
      if self._uploadCallback:
        req.callback = self._uploadCallback
      stream = IOBuffer()
      g = self._generatorClass(stream, self._encoding)
      if self._appPrefix:
        fullMethodName = '%s.%s' % (self._appPrefix, method)
      else:
        fullMethodName = method
      g.generateRequest(fullMethodName, args)
      stream.seek(0)
      req.fileObject = stream
      req.headers["Content-length"] = str(len(stream))
      con = self.getConnection()
      if not con:
        raise TimeoutError(-1, "Can't get connection")
      try:
        try:
          resp = con.request(req)
        except _UserInterrupt, e:
          raise UserInterrupt, e
        except _AddressError, e:
          raise AddressError(-1, e.args[0])
        except _AuthenticationError, e:
          raise AuthenticationError(-1, e.args[0])
        except _TimeoutError, e:
          raise TimeoutError(-1, e.args[0])
        except _ConnectionRefusedError, e:
          raise ConnectionRefusedError(-1, e.args[0])
        except _ServerUnreachableError, e:
          raise ServerUnreachableError(-1, e.args[0])
        except _ResponseError, e:
          raise NetworkError(-1, e.args[0])
        except _NetworkError, e:
          raise NetworkError(-1, e.args[0])
        except _InternalError:
          raise InternalError(-1, "HTTPConnection internal error")
        del req
        if resp.code != 200:
          con.closeResponse()
          if resp.code in (401, 407):
            raise AuthenticationError(resp.code, resp.reason)
          elif resp.code == 403:
            raise AuthorizationError(resp.code, resp.reason)
          elif resp.code == 504:
            raise TimeoutError(resp.code, resp.reason)
          elif resp.code == 502:
            raise NetworkError(resp.code, resp.reason)
          elif resp.code // 100 == 5: # 5xx
            raise ServerError(resp.code, resp.reason)
          else:
            raise NetworkError(resp.code, resp.reason)
        stream = IOBuffer()
        try:
          con.retrieveResponse(stream, self._downloadCallback)
        except _UserInterrupt, ui:
          raise UserInterrupt, ui
        except _TimeoutError, e:
          raise TimeoutError(-1, e.args[0])
        except _ConnectionRefusedError, e:
          raise ConnectionRefusedError(-1, e.args[0])
        except _ServerUnreachableError, e:
          raise ServerUnreachableError(-1, e.args[0])
        except _ResponseError, e:
          raise NetworkError(-1, e.args[0])
        except _NetworkError, e:
          raise NetworkError(-1, e.args[0])
        except _InternalError:
          raise InternalError(-1, "HTTPConnection internal error")
        con.closeResponse()
        stream.seek(0)
        try:
          p = self._parserClass(stream)
          p.parse()
          res = p.getResult()
        except _Fault, f:
          raise Fault(f.faultCode, f.faultString)
        except Exception, e:
          raise XMLRPCParseError, str(e)
      finally:
        self.putConnection(con)
      return res
    except XMLRPCProxyError:
      raise
    except:
      self.logInternalError()
      raise InternalError(-1, "XMLRPCProxy internal error")

  def __getattr__(self, name):
    return _DummyMethod(self.callXMLRPC, name)

  def __repr__(self):
    if self._proxyHost:
      s = ' (proxy %s)' % self._proxyHost
    else:
      s = ''
    return "<%s '%s%s'%s>" % (self.__class__.__name__, self._host, self._path, s)

  def _setHost(self, host):
    if not isinstance(host, str) or not host.strip():
      raise ValueError, "'host' must be non-empty string"
    self._host = host.strip()

  def _setProxyHost(self, proxyHost):
    if proxyHost is None:
      self._proxyHost = ''
    elif not isinstance(proxyHost, str):
        raise ValueError, "'proxyHost' must be string or None"
    else:
      self._proxyHost = proxyHost.strip()

  def getConnection(self):
    raise NotImplementedError, "'getConnection' methos is not implemented"

  def putConnection(self, con):
    raise NotImplementedError, "'putConnection' methos is not implemented"


class XMLRPCProxy(BaseXMLRPCProxy):

  def __init__(self, host, proxyHost=None, path=None, appPrefix=None, encoding=None,
               uploadCallback=None, downloadCallback=None,
               parserClass=None, generatorClass=None, ConnectionClass=None):
    if ConnectionClass is None:
      ConnectionClass = HTTPConnection
    elif not isinstance(ConnectionClass, HTTPConnection):
      raise ValueError, "'ConnectionClass' must be 'HTTPConnection' instance or None"
    self._setHost(host)
    self._setProxyHost(proxyHost)
    self._connectionObj = ConnectionClass(self._host, self._proxyHost)
    self._lock = threading.Lock()
    super(XMLRPCProxy, self).__init__(host, proxyHost, path, appPrefix, encoding,
                                      uploadCallback, downloadCallback,
                                      parserClass, generatorClass)
    self.setDefaultConnectionParams()

  def getConnection(self):
    self._lock.acquire()
    return self._connectionObj

  def putConnection(self, con):
    self._lock.release()

  def interruptOperation(self):
    self._connectionObj.interruptOperation()


class XMLRPCConcurrentProxy(BaseXMLRPCProxy):

  def __init__(self, host, proxyHost=None, path=None, appPrefix=None, encoding=None,
               uploadCallback=None, downloadCallback=None,
               parserClass=None, generatorClass=None, ConnectionPoolClass=None):
    if ConnectionPoolClass is None:
      ConnectionPoolClass = HTTPConnectionPool
    elif not isinstance(ConnectionPoolClass, HTTPConnectionPool):
      raise ValueError, "'ConnectionPoolClass' must be 'HTTPConnectionPool' instance or None"
    self._connectionObj = ConnectionPoolClass()
    super(XMLRPCConcurrentProxy, self).__init__(host, proxyHost, path, appPrefix, encoding,
                                                uploadCallback, downloadCallback,
                                                parserClass, generatorClass)
    self.setDefaultConnectionParams()
    self.maxConnections = 5

  @makeProperty(int)
  def maxConnections():
    def fset(self, value):
      if value <= 0:
        raise ValueError, "'maxConnections' must be positive integer"
      self._maxConnections_property_value = value
      self._connectionObj.maxConnectionsToPeer = value

  def getConnection(self):
    return self._connectionObj.getConnection(self._host, self._proxyHost)

  def putConnection(self, con):
    self._connectionObj.putConnection(con)
