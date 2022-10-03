import sys, socket, errno, traceback
import copy
import base64
import select
from posixpath import normpath, dirname
from cStringIO import StringIO

from dpa.lib.IOBuffer import IOBuffer
from dpa.lib.SocketStreams import SocketIStream, SocketOStream
from dpa.lib.HTTPStreams import IdentityIStream, ChunkedIStream, \
                                 IdentityOStream, ChunkedOStream
from dpa.lib.URITools import encodePath, splitHost
from dpa.lib.HTTPTools import HTTPHeaders, parseHTTPHeaders
from dpa.lib.makeProperty import makeProperty
from dpa.lib import log
from dpa.lib.SharedLock import SharedLock

from dpa.client.AuthManager import BaseAuthManager


__version__ = "0.7.1"

amBASIC = 1
amDIGEST = 2

SUPPORTED_AUTH_METHODS = ['basic']

currentEncoding = sys.getdefaultencoding()


class _HostInfoCache(object):

  def __init__(self):
    self._hostInfo = {}
    self._lock = SharedLock()

  def getHostInfo(self, host, port):
    hp = (host, port)
    self._lock.acquireRead()
    try:
      return self._hostInfo[hp]
    finally:
      self._lock.release()

  def deleteHostInfo(self, host, port):
    hp = (host, port)
    self._lock.acquireWrite()
    try:
      del self._hostInfo[hp]
    except:
      pass
    self._lock.release()

  def updateHostInfo(self, host, port, address=None, version=None,
                                                          sendContinue=None):
    hp = (host, port)
    self._lock.acquireWrite()
    if not hp in self._hostInfo:
      self._hostInfo[hp] = (address, version, sendContinue)
    else:
      a, v, s = self._hostInfo[hp]
      if address is not None:
        a = address
      if version is not None:
        v = version
      if sendContinue is not None:
        s = sendContinue
      self._hostInfo[hp] = (a, v, s)
    self._lock.release()


class _AuthData: # for internal use only

  def __init__(self, realm, login, password, authMethod, pathDir,
                                                          updateCache=False):
    self.realm = realm
    self.login = login
    self.password = password
    self.authMethod = authMethod
    self.pathDir = pathDir
    self.updateCache = updateCache


class _AuthItem: # cached in AuthManager class

  def __init__(self, login, password, authMethod):
    self.login = login
    self.password = password
    self.authMethod = authMethod


class _RealmInfoCache(object):

  def __init__(self):
    self._lock = SharedLock()
    self._realmPathDict = {}

  def getRealmByPath(self, host, port, pathDir):
    hp = (host, port)
    res = None
    self._lock.acquireRead()
    if hp in self._realmPathDict:
      pathList = self._realmPathDict[hp]
      for path, realm in pathList:  # long paths are first in pathList
        if pathDir.startswith(path):
          res = realm
          break
    self._lock.release()
    return res

  def deleteRealm(self, host, port, realm):
    hp = (host, port)
    self._lock.acquireWrite()
    if hp in self._realmPathDict:
      pathList = self._realmPathDict[host]
      newList = []
      for path, rlm in pathList:
        if rlm != realm:
          newList.append((path, rlm))
      self._realmPathDict[hp] = newList
    self._lock.release()

  def updateRealmPaths(self, host, port, realm, path):
    hp = (host, port)
    self._lock.acquireWrite()
    if hp in self._realmPathDict:
      pathList = self._realmPathDict[hp]
      newList = []
      currentPathAppended = False
      for pth, rlm in pathList: # pathList sorted by pth
        if pth < path:
          if not currentPathAppended:
            newList.append((path, realm))
            currentPathAppended = True
          newList.append((pth, rlm))
        elif pth == path: # replace old realm
          newList.append((path, realm))
          currentPathAppended = True
        elif not pth.startswith(path) or realm != rlm:
          newList.append((pth, rlm))
      self._realmPathDict[hp] = newList
    else:
      self._realmPathDict[hp] = [(path, realm)]
    self._lock.release()


_hostInfo = _HostInfoCache()
_realmInfo = _RealmInfoCache()


class HTTPConnectionError(Exception): pass

class UserInterrupt(HTTPConnectionError): pass

class RequestError(HTTPConnectionError): pass

class ResponseError(HTTPConnectionError): pass

class ProtocolError(HTTPConnectionError): pass

class HTTP10CommunicationError(ProtocolError): pass

class NetworkError(HTTPConnectionError): pass

class AddressError(NetworkError): pass

class AuthenticationError(NetworkError): pass

class TimeoutError(NetworkError): pass

class ConnectionRefusedError(NetworkError): pass

class ServerUnreachableError(NetworkError): pass

class InternalError(HTTPConnectionError): pass


class _OperationOnClosedSocket(Exception): pass


class HTTPRequest(object):

  blockSize = 65536

  def __init__(self, method, path, query=None, headers=None, fileObject=None,
                                                              callback=None):
    self.method = method
    self.path = path
    self.query = query
    self.fileObject = fileObject
    self.callback = callback
    self.headers = headers
    self._fileObjectInitPos = 0

  def __copy__(self):
    c = HTTPRequest(self.method, self.path)
    c.query = self.query
    c.headers = HTTPHeaders()
    for h, v in self.headers.items():
      c.headers[h] = v
    c.fileObject = self.fileObject
    c.callback = self.callback
    return c

  @makeProperty(str)
  def method():
    def prepare(self, value):
      method = value.strip()
      if not method:
        raise ValueError, "'method' must be non-empty string"
      else:
        return method

  @makeProperty(str)
  def path():
    def prepare(self, value):
      path = value.strip()
      if not path:
        raise ValueError, "'path' must be non-empty string"
      # check path
      if path[-1] == '/': # this is directory path
        pth = path
      else:
        pth = dirname(path)
        if pth[-1] != '/':
          pth += '/'
      if pth == '/':
        self._pathDir = '/'
      else:
        if pth[0] != '/' or normpath(pth) != pth[:-1]:
          raise ValueError, \
            "'path' value must be string, contained normalized absolute path"
        else:
          self._pathDir = pth
      return path

  @makeProperty(str, None)
  def query():
    def prepare(self, value):
      if value:
        value = value.strip()
      if not value:
        value = None
      return value

  @makeProperty(HTTPHeaders, None)
  def headers():
    def prepare(self, value):
      if value:
        return value
      else:
        return HTTPHeaders()

#
#  callback(sendSize, bodySize)
#  sendSize - bytes sended
#  bodySize - body size, if known (by 'Content-length' or
#                                     if fileObject has 'size' attribute)
#                        else None
#  if return value: - request will be interrupted
#
  @makeProperty()
  def callback():
    def prepare(self, value):
      if value is not None and not callable(value):
        raise TypeError, "'callback' must be callable or None"
      return value

  @makeProperty()
  def fileObject():
    def prepare(self, value):
      if value is not None and not hasattr(value, 'read'):
        raise TypeError, \
                      "'fileObject' must be None or must have 'read' attribute"
      if value is None:
        self._fileObjectInitPos = 0
        return value
      elif not hasattr(value, 'tell') or not hasattr(value, 'seek'):
        io = IOBuffer()
        s = value.read(self.blockSize)
        while s:
         io.write(s)
         s = value.read(self.blockSize)
        io.seek(0)
        self._fileObjectInitPos = 0
        return io
      else:
        self._fileObjectInitPos = value.tell()
        return value

  fileObjectInitPos = property(lambda self: self._fileObjectInitPos)


class HTTPResponse(object):

  def __init__(self, code, reason, headers, fileObject=None):
    self.code = code
    self.reason = reason
    self.headers = headers
    self.fileObject = fileObject


def exc_processor(func):
  def wrapper(self, *args, **kw_args):
    try:
      try:
        return func(self, *args, **kw_args)
      except:
        self._checkUserInterrupt()
        raise
    except HTTPConnectionError:
      self._drop()
      raise
    except socket.timeout:
      self._drop()
      raise TimeoutError, "Don't receive response"
    except socket.error, se:
      self._drop()
      if isinstance(se.args, tuple):
        if se.args[0] == errno.ECONNREFUSED:
          raise ConnectionRefusedError, "Connection refused."
        elif se.args[0] in (errno.EHOSTUNREACH,
                            errno.ENETUNREACH,
                            errno.EHOSTDOWN,
                            errno.ENETDOWN):
          raise ServerUnreachableError, "Socket error: %d. '%s'" % se.args[:2]
        else:
          raise NetworkError, "Socket error: %d. '%s'" % se.args[:2]
      else:
        raise NetworkError, "Socket error: %s" % se.args
    except:
      self._drop()
      self.logInternalError()
      raise InternalError, "HTTPConnection internal error"
  return wrapper

class HTTPConnection(object):

  sysVersion = "Python/" + sys.version.split()[0]
  clientVersion = "dpaHTTPClient/" + __version__
  defaultPort = 80
  blockSize = 65536
  maxDummyReadSize = 16384
  maxResponseLen = 209715200 # 200M
  maxRespLineLen = 20480 # 20K
  maxHeaders = 50
  readBufferSize = -1
  writeBufferSize = -1
  scheme = 'http'

  def __init__(self, host, proxyHost=None, authManager=None):
    self.socket = None
    self._readStream = None
    self._writeStream = None
    self._response = None
    self._closeConnection = False
    self._interruptedByUser = False
    self._hadLastResponseEmpty = False
    self.errorLoggerName = 'unhandledExceptions'
    self.__host = None            # initialize object attributes
    self.__hostName = None        #
    self.__port = None            #
    self.__proxyHost = None       # before using properties
    self.__proxyHostName = None   #
    self.__proxyPort = None       #
    self.host = host
    self.proxyHost = proxyHost
    self.authManager = authManager
    self.setDefaultTimeouts()
    self.__protocolVersionString = 'HTTP/1.1'
    self.__protocolVersion = 101

  @makeProperty(str)
  def errorLoggerName():
    pass

  peerVersion = property(lambda self: self.__peerVersion)
  protocolVersionString = property(lambda self: self.__protocolVersionString)
  protocolVersion = property(lambda self: self.__protocolVersion)

  def get_host(self):
    return self.__host
  def set_host(self, host):
    if host == self.__host:
      return
    if not isinstance(host, str):
      raise TypeError, "'host' must be in 'host[:port]' format"
    host = host.strip()
    if not host:
      raise ValueError, "'host' must be in 'host[:port]' format"
    try:
      hst, prt = splitHost(host)
    except:
      raise ValueError, "'host' must be in 'host[:port]' format"
    self.__hostName = hst
    if prt:
      self.__port = prt
    else:
      self.__port = self.defaultPort
    hst = unicode(hst).encode('idna')
    if prt and prt != 80:
      self._hostHeader = '%s:%s' % (hst, prt)
    else:
      self._hostHeader = hst
    self.__host = host
    self._checkPeerInfo()
    if not self.__proxyHost:
      if self._response:
        self._closeConnection = True
      else:
        self.close()
  def get_hostName(self):
    return self.__hostName
  def get_port(self):
    return self.__port
  host = property(get_host, set_host)
  hostName = property(get_hostName)
  port = property(get_port)
  del get_host, set_host, get_hostName, get_port

  def get_proxyHost(self):
    return self.__proxyHost
  def set_proxyHost(self, proxyHost):
    if proxyHost == self.__proxyHost:
      return
    if proxyHost is not None and not isinstance(proxyHost, str):
      raise TypeError, "'proxyHost' must be in 'host[:port]' format or None"
    if proxyHost:
      proxyHost = proxyHost.strip()
      try:
        hst, prt = splitHost(proxyHost)
      except:
        raise ValueError, \
                        "'proxyHost' must be in 'host[:port]' format or None"
      self.__proxyHostName = hst
      if prt:
        self.__proxyPort = prt
      else:
        self.__proxyPort = self.defaultPort
    else:
      self.__proxyHostName = None
      self.__proxyPort = None
    self.__proxyHost = proxyHost
    self._checkPeerInfo()
    if self._response:
     self._closeConnection = True
    else:
      self.close()
  def get_proxyHostName(self):
    return self.__proxyHostName
  def get_proxyPort(self):
    return self.__proxyPort
  proxyHost = property(get_proxyHost, set_proxyHost)
  proxyHostName = property(get_proxyHostName)
  proxyPort = property(get_proxyPort)
  del get_proxyHost, set_proxyHost, get_proxyHostName, get_proxyPort

  @makeProperty(int)
  def socketTimeout():
    def prepare(self, value):
      if value <= 0:
        raise ValueError, "'socketTimeout' must be positive integer"
      return value

  @makeProperty(int)
  def requestTimeout():
    def prepare(self, value):
      if value <= 0:
        raise ValueError, "'requestTimeout' must be positive integer"
      return value

  @makeProperty(int)
  def continueTimeout():
    def prepare(self, value):
      if value <= 0:
        raise ValueError, "'continueTimeout' must be positive integer"
      return value

  @makeProperty(BaseAuthManager, None)
  def authManager():
     pass

  def __repr__(self):
    if self.proxyHost:
      s = ' (proxy %s)' % self.proxyHost
    else:
      s = ''
    return "<HTTPConnection '%s://%s'%s>" % (self.scheme, self.host, s)

  __str__ = __repr__

  def setDefaultTimeouts(self):
    self.socketTimeout = 120
    self.requestTimeout = 300
    self.continueTimeout = 30

  def logInternalError(self):
    excStr = '\n  '.join(traceback.format_exc().split('\n'))
    log.error(self.errorLoggerName, "Unhandled exception:\n  %s\n", excStr)

  @exc_processor
  def request(self, request):
    # Put 'OPTIONS' request here to check server version
    # if server does not support 'OPTIONS' method, it will return
    # response with non-200 status code, but right HTTP version
    # self.request() will set self.__peerVersion if it was None
    if self.peerVersion is None:
      try:
        self._makeRequest(HTTPRequest('OPTIONS', '/'), forSetPeerVersion=True)
      except:
        self._checkUserInterrupt()
    return self._makeRequest(request)

  @exc_processor
  def retrieveResponse(self, fileObject, callback=None):
 #
 #  callback(retrievedSize, bodySize)
 #  retrievedSize - bytes retrived
 #  bodySize - body size from 'Content-length' or None
 #  if return value: - retrieving will be interrupted
 #
    if not hasattr(fileObject, 'read'):
      raise TypeError, "'fileObject' must have 'read' attribute"
    if callback is not None and not callable(callback):
      raise TypeError, "'callback' must be callable or None"
    retrieved = 0
    if not self._response:
      self._checkUserInterrupt()
      raise ProtocolError, "Response is not ready"
    size = self._response.headers['Content-Length']
    if size is not None:
      try:
        size = int(size)
      except:
        raise ResponseError, "Bad 'Content-Length' header: '%s'" % size
    else:
      size = 0
    inputStream = self._response.fileObject
    if callback:
      stopProcessing = callback(retrieved, size)
    else:
      stopProcessing = False
    while True:
      data = inputStream.read(self.blockSize)
      if not data:
        break
      retrieved += len(data)
      fileObject.write(data)
      if callback:
        if callback(retrieved, size): # user interrupt
          self.closeResponse()
          raise UserInterrupt, 'Data download interrupted by user'

  @exc_processor
  def closeResponse(self):
    if not self._response:
      return
    willClose = self._closeConnection
    if self._response.fileObject:
      if not willClose:
        try:
          remain = self.maxDummyReadSize
          foundEof = False
          while remain:
            s = self._response.fileObject.read(remain)
            if not s: # eof
              foundEof = True
              break
            remain -= len(s)
          if not foundEof:
            willClose = True
        except ValueError:  # stream is closed
          willClose = True
        except socket.error, se:
          self._checkUserInterrupt()
          if isinstance(se.args, tuple) and \
             se.args[0] in (errno.ECONNABORTED,
                            errno.ECONNRESET,
                            errno.EPIPE,
                            errno.ENOTCONN,
                            errno.ESHUTDOWN):
            # server closed connection
            willClose = True
          else:
            raise
    self._response = None
    if willClose:
      self.close()

  def setSocketOptions(self):
    # can be redefined in ancestors for setting socket options
    # called after creation of new client socket (before connect)
    # You can add additional properties to ancestor and set
    # actual options to new socket
    pass

  def close(self):
    if self._response:
      self._response = None
    if self._readStream:
      self._readStream.close()
      self._readStream = None
    if self._writeStream:
      self._writeStream.close()
      self._writeStream = None
    if self.socket:
      try:
        self.socket.shutdown(2)
      except:
        pass
      try:
        self.socket.close()
      except:
        pass
      self.socket = None

  def __del__(self):
    self.close()

  def versionString(self):
    return '%s %s' % (self.clientVersion, self.sysVersion)

  def interruptOperation(self):
    self._interruptedByUser = True
    self._drop()

  def _checkUserInterrupt(self):
    if self._interruptedByUser:
      self._interruptedByUser = False
      raise UserInterrupt, "Interrupted by user"

  def _connect(self):
    if self.socket:
      self.close()
    if not self.__peerAddress:
      try:
        global _hostInfo
        if not self.proxyHost: # will connect to 'host'
          host = unicode(self.hostName).encode('idna')
          addrInfo = socket.getaddrinfo(host, self.port, socket.AF_INET,
                                                             socket.SOCK_STREAM)
          self.__peerAddress = [x[4] for x in addrInfo]
          self.__peerVersion = None # unknown
          self.__peerSendContinue = None # unknown
          _hostInfo.updateHostInfo(self.hostName, self.port, self.__peerAddress,
                                    self.__peerVersion, self.__peerSendContinue)
        else: # will connect to 'proxyHost':
          host = unicode(self.proxyHostName).encode('idna')
          addrInfo = socket.getaddrinfo(host, self.proxyPort, socket.AF_INET,
                                                            socket.SOCK_STREAM)
          self.__peerAddress = [x[4] for x in addrInfo]
          self.__peerVersion = None # unknown
          self.__peerSendContinue = None # unknown
          _hostInfo.updateHostInfo(self.proxyHostName, self.proxyPort,
                self.__peerAddress, self.__peerVersion, self.__peerSendContinue)
      except socket.gaierror, msg:
        raise AddressError, "Host '%s'. Address error: \"%s\"" % (host, str(msg))
    for addr in self.__peerAddress:
      try:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.setSocketOptions()
        self.socket.settimeout(self.socketTimeout)
        self.socket.connect(addr)
      except socket.error, msg:
        self._checkUserInterrupt()
        if self.socket:
          self.socket.close()
          self.socket = None
        continue
      break
    if not self.socket:
        raise socket.error, msg
    self._readStream = SocketIStream(self.socket, self.readBufferSize)
    self._writeStream = SocketOStream(self.socket, self.writeBufferSize)

  def _makeRequest(self, request, forSetPeerVersion=False):
    global _hostInfo
    if not isinstance(request, HTTPRequest):
      raise TypeError, "'request' must be 'HTTPRequest' instance"
    if self._response:
      if self._response.fileObject and not self._response.fileObject.eof:
        raise ProtocolError, "Previous request not processed"
      else:
        self._response = None
    request = copy.copy(request) # don't modify original request's headers
    self._analyzeRequest(request)
    self._authData = None
    self._proxyAuthData = None
    self._processAuthHeaders(request)
    while True:
      try:
        if self._closeConnection:
          self.close()
        if not self.socket:
          self._connect()
        self._sendRequest(request)
        resp = None
        if request.fileObject:
          will_send = True
          if request.waitContinue:
            r, w, e = select.select([self.socket], [], [], self.continueTimeout)
            if r:
              resp = self._receiveResponse(request)
              if resp.code == 100:
                if self.__peerSendContinue is None:
                  self.__peerSendContinue = True
                  if not self.proxyHost: # will connect to 'host'
                    _hostInfo.updateHostInfo(self.hostName, self.port,
                                                              sendContinue = True)
                  else:
                    _hostInfo.updateHostInfo(self.proxyHostName, self.proxyPort,
                                                              sendContinue = True)
              else:
                will_send = False
            else:
              if self.__peerSendContinue:
                raise TimeoutError, "Don't receive response"
              elif self.__peerSendContinue is None:
                self.__peerSendContinue = False
                if not self.proxyHost: # will connect to 'host'
                  _hostInfo.updateHostInfo(self.hostName, self.port,
                                                            sendContinue = False)
                else:
                  _hostInfo.updateHostInfo(self.proxyHostName, self.proxyPort,
                                                            sendContinue = False)
          if will_send:
            resp = None
            if request.contentLen:
              writeStream = IdentityOStream(self._writeStream, request.contentLen)
            elif request.useChunked:
              writeStream = ChunkedOStream(self._writeStream)
            else:
              writeStream = IdentityOStream(self._writeStream)
            bodySize = request.contentLen
            sendSize = 0
            while True: # send body
              s = request.fileObject.read(self.blockSize)
              len_s = len(s)
              if len_s:
                writeStream.write(s)
                sendSize += len_s
                if request.callback:
                  if request.callback(sendSize, bodySize): # interrupt
                    self._closeConnection = True
                    raise UserInterrupt, 'Data upload interrupted by user'
              else:
                writeStream.close()
                break
              while self._hasInputData(): # ignore ALL 100 Continue responses
                resp = self._receiveResponse(request)
                if resp.code != 100:
                  break
              if resp:
                break # from send body
        saveTimeout = self.socket.gettimeout()
        self.socket.settimeout(self.requestTimeout)
        if resp is None:
          resp = self._receiveResponse(request)
        while resp.code == 100:
          resp = self._receiveResponse(request)
        self.socket.settimeout(saveTimeout)
        self._checkClose(resp)
        self._response = resp
        if forSetPeerVersion:
          self.closeResponse()
          break
        if resp.code in (401, 407): # authentication or proxy authentication
          if self._processAuthHeaders(request, resp):
            self.closeResponse()
            if request.fileObject:
              request.fileObject.seek(request.fileObjectInitPos)
            continue
        elif resp.code / 100 == 2 or resp.code / 100 == 3:
          # check cache update
          if self._authData and self._authData.updateCache:
            ai = _AuthItem(self._authData.login, self._authData.password,
                                                  self._authData.authMethod)
            _realmInfo.updateRealmPaths(self.hostName, self.port,
                               self._authData.realm, self._authData.pathDir)
            if self.authManager:
              self.authManager.updateAuthItem(self.hostName, self.port,
                                                   self._authData.realm, ai)
          if self._proxyAuthData and self._proxyAuthData.updateCache:
            ai = _AuthItem(self._proxyAuthData.login,
               self._proxyAuthData.password, self._proxyAuthData.authMethod)
            _realmInfo.updateRealmPaths(self.proxyHostName, self.proxyPort,
                                             self._proxyAuthData.realm, '/')
            if self.authManager:
              self.authManager.updateAuthItem(self.proxyHostName,
                              self.proxyPort, self._proxyAuthData.realm, ai)
        resp = None
        break
      except _OperationOnClosedSocket:
        if self.socket and self._writeStream:
          self._writeStream._sock = None # don't want flush buffer
        self.close()
    return self._response

  def _drop(self):
    if self.socket and self._writeStream:
      self._writeStream._sock = None # don't want flush buffer
    self.close()

  def _analyzeRequest(self, request):
    newHeaders = HTTPHeaders()
    if 'Host' in request.headers:
      hostStr = unicode(request.headers['Host']).encode('idna')
      del request.headers['Host']
    else:
      hostStr = self._hostHeader
    URI = encodePath(request.path)
    if request.query:
      URI = '%s?%s' % (URI, request.query)
    if self.proxyHost:
      URI = '%s://%s%s' % (self.scheme, hostStr, URI)
    request.requestLine ='%s %s %s' % \
                            (request.method, URI, self.protocolVersionString)
    newHeaders['Host'] = hostStr
    user_agent = request.headers['User-Agent']
    del request.headers['User-Agent']
    if user_agent:
      user_agent = user_agent.strip()
    else:
      user_agent = self.versionString()
    newHeaders['User-Agent'] = user_agent
    tr_enc = request.headers['Transfer-Encoding']
    if tr_enc:
      tr_enc = tr_enc.strip().lower()
    del request.headers['Transfer-Encoding']
    cont_len = request.headers['Content-Length']
    if cont_len:
      try:
        try:
          cont_len = cont_len.strip()
        except:
          pass
        cont_len = int(cont_len)
      except:
        raise RequestError, "'Content-Length' header must be integer"
    del request.headers['Content-Length']
    expect = request.headers['Expect']
    if expect:
      expect = expect.strip()
    del request.headers['Expect']
    if request.fileObject:
      request.useChunked = False
      if not cont_len and hasattr(request.fileObject, '__len__'):
        cont_len = len(request.fileObject)
      if tr_enc:
        if not self.peerVersion or self.peerVersion <= 100:
          raise HTTP10CommunicationError, \
             "HTTP/1.0 Server doesn't support 'Transfer-Encoding' header"
        elif cont_len:
          cont_len = None # ignore Content-Length
      elif not cont_len:
        if self.peerVersion >= 101:
          request.useChunked = True
          tr_enc = 'chunked'
        else:
          raise HTTP10CommunicationError, \
             "HTTP/1.0 Server want 'Content-Length' header"
      if cont_len:
        request.contentLen = cont_len
      else:
        request.contentLen = None
      if tr_enc:
        newHeaders['Transfer-Encoding'] = tr_enc
      elif cont_len:
        newHeaders['Content-Length'] = str(cont_len)
      request.waitContinue = False
      if self.peerVersion >= 101 and \
              (self.__peerSendContinue is None or self.__peerSendContinue):
        request.waitContinue = True
        if expect:
          if not '100-continue' in expect:
            newHeaders['Expect'] = '100-continue, ' + expect
          else:
            newHeaders['Expect'] = expect
        else:
          newHeaders['Expect'] = '100-continue'
      else:
        if expect:
          expect_tokens = [x.strip() for x in expect.split(',') if x.strip()]
          if '100-continue' in expect_tokens:
            new_tokens = []
            for token in expect_tokens:
              if token != '100-continue':
                new_tokens.append(token)
            expect = ', '.join(new_tokens)
          newHeaders['Expect'] = expect
    conn = request.headers['Connection']
    if conn:
      conn = conn.strip().lower()
      conn_tokens = [x.strip() for x in conn.split(',') if x.strip()]
      if self.peerVersion >= 101:
        if 'keep-alive' in conn_tokens: # RFC-2068
          raise RequestError, \
            "'keep-alive' token is unallowed in 'Connection' header in HTTP/1.1"
        elif 'close' in conn_tokens:
          self._closeConnection = True
      else:
        if 'keep-alive' in conn_tokens:
          if not request.headers['Keep-Alive']:
            newHeaders['Keep-Alive'] = '300'
        else:
          self._closeConnection = True
      del request.headers['Connection']
      newHeaders['Connection'] = conn
    for h, v in request.headers.items():
      newHeaders[h] = v
    request.headers = newHeaders

  def _processAuthHeaders(self, request, response=None):
    global _realmInfo
    pathDir = request._pathDir
    if not response: # 1st attempt, set headers if we know
      if self.proxyHost:
        realm = _realmInfo.getRealmByPath(self.proxyHostName,
                                                          self.proxyPort, '/')
        if realm and self.authManager:
          ai = self.authManager.getAuthItem(self.proxyHostName, \
                                                        self.proxyPort, realm)
        else:
          ai = None
        if ai:
          if ai.authMethod == amBASIC:
            self._addBasicAuthHeaders(request, ai.login, ai.password,
                                                            proxyHeader=True)
            self._proxyAuthData = _AuthData(realm, ai.login, ai.password,
                                                                amBASIC, '/')
      realm = _realmInfo.getRealmByPath(self.hostName, self.port, pathDir)
      if realm and self.authManager:
        ai = self.authManager.getAuthItem(self.hostName, self.port, realm)
      else:
        ai = None
      if ai:
        if ai.authMethod == amBASIC:
          self._addBasicAuthHeaders(request, ai.login, ai.password)
        self._authData = _AuthData(realm, ai.login, ai.password, amBASIC,
                                                                     pathDir)
      return True
    else: # we have authentication or proxy authentication error
      if response.code == 401:
        ahl = response.headers.get_all('WWW-Authenticate', [])
      else:
        ahl = response.headers.get_all('Proxy-Authenticate', [])
      authMethod = None
      for ah in ahl:
        try:
          authMethod = ah.strip().split()[0].lower()
          if authMethod in SUPPORTED_AUTH_METHODS:
            break
        except:
          pass
      if not authMethod:
        return False
      if authMethod == 'basic':
        amPos = ah.find(' ')
        if amPos == -1:
          return False
        realm = self._getBasicAuthRealm(ah[amPos+1:].strip())
        if realm is None:
          return False
        if response.code == 401:
          if self.authManager:
            ai = self.authManager.getAuthItem(self.hostName, self.port, realm)
            if ai:
              login, password = ai.login, ai.password
            else:
              login, password = \
                 self.authManager.requestLoginAndPassword(self.hostName,
                                                             self.port, realm)
            if not login: # login/password not found
              return False
            if self._authData and login == self._authData.login and \
                                          password == self._authData.password:
              self.authManager.deleteAuthItem(self.hostName, self.port, realm)
              return False
            else:
              self._authData = _AuthData(realm, login, password, amBASIC,
                                                                pathDir, True)
              self._addBasicAuthHeaders(request, login, password)
              return True
          else:
            return False
        else:
          if self.authManager:
            ai = self.authManager.getAuthItem(self.proxyHostName,
                                                        self.proxyPort, realm)
            if ai:
              login, password = ai.login, ai.password
            else:
              login, password = \
                 self.authManager.requestLoginAndPassword(self.proxyHostName,
                                                        self.proxyPort, realm)
            if not login: # login/password not found
              return False
            if self._proxyAuthData and login == self._proxyAuthData.login and \
                                      password == self._proxyAuthData.password:
              self.authManager.deleteAuthItem(self.proxyHostName, \
                                                        self.proxyPort, realm)
              return False
            else:
              self._proxyAuthData = _AuthData(realm, login, password, amBASIC,
                                                                     '/', True)
              self._addBasicAuthHeaders(request, login, password,
                                                            proxyHeader = True)
              return True
          else:
            return False
      else:
        return False

  def _getBasicAuthRealm(self, authParams):
    realm = None
    rPos = authParams.find('=')
    if rPos != -1:
      try:
        realm = authParams[rPos+1:].strip()
        if realm[0] == '"' and realm[-1] == '"':
          realm = realm[1:-1]
      except:
        pass
    return realm

  def _addBasicAuthHeaders(self, request, login, password,
                                                          proxyHeader=False):
    if not login:
      login = ''
    if not password:
      password = ''
    cred = '%s:%s' % (login, password)
    cred = ''.join(base64.encodestring(cred).split())
    if proxyHeader:
      del request.headers['Proxy-Authorization']
      request.headers['Proxy-Authorization'] = 'basic %s' % cred
    else:
      del request.headers['Authorization']
      request.headers['Authorization'] = 'basic %s' % cred

  def _sendRequest(self, request):
    try:
      self._writeStream.write('%s\r\n' % request.requestLine)
      for h, v in request.headers.items():
        self._writeStream.write('%s: %s\r\n' % (h, v))
      self._writeStream.write("\r\n")
      self._writeStream.flush()
    except socket.error, se:
      self._checkUserInterrupt()
      if isinstance(se.args, tuple) and \
         se.args[0] in (errno.ECONNABORTED,
                        errno.ECONNRESET,
                        errno.EPIPE,
                        errno.ENOTCONN,
                        errno.ESHUTDOWN):
        # server closed connection
        raise _OperationOnClosedSocket
      else:
        raise


  def _receiveResponse(self, request):
    global _hostInfo
    try:
      rline = self._readStream.readline(self.maxRespLineLen)
      if not rline:
        self._checkUserInterrupt()
        if self._hadLastResponseEmpty:
          self._hadLastResponseEmpty = False
          raise ResponseError, "Empty response from server"
        else:
          self._hadLastResponseEmpty = True
          raise _OperationOnClosedSocket
      else:
        self._hadLastResponseEmpty = False
      if len(rline) >= 2 and rline[-2:] == '\r\n':
          rline = rline[:-2]
      elif rline[-1:] == '\n':
          rline = rline[:-1]
      else: # End of request line was not found!
        raise ResponseError, "Response status line is too long"
      words = rline.split(None, 2) # None - whitespace separator, 2 splits
      if len(words) == 3:
        version, code, reason = words
        if version[:5] != 'HTTP/':
          raise ResponseError, "Wrong HTTP version token (%s)" % version
        try:
          base_version_number = version.split('/', 1)[1]
          version_number = base_version_number.split(".")
          if len(version_number) != 2:
            raise ValueError
          version_number = int(version_number[0]), int(version_number[1])
        except (ValueError, IndexError):
          raise ResponseError, "Wrong HTTP version token (%s)" % version
        try:
          version = version_number[0] * 100 + version_number[1]
        except ValueError:
          raise ResponseError, "Wrong HTTP version token (%s)" % version
        try:
          code = int(code)
        except:
          raise ResponseError, "Wrong HTTP status code (%s)" % code
      else:
        raise ResponseError, "Wrong response status line (%s)" % rline
      hfile = IOBuffer()
      hcount = 0
      while hcount < self.maxHeaders:
        # We don't accept very long headers
        line = self._readStream.readline(self.maxRespLineLen)
        if line == '\r\n' or line == '\n' or line == '':
            break
        if line[-2:] != '\r\n' and line[-1:] != '\n':
          raise ResponseError, "Response header is too long (%s)" % line
        hfile.write(line)
      else:
        raise ResponseError, "Too many response headers"
      hfile.seek(0)
      try:
        headers = parseHTTPHeaders(hfile)
      except:
        raise ResponseError, "Response headers parsing error"
      if 100 <= code < 200 or code in (204, 304) or request.method == 'HEAD':
        fileObject = StringIO('')
      else:
        trEnc = headers['Transfer-Encoding']
        if trEnc:
          trEnc = trEnc.strip().lower()
          if trEnc == "chunked":
            fileObject = ChunkedIStream(self._readStream)
          else:
            raise ResponseError, \
                              "'%s' Transfer-Encoding is not supported" % trEnc
        else:
          contLen = headers['Content-Length']
          if contLen:
            try:
              contLen = int(contLen.strip())
            except:
              raise ResponseError, \
                                  "Bad 'Content-Length' header: '%s'" % contLen
            if contLen:
              fileObject = IdentityIStream(self._readStream, contLen)
            else: #Content-Length: 0
              fileObject = None
          else: # read until socket's EOF
            self._closeConnection = True
            fileObject = IdentityIStream(self._readStream)
      if currentEncoding != 'utf-8':
        try:
          reason = reason.decode('utf-8').encode(currentEncoding)
        except:
          pass
      resp = HTTPResponse(code, reason, headers, fileObject)
      if self.peerVersion is None:
        self.__peerVersion = version
        if not self.proxyHost: # will connect to 'host'
          _hostInfo.updateHostInfo(self.hostName, self.port,
                                                 version = self.__peerVersion)
        else:
          _hostInfo.updateHostInfo(self.proxyHostName, self.proxyPort,
                                                 version = self.__peerVersion)
    except socket.error, se:
      self._checkUserInterrupt()
      if isinstance(se.args, tuple) and \
         se.args[0] in (errno.ECONNABORTED,
                        errno.ECONNRESET,
                        errno.EPIPE,
                        errno.ENOTCONN,
                        errno.ESHUTDOWN):
        # server closed connection
        raise _OperationOnClosedSocket
      else:
        raise
    return resp

  def _hasInputData(self):
    r, w, e = select.select([self.socket], [], [], 0)
    if r:
      return True
    else:
      return False

  def _checkClose(self, response):
    if self._closeConnection:
      return
    if self.peerVersion >= 101:
      self._closeConnection = False
    else:
      self._closeConnection = True
    conn = response.headers['Connection']
    if conn:
      conn = conn.strip().lower()
      conn_tokens = [x.strip() for x in conn.split(',') if x.strip()]
      if self.peerVersion >= 101:
        if 'close' in conn_tokens:
          self._closeConnection = True
          return
      else:
        if 'keep-alive' in conn_tokens:
          self._closeConnection = False
          return
    if self.peerVersion <= 100:
      if response.headers['Keep-Alive']:
        self._closeConnection = False
        return
      pConn = response.headers['Proxy-Connection']
      if pConn:
        pConn = pConn.strip().lower()
        pConn_tokens = [x.strip() for x in pConn.split(',') if x.strip()]
        if 'keep-alive' in pConn_tokens:
          self._closeConnection = False
          return

  def _checkPeerInfo(self):
    global _hostInfo
    if not self.proxyHost: # will connect to 'host'
      try:
        self.__peerAddress, self.__peerVersion, self.__peerSendContinue = \
                               _hostInfo.getHostInfo(self.hostName, self.port)
      except KeyError:
        self.__peerAddress, self.__peerVersion, self.__peerSendContinue =  \
                                                              None, None, None
    else: # will connect to 'proxyHost':
      try:
        self.__peerAddress, self.__peerVersion, self.__peerSendContinue = \
                     _hostInfo.getHostInfo(self.proxyHostName, self.proxyPort)
      except KeyError:
        self.__peerAddress, self.__peerVersion, self.__peerSendContinue =  \
                                                              None, None, None

class HTTPSConnection(HTTPConnection):

  defaultPort = 437

  def __init__(self, host, proxyHost=None, authManager=None):
    raise NotImplementedError, "'HTTPSConnection' class will be added later"
