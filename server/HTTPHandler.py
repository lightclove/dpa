import sys, time, socket, errno
import traceback
import select
from cStringIO import StringIO
from posixpath import normpath, dirname

from dpa.lib.IOBuffer import IOBuffer
from dpa.lib.HTTPStreams import IdentityIStream, ChunkedIStream, \
                                 IdentityOStream, ChunkedOStream
from dpa.lib.URITools import decodePath, parseURI
from dpa.lib.HTTPTools import HTTPHeaders, parseHTTPHeaders
from dpa.lib.makeProperty import makeProperty
from dpa.lib import log
from dpa.lib.SharedLock import SharedLock

from Handler import BaseStreamHandler
from HTTPProcessor import HTTPProcessor, ServiceUnavailableError
from HTTPProxyProcessor import HTTPProxyProcessor
from HTTPDispatcher import BaseHTTPDispatcher
from AuthInfo import getAuthInfo, clearAuthInfo
from IPFilter import IPFilter


__version__ = "0.7.1"

DEFAULT_ERROR_MESSAGE = """\
<head>
<title>Error</title>
</head>
<body>
<h2>Error response</h2>
<p><strong>Server:</strong> %(server)s
<p><strong>Code:</strong> %(code)d - %(explain)s
<p><strong>Message:</strong> %(message)s
</body>
"""

weekdayname = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

monthname = [None,
             'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
             'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

currentEncoding = sys.getdefaultencoding()

def escape(s):
  return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

class _FQDNCache(object):

  def __init__(self, maxCacheSize):
    self._fqdnames = {}
    self._lock = SharedLock()
    self._maxCacheSize = maxCacheSize

  def getFQDN(self, addr):
    self._lock.acquireRead()
    try:
      return self._fqdnames[addr]
    finally:
      self._lock.release()

  def addFQDN(self, addr, name):
    self._lock.acquireWrite()
    if len(self._fqdnames) >= self._maxCacheSize:
      self._fqdnames = {}
    self._fqdnames[addr] = name
    self._lock.release()


class HTTPRequest(object):

  def __init__(self, version=100):
    self.version = version  # 100 - HTTP/1.0, 101 - HTTP/1.1
    self.requestLine = ''
    self.command = ''
    self.requestURI = ''
    self.scheme = ''
    self.host = '' # host[:port]
    self.path = ''
    self.pathDir = ''
    self.query = ''
    self.headers = HTTPHeaders()
    self.stream = None
    self.expectContinue = False
    self.continueSend = False
    self.serverHost = ''
    self.serverPort = 0
    self.clientHost = ''

  @makeProperty()
  def version():
    def prepare(self, value):
      if value not in (100, 101):
        raise ValueError, "'version' must be 100 (HTTP/1.0) or 101 (HTTP/1.1)"
      return value


class HTTPResponse(object):

  def __init__(self):
    self.headers = HTTPHeaders()
    self.stream = None
    self.code = 200
    self.message = None
    self.error = False


# Internal exceptions
class _FinishRequest(Exception):
  pass

class _CloseSocket(Exception):
  pass


class BaseHTTPHandler(BaseStreamHandler):

  sysVersion = "Python/" + sys.version.split()[0]
  serverVersion = "dpaHTTPServer/" + __version__
  httpVersion = 'HTTP/1.1'
  maxHeaders = 50
  blockSize = 65536
  maxDummyReadSize = 16384
  waitRequestTimeout = 30
  writeBufferSize = -1 # redefine unbuffered write from Handler


  def __init__(self):
    super(BaseHTTPHandler, self).__init__()
    self.ipFilter = None
    self.maxRequestLen = 209715200 # 200M
    self.maxReqLineLen = 20480 # 20K
    self.requestLoggerName = 'httpRequests'
    self.errorLoggerName = 'unhandledExceptions'
    self.serverHost = socket.getfqdn()
    self.errorMessageFormat = DEFAULT_ERROR_MESSAGE

  @makeProperty(int)
  def maxRequestLen():
    def prepare(self, value):
      if value < 0:
        raise TypeError, "'maxRequestLen' must be positive integer"
      return value

  @makeProperty(int)
  def maxRequestLineLen():
    def prepare(self, value):
      if value < 0:
        raise TypeError, "'maxRequestLineLen' must be positive integer"
      return value

  @makeProperty(IPFilter, None)
  def ipFilter():
    pass

  @makeProperty()
  def processor():
    def fget(self):
      raise NotImplementedError,  "'processor' is not defined"
    fset = fget

  @makeProperty(str)
  def requestLoggerName():
    pass

  @makeProperty(str)
  def errorLoggerName():
    pass

  def checkIP(self, ip_addr):
    if self.ipFilter:
      return self.ipFilter.check(ip_addr)
    else:
      return True

  def handle(self, connection):
    connection.close = False
    while not connection.close:
      connection.close = True
      try:
        try:
          self.handleOneRequest(connection)
        except _FinishRequest:  # It's OK! (raised by finishRequest)
          pass
        except Exception, e:
          if not self._isClosedConnectionException(e):
            self.logInternalError()
          break
      finally:
        self.clearRequest(connection)

  def findProcessor(self, connection):
    raise NotImplementedError,  "'findProcessor' method is not defined"

  def handleOneRequest(self, connection):
    global _fqdnCache
    connection.currentRequest = req = HTTPRequest()
    connection.currentResponse = HTTPResponse()
    clearAuthInfo()
    req.serverHost = self.serverHost
    req.serverPort = connection.serverPort
    try:
      req.clientHost = _fqdnCache.getFQDN(connection.clientAddress[0])
    except KeyError:
      try:
        cl_host = str(socket.getfqdn(connection.clientAddress[0]).decode('idna'))
      except:
        cl_host = str(connection.clientAddress[0])
      _fqdnCache.addFQDN(connection.clientAddress[0], cl_host)
      req.clientHost = cl_host
    self.parseRequest(connection)
    proc = self.findProcessor(connection)
    if proc:
      try:
        self.executeRequest(connection, proc)
      except _FinishRequest:  # It's OK! (raised by finishRequest)
        raise
      except ServiceUnavailableError, sue:
        self.sendError(connection, 503, str(sue))
      except Exception, e:
        if self._isClosedConnectionException(e):
          raise
        else:
          self.logInternalError()
          self.sendError(connection, 500)
    else:
      self.sendError(connection, 501)

  def _isClosedConnectionException(self, e):
    if isinstance(e, (socket.timeout, _CloseSocket)):
      return True
    elif isinstance(e, socket.error):
      if isinstance(e.args, tuple) and \
                    e.args[0] in (errno.ECONNABORTED,
                                  errno.ECONNRESET,
                                  errno.EBADF,
                                  errno.EPIPE,
                                  errno.ENOTCONN,
                                  errno.ESHUTDOWN):
        return True
    return False


  def parseRequest(self, connection):
    self.parseRequestLine(connection)
    self.parseRequestHeaders(connection)
    self.analyzeHostAndURI(connection)
    cl_addr = connection.clientAddress[0]
    if not self.checkIP(cl_addr):
      self.sendError(connection, 403, "Access from %s is forbidden" % cl_addr)
    self.analyzeExpectHeader(connection)
    self.analyzeRequestBody(connection)

  def parseRequestLine(self, connection):
    req = connection.currentRequest
    try:
      r, w, e = select.select([connection.socket], [], [], self.waitRequestTimeout)
    except select.error, err:
      if err[0] == errno.EINTR: # Interrupted system call.
        raise _CloseSocket
      else:
        raise
    if not r:
      raise _CloseSocket
    rline = connection.readStream.readline(self.maxReqLineLen)
    if not rline:
      raise _CloseSocket
    if rline[-2:] == '\r\n':
      rline = rline[:-2]
    elif rline[-1:] == '\n':
      rline = rline[:-1]
    else: # End of request line was not found!
      self.sendError(connection, 414, closeConnection=True)
    req.requestLine = rline
    words = rline.split()
    if len(words) == 3:
      req.command, req.requestURI, version = words
      if version[:5] != 'HTTP/':
        self.sendError(connection, 400, "Bad request syntax (%s)" % rline,
                                                          closeConnection=True)
      try:
        version_number = version[5:].split(".", 1)
        req.version = int(version_number[0]) * 100 + int(version_number[1])
      except (ValueError, IndexError):
        self.sendError(connection, 400, "Bad request version (%s)" % version,
                                                         closeConnection=True)
      if req.version < 100:
        self.sendError(connection, 505,
                       "Invalid HTTP Version (%s)" % version,
                                                         closeConnection=True)
    else:
      self.sendError(connection, 400, "Bad request syntax (%s)" % rline,
                                                         closeConnection=True)

  def parseRequestHeaders(self, connection):
    req = connection.currentRequest
    hfile = IOBuffer()
    hcount = 0
    while hcount < self.maxHeaders:
      line = connection.readStream.readline(self.maxReqLineLen) # We don't accept very long headers
      if line == '\r\n' or line == '\n' or line == '':
          break
      if line[-2:] != '\r\n' and line[-1:] != '\n':
        self.sendError(connection, 400,
                                  "Request header is too long (%s)" % line,
                                                         closeConnection=True)
      hfile.write(line)
    else:
      self.sendError(connection, 400, "Too many request headers",
                                                         closeConnection=True)
    hfile.seek(0)
    try:
      req.headers = parseHTTPHeaders(hfile)
    except:
      self.sendError(connection, 400, "Request headers parsing error",
                                                         closeConnection=True)

  def analyzeHostAndURI(self, connection):
    req = connection.currentRequest
    hostHeader = req.headers.get('Host', '')
    if req.version >= 101 and not hostHeader:
      self.sendError(connection, 400,
                         "'Host' header must be specifyed by HTTP/1.1 client")
    req.scheme, req.host, req.path, req.query, d = parseURI(req.requestURI)
    if not req.host: # host from absolute URI is preffered - 19.6.1.1
      req.host = hostHeader
    pos = req.host.find(':')
    if pos != -1:
      req.host = '%s:%s' % (str(req.host[:pos].decode('idna')),
                                                            req.host[pos+1:])
    else:
      req.host = str(req.host.decode('idna'))
    req.path = decodePath(req.path)
    if req.path[-1] == '/': # this is directory path
      pth = req.path
    else:
      pth = dirname(req.path)
      if pth[-1] != '/':
        pth += '/'
    if pth == '/':
      req.pathDir = '/'
    else:
      if pth[0] != '/' or normpath(pth) != pth[:-1]:
        self.sendError(connection, 400,
                                "Request path must be normalized absolute path")
      else:
        req.pathDir = pth

  def analyzeExpectHeader(self, connection):
    req = connection.currentRequest
    eH = req.headers['Expect']
    if eH:
      eH = eH.strip()
      if eH == '100-continue':
        if req.version != 100:
          req.expectContinue = True
      else:
        self.sendError(connection, 417, "Only 100-continue allowed in 'Expect' header")

  def analyzeRequestBody(self, connection):
    req = connection.currentRequest
    tr_enc = req.headers['Transfer-Encoding']
    if tr_enc:
      tr_enc = tr_enc.strip().lower()
      if tr_enc == 'chunked':
        req.stream = ChunkedIStream(connection.readStream)
      else:
        self.sendError(connection, 501, "Not implemented encoding (%s)" % tr_enc)
    else:
      cont_len = req.headers['Content-Length']
      if cont_len is None:
        if req.command in ('POST', 'PUT'):
          self.sendError(connection, 411)
      else:
        try:
          cont_len = int(cont_len)
        except:
          self.sendError(connection, 400,
                      "'Content-Length' header must be integer, '%s' given" % cont_len)
        if cont_len > self.maxRequestLen:
          self.sendError(connection, 413)
        req.stream = IdentityIStream(connection.readStream, cont_len)

  def executeRequest(self, connection, processor):
    req = connection.currentRequest
    resp = connection.currentResponse
    processor.verifyRequest(req, resp)
    if resp.error:
      self.sendResponse(connection) # will clear error flag if resp.code==100
    if not resp.error:
      try:
        processor.preProcess(req, resp)
        processor.processRequest(req, resp)
        self.sendResponse(connection)
      finally:
        processor.postProcess(req, resp)

  def clearRequest(self, connection):
    connection.currentRequest = None
    connection.currentResponse = None
    clearAuthInfo()

  def sendError(self, connection, code, message=None, closeConnection = False):
    resp = connection.currentResponse
    resp.code = code
    resp.stream = None
    if not message:
      resp.message = None
    else:
      resp.message = message
    resp.error = True
    if closeConnection:
      resp.headers['Connection'] = 'close'
    self.sendResponse(connection)
    raise _FinishRequest

  def sendResponse(self, connection):
    try:
      req = connection.currentRequest
      resp = connection.currentResponse
      resp_stream = resp.stream
      if resp.message is None:
        if resp.code in self.responses:
          resp.message = self.responses[resp.code][0]
        else:
          resp.message = ''
      if currentEncoding != 'utf-8':
        try:
          resp.message = resp.message.decode(currentEncoding).encode('utf-8')
        except:
          pass
      resp.message = escape(resp.message)
      if resp.error:
        if resp.code == 100: # Not really error. Client wait 100 Continue response
          connection.writeStream.write('%s 100 Continue\r\n\r\n' % self.httpVersion)
          connection.writeStream.flush()
          req.continueSend = True
          resp.code = 200      #  Clear response fields
          resp.message = None  #
          resp.error = False   #
          return
        self.logRequest(connection)
        if not resp_stream: # Error message body was not generated by method handler
          try:
            explain = self.responses[resp.code][1]
          except KeyError:
            explain = ''
          dct = {'code': resp.code, 'message': resp.message, 'explain': explain,
                 'server': self.serverHost}
          content = (self.errorMessageFormat % dct)
          resp_stream = StringIO(content)
          resp.headers['Content-Length'] = str(len(content))
          resp.headers['Content-Type'] = 'text/html'
      else:
        self.logRequest(connection)
      connection.writeStream.write('%s %d %s\r\n' % \
                             (self.httpVersion, resp.code, resp.message))
      v = resp.headers.get('server', self.versionString()).strip()
      connection.writeStream.write('Server: %s\r\n' % v)
      del resp.headers['server']
      v = resp.headers.get('date', self.dateTimeString()).strip()
      connection.writeStream.write('Date: %s\r\n' % v)
      del resp.headers['date']
      try:
        resp_length = int(resp.headers['Content-Length'].strip())
      except:
        resp_length = None
      del resp.headers['Content-Length']
      tr_enc =  resp.headers['Transfer-Encoding']
      del resp.headers['Transfer-Encoding']
      if tr_enc is not None and req.version == 100:
        # Need internal error indication here
        tr_enc = None
      if tr_enc == 'identity':
        tr_enc = None  # will not send 'Transfer-Encoding: identity'
      if tr_enc:
        tr_enc_served_by_user = True
      else:
        tr_enc_served_by_user = False
      req_con = req.headers.get('Connection', '').strip().lower()
      req_con_tokens = [x.strip() for x in req_con.split(',') if x.strip()]
      resp_con = resp.headers.get('Connection', '').strip().lower()
      resp_con_tokens = [x.strip() for x in resp_con.split(',') if x.strip()]
      del resp.headers['Connection']
      con_close = False
      if req.version == 100: # HTTP/1.0
        if 'keep-alive' not in req_con_tokens or 'close' in resp_con_tokens or \
           (resp_stream is not None and resp_length is None):
          con_close = True
      elif req.version == 101: # HTTP/1.1
        if 'close' in req_con_tokens or 'close' in resp_con_tokens:
          con_close = True
      else: # unknown HTTP version
        con_close = True
      # we want read tail of request if it is not very big
      if resp.error and req.stream is not None and not con_close:
        try:
          r, w, e = select.select([connection.socket], [], [], 0)
        except:
          r = None
        if r:
          con_close = True
          remain = self.maxDummyReadSize
          while remain:
            s = req.stream.read(remain)
            if not s: # eof
              con_close = False
              break
            remain -= len(s)
      if req.version == 100 and not con_close: # HTTP/1.0
        connection.writeStream.write('Connection: keep-alive\r\n')
        connection.writeStream.write('Keep-Alive: timeout=%d\r\n' % \
                                                             self.waitRequestTimeout)
      elif req.version == 101 and con_close: # HTTP/1.1
        connection.writeStream.write('Connection: close\r\n')
      connection.close = con_close
      # will send 'Content-Type' only if response body present
      cont_type = resp.headers.get('Content-Type', 'application/octet-stream').strip()
      del resp.headers['Content-Type']
      # will not modify another headers
      for h, v in resp.headers.items():
        connection.writeStream.write('%s: %s\r\n' % (h, v))
      if resp_stream is None and resp.code == 200 and req.command != 'HEAD':
        resp.code = 204 # No content
      # write 'Content-Length' or 'Transfer-Encoding' header and body (if needed)
      if (resp_stream is not None or req.command == 'HEAD') and \
         resp.code >= 200 and resp.code not in (204, 304):
        if req.version == 100: # HTTP/1.0
          if resp_length is not None:
            connection.writeStream.write('Content-Length: %s\r\n' % resp_length)
        elif req.version == 101: # HTTP/1.1
          if tr_enc:
            connection.writeStream.write('Transfer-Encoding: %s\r\n' % tr_enc)
          elif resp_length is not None:
            connection.writeStream.write('Content-Length: %s\r\n' % resp_length)
          else:
            tr_enc = 'chunked' # any HTTP/1.1 client must support it
            connection.writeStream.write('Transfer-Encoding: %s\r\n' % tr_enc)
        connection.writeStream.write('Content-Type: %s\r\n' % cont_type)
        connection.writeStream.write("\r\n")
        if req.command != 'HEAD':
          if tr_enc_served_by_user:
            wStream = IdentityOStream(connection.writeStream)
          elif tr_enc == 'chunked':
            wStream = ChunkedOStream(connection.writeStream)
          elif resp_length is not None:
            wStream = IdentityOStream(connection.writeStream, resp_length)
          else:
            wStream = IdentityOStream(connection.writeStream)
          blockSize = self.blockSize
          while True:
            s = resp_stream.read(blockSize)
            if not s:
              wStream.close()
              break
            wStream.write(s)
      else: #don't need write body, write end of headers
        connection.writeStream.write("\r\n")
      connection.writeStream.flush()
      if req.stream is not None:
        req.stream.close()
    except socket.timeout:
      connection.close = True

  def logInternalError(self):
    excStr = '\n  '.join(traceback.format_exc().split('\n'))
    log.error(self.errorLoggerName, "Unhandled exception:\n  %s\n", excStr)

  def logRequest(self, connection):
    req = connection.currentRequest
    resp = connection.currentResponse
    ai = getAuthInfo()
    u = ai.user or '-'
    r = ai.role or '-'
    log.info(self.requestLoggerName, '%s %s %s "%s" %s %s', \
             req.clientHost, u, r, req.requestLine, resp.code, resp.message)

  def versionString(self):
      return '%s %s' % (self.serverVersion, self.sysVersion)

  def dateTimeString(self, msSinceEpoch=None):
    """Convert seconds since epoch to HTTP datetime string."""
    if msSinceEpoch == None:
      msSinceEpoch = time.time()
    year, month, day, hh, mm, ss, wd, y, z = time.gmtime(msSinceEpoch)
    return  "%s, %02d %3s %4d %02d:%02d:%02d GMT" % (
            weekdayname[wd], day, monthname[month], year, hh, mm, ss)

  responses = {
    100: ('Continue', 'Request received, please continue.'),
    101: ('Switching Protocols',
          'Switching to new protocol; obey Upgrade header.'),

    200: ('OK', 'Request fulfilled, document follows.'),
    201: ('Created', 'Document created, URL follows.'),
    202: ('Accepted',
          'Request accepted, processing continues off-line.'),
    203: ('Non-Authoritative Information', 'Request fulfilled from cache.'),
    204: ('No response', 'Request fulfilled, nothing follows.'),
    205: ('Reset Content', 'Clear input form for further input.'),
    206: ('Partial Content', 'Partial content follows.'),

    300: ('Multiple Choices',
          'Object has several resources -- see URI list.'),
    301: ('Moved Permanently', 'Object moved permanently -- see URI list.'),
    302: ('Found', 'Object moved temporarily -- see URI list.'),
    303: ('See Other', 'Object moved -- see Method and URL list.'),
    304: ('Not modified',
          'Document has not changed since given time.'),
    305: ('Use Proxy',
          'You must use proxy specified in Location to access this '
          'resource.'),
    307: ('Temporary Redirect',
          'Object moved temporarily -- see URI list.'),

    400: ('Bad request',
          'Bad request syntax or unsupported method.'),
    401: ('Unauthorized',
          'No permission -- see authorization schemes.'),
    402: ('Payment required',
          'No payment -- see charging schemes.'),
    403: ('Forbidden',
          'Request forbidden -- authorization will not help.'),
    404: ('Not Found', 'Nothing matches the given URI.'),
    405: ('Method Not Allowed',
          'Specified method is invalid for this server.'),
    406: ('Not Acceptable', 'URI not available in preferred format.'),
    407: ('Proxy Authentication Required', 'You must authenticate with '
          'this proxy before proceeding.'),
    408: ('Request Timed Out', 'Request timed out; try again later.'),
    409: ('Conflict', 'Request conflict.'),
    410: ('Gone',
          'URI no longer exists and has been permanently removed.'),
    411: ('Length Required', 'Client must specify Content-Length.'),
    412: ('Precondition Failed', 'Precondition in headers is false.'),
    413: ('Request Entity Too Large', 'Entity is too large.'),
    414: ('Request-URI Too Long', 'URI is too long.'),
    415: ('Unsupported Media Type', 'Entity body in unsupported format.'),
    416: ('Requested Range Not Satisfiable',
          'Cannot satisfy request range.'),
    417: ('Expectation Failed',
          'Expect condition could not be satisfied.'),

    500: ('Internal error', 'Server got itself in trouble.'),
    501: ('Not Implemented',
          'Server does not support this operation.'),
    502: ('Bad Gateway', 'Invalid responses from another server/proxy.'),
    503: ('Service temporarily unavailable',
          'The server cannot process the request now.'),
    504: ('Gateway timeout',
          'The gateway server did not receive a timely response.'),
    505: ('HTTP Version not supported', 'Cannot fulfill request.'),
  }


class HTTPHandler(BaseHTTPHandler):

  def __init__(self):
    super(HTTPHandler, self).__init__()
    self.processor = None
    self._mustDispatchRequest = False

  @makeProperty(HTTPProcessor, BaseHTTPDispatcher, None)
  def processor():
    def prepare(self, value):
      if isinstance(value, BaseHTTPDispatcher):
        self._mustDispatchRequest = True
      else:
        self._mustDispatchRequest = False
      return value

  def findProcessor(self, connection):
    if self._mustDispatchRequest:
      return self.processor.dispatch(connection.currentRequest)
    else:
      return self.processor


class HTTPProxyHandler(BaseHTTPHandler):

  def __init__(self):
    super(HTTPProxyHandler, self).__init__()
    self.processor = None

  @makeProperty(HTTPProxyProcessor, None)
  def processor():
    pass

  def findProcessor(self, connection):
    return self.processor

_fqdnCache = _FQDNCache(500)
