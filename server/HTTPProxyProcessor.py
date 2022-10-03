from dpa.client.HTTPConnection import HTTPRequest, HTTPConnectionError, \
                                       TimeoutError
from dpa.client.HTTPConnectionPool import HTTPConnectionPool

from dpa.lib.makeProperty import makeProperty
from dpa.lib.HTTPTools import HTTPHeaders

from HTTPProcessor import BaseHTTPProcessor, atPROXY, _FinishProcess

class HTTPProxyProcessor(BaseHTTPProcessor):

  authType = atPROXY

  hopByHopHeaders = ("connection",
                     "keep-alive",
                     "proxy-authenticate",
                     "proxy-authorization",
                     "te",
                     "trailers",
                     "transfer-encoding",
                     "upgrade")

  def __init__(self, connectionPool=None):
    super(HTTPProxyProcessor, self).__init__()
    self.connectionPool = connectionPool

  @makeProperty(HTTPConnectionPool, None)
  def connectionPool():
    def prepare(self, value):
      if value is None:
        return HTTPConnectionPool()
      else:
        return value

  def processRequest(self, request, response):
    try:
      if not self.processRequestLocally(request, response):
        self.makeRequestToOrigin(request, response)
    except _FinishProcess:
      pass

  def processRequestLocally(self, request, response):
    # redefine in caching proxies
    return False

  def makeRequestToOrigin(self, request, response):
    proxyHost = self.getClientProxy(request)
    con = self.connectionPool.getConnection(request.host, proxyHost)
    if not con:
      self.sendError(response, 503, "Can't get connection to original server")
    clientRequest = self.createClientRequest(request)
    request.clientConnection = con
    try:
      clientResponse = con.request(clientRequest)
    except Exception, e:
      request.clientConnection.closeResponse()
      self.connectionPool.putConnection(con)
      if isinstance(e, TimeoutError):
        self.sendError(response, 504, 'Timed Out')
      elif isinstance(e, HTTPConnectionError):
        self.sendError(response, 502, str(e))
      else: # maybe need more detailed analisys
        self.sendError(response, 500, str(e))
    self.setupResponse(response, clientResponse)

  def postProcess(self, request, response):
    try:
      con = request.clientConnection
    except:
      return
    con.closeResponse()
    super(HTTPProxyProcessor, self).postProcess(request, response)
    self.connectionPool.putConnection(con)

  def createClientRequest(self, request):
    clientRequest = HTTPRequest(request.command, request.path)
    clientRequest.query = request.query
    clientRequest.fileObject = request.stream
    clientRequest.headers = HTTPHeaders()
    conHeader = request.headers.get('Connection', '').strip().lower()
    additionalHopByHopHeaders = [x.strip() for x in conHeader.split(',') if x.strip()]
    for h, v in request.headers.items():
      hl = h.lower()
      if hl not in self.hopByHopHeaders and hl not in additionalHopByHopHeaders:
        clientRequest.headers[h] = v
    return clientRequest

  def setupResponse(self, response, clientResponse):
    response.code = clientResponse.code
    if clientResponse.code // 100 >= 4:
      response.error = True
    response.message = clientResponse.reason
    response.stream = clientResponse.fileObject
    conHeader = clientResponse.headers.get('Connection', '').strip().lower()
    additionalHopByHopHeaders = [x.strip() for x in conHeader.split(',') if x.strip()]
    for h, v in clientResponse.headers.items():
      hl = h.lower()
      if hl not in self.hopByHopHeaders and hl not in additionalHopByHopHeaders:
        response.headers[h] = v

  def getClientProxy(self, request):
    # can be redefined when need
    return None
