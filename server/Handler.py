import sys

from dpa.lib import IPy
from dpa.lib.SocketStreams import SocketIStream, SocketOStream
from dpa.lib.SharedLock import SharedLock


class _SocketDataObject(object):

  def __init__(self, server, sock, cl_addr, packet=None):
    self.server = server
    self.socket = sock
    self.clientAddress = cl_addr
    self.serverPort = sock.getsockname()[1]
    self.packet = packet

class BaseSocketHandler(object):

  def __init__(self):
    pass

  def process(self, data):
    try:
      self.setup(data)
      self.handle(data)
      self.finish(data)
    finally:
      self.clear(data)
      sys.exc_traceback = None    # Help garbage collection

  def setup(self, data):
    pass

  def handle(self, data):
    raise NotImplementedError, "'handle' not implemented"

  def finish(self, data):
    pass

  def clear(self, data):
    pass

class BaseStreamHandler(BaseSocketHandler):

  timeout = 120
  readBufferSize = -1
  writeBufferSize = 0

  def __init__(self):
    super(BaseStreamHandler, self).__init__()

  def setup(self, data):
    data.socket.settimeout(self.timeout)
    data.readStream = SocketIStream(data.socket, self.readBufferSize)
    data.writeStream = SocketOStream(data.socket, self.writeBufferSize)

  def clear(self, data):
    data.writeStream.close()
    data.readStream.close()
    data.writeStream = None
    data.readStream = None

class BaseDatagramHandler(BaseSocketHandler):

  def __init__(self):
    super(BaseDatagramHandler, self).__init__()

  def setup(self, data):
    import cStringIO
    data.readStream = cStringIO.StringIO(data.packet)
    data.writeStream = cStringIO.StringIO()

  def finish(self, data):
    data.socket.sendto(data.writeStream.getvalue(), data.clientAddress)

  def clear(self, data):
    data.writeStream = None
    data.readStream = None

class BaseIPDispatcher(BaseSocketHandler):

  HandlerClass = None

  def __init__(self):
    if self.HandlerClass is None:
      raise RuntimeError, "Can't create instance of 'BaseIPDispatcher' class"
    super(BaseIPDispatcher, self).__init__()
    self._IPs = {}
    self._default_handler = None
    self._lock = SharedLock()

  def addHandler(self, ip, handler):
    if not isinstance(handler, self.HandlerClass):
      raise TypeError, "'handler' must be '%s' instance" % self.HandlerClass
    try:
      if not isinstance(ip, IPy.IP):
        ip = IPy.IP(ip)
    except:
      raise TypeError, 'Bad IP address: %r' % ip
    conflicts = False
    self._lock.acquireWrite()
    try:
      for v in self._IPs:
        if ip in v or v in ip:
          raise ValueError,  "IP address (%s) conflicts with another: %s" % (ip, v)
      self._IPs[ip] = handler
    finally:
      self._lock.release()

  def deleteHandler(self, ip):
    try:
      if not isinstance(ip, IPy.IP):
        ip = IPy.IP(ip)
    except:
      raise TypeError, 'Bad IP address: %r' % ip
    self._lock.acquireWrite()
    try:
      del self._IPs[ip]
    finally:
      self._lock.release()

  def setDefaultHandler(self, handler):
    if not isinstance(handler, self.HandlerClass):
      raise TypeError, "'handler' must be '%s' instance" % self.HandlerClass
    self._default_handler = handler

  def getHandler(self, ip):
    try:
      if not isinstance(ip, IPy.IP):
        ip = IPy.IP(ip)
    except:
      raise TypeError, 'Bad IP address: %r' % ip
    self._lock.acquireRead()
    try:
      h = self._IPs[ip]
    except:
      h = None
    self._lock.release()
    return h

  def enumerateHandlers(self):
    self._lock.acquireRead()
    h = self._IPs.keys()
    self._lock.release()
    return h

  def findHandler(self, ip):
    try:
      if not isinstance(ip, IPy.IP):
        ip = IPy.IP(ip)
    except:
      raise TypeError, 'Bad IP address: %r' % ip
    h = None
    self._lock.acquireRead()
    for v in self._IPs:
      if ip in v:
        h = self._IPs[v]
        break
    self._lock.release()
    return h

  def process(self, data):
    handler = self.findHandler(data.clientAddress[0])
    if handler:
      handler.process(data)
    elif self._default_handler:
      self._default_handler.process(data)


class StreamIPDispatcher(BaseIPDispatcher, BaseStreamHandler):
  HandlerClass = BaseStreamHandler

class DatagramIPDispatcher(BaseIPDispatcher, BaseDatagramHandler):
  HandlerClass = BaseDatagramHandler
