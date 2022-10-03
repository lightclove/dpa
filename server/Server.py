import sys, os, threading
import socket, select
import errno, traceback
from weakref import WeakKeyDictionary

from dpa.lib.makeProperty import makeProperty
from dpa.lib.BoundedQueue import BoundedQueue, QueueTimeout
from dpa.lib import log
from Handler import BaseStreamHandler, BaseDatagramHandler, _SocketDataObject
from Application import getApplication


class BaseServer(object):

  addressFamily = socket.AF_INET
  allowReuseAddress = False
  selectTimeout = 0.5
  HandlerClass = None

  def __init__(self, hostList, port, handler):
    if self.HandlerClass is None:
      raise RuntimeError,  "Can't create instance of 'BaseServer' class"
    if isinstance(handler, self.HandlerClass):
      self.handler = handler
    else:
      raise TypeError, "'handler' must be '%s' instance" % self.HandlerClass
    self.loggerName = 'messages'
    self.errorLoggerName = 'unhandledExceptions'
    if not isinstance(port, int) or port <= 0:
      raise TypeError, "'port' must be positive integer"
    self.__port = port
    if isinstance(hostList, str):
      self.__hostList = (hostList,)
    elif not hasattr(hostList, '__len__'):
      raise TypeError, "'hostList' must be string or sequence of strings"
    elif not len(hostList):
      self.__hostList = ('',) # listen on all interfaces
    else:
      self.__hostList = []
      for iface in hostList:
        if isinstance(iface, str):
          # address checking
          # getaddrinfo will raise exception if address is wrong
          socket.getaddrinfo(iface, self.port, self.addressFamily, self.socketType)
          self.__hostList.append(iface)
        else:
          raise TypeError, "'hostList' must be string or sequence of strings"
    self._active = False
    self._sockets = None
    self._thread = None

  @makeProperty(str)
  def loggerName():
    pass

  @makeProperty(str)
  def errorLoggerName():
    pass

  port = property(lambda self: self.__port)
  hostList = property(lambda self: self.__hostList)

  def activate(self):
    if not self._active:
      self._active = True
      self._doActivate()
      self._thread = threading.Thread(target=self._runMethod)
      self._thread.setDaemon(True)
      self._thread.start()

  def _doActivate(self):
    self._sockets = []
    for host in self.hostList:
      sock = socket.socket(self.addressFamily, self.socketType)
      if self.allowReuseAddress:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      sock.bind((host, self.port))
      self._sockets.append(sock)

  def deactivate(self):
    if self._active:
      self._active = False
      self._thread.join()
      self._doDeactivate()

  def _doDeactivate(self):
    for s in self._sockets:
      s.close()
    self._thread = None
    self._sockets = None

  def _getData(self, sock):
    raise NotImplementedError, "'_getData' not implemented"

  def _handleData(self, sock):
    data = self._getData(sock)
    self._processData(data)

  def _processData(self, data):
    self._doProcessData(data)

  def _doProcessData(self, data):
    try:
      self.handler.process(data)
    finally:
      self.clear(data)

  def clear(self, data):
    pass

  def logInternalError(self):
    exc = '\n  '.join(traceback.format_exc().split('\n'))
    log.error(self.errorLoggerName, "Unhandled exception:\n  %s\n", exc)

  def _runMethod(self):
    try:
      while True:
        r, w, e = select.select(self._sockets, [], [], self.selectTimeout)
        if not self._active:
          break
        for sock in r:
          self._handleData(sock)
    except Exception, e:
      if isinstance(e, (SystemExit, socket.error)) or \
         isinstance(e, select.error) and e[0] == errno.EINTR:
        pass
      else:
        self.logInternalError()


class TCPServer(BaseServer):

  HandlerClass = BaseStreamHandler
  socketType = socket.SOCK_STREAM
  queueSize = 5

  def __init__(self, hostList, port, handler):
    super(TCPServer, self).__init__(hostList, port, handler)
    self._activeSockets = WeakKeyDictionary()

  def _doActivate(self):
    super(TCPServer, self)._doActivate()
    for s in self._sockets:
      s.listen(self.queueSize)

  def _doDeactivate(self):
    for sock in self._activeSockets:
      try:
        sock.close()
      except:
        pass
    super(TCPServer, self)._doDeactivate()

  def _getData(self, sock):
    s, cl_addr = sock.accept()
    self._activeSockets[s] = None
    return _SocketDataObject(self, s, cl_addr)

  def clear(self, data):
    try:
      data.socket.shutdown(2)
    except:
      pass
    data.socket.close()


class UDPServer(BaseServer):

  HandlerClass = BaseDatagramHandler
  socketType = socket.SOCK_DGRAM
  maxPacketSize = 65535

  def _getData(self, sock):
    packet, cl_addr = sock.recvfrom(self.maxPacketSize)
    return _SocketDataObject(self, sock, cl_addr, packet)


class _QueuedMixIn(object):

  queueLength = 20
  queueTimeout = 0.5

  def _doActivate(self):
    super(_QueuedMixIn, self)._doActivate()
    self.queue = BoundedQueue(self.queueLength)
    self.queue.timeout = self.queueTimeout
    self.executorThread = threading.Thread(target = self._dataExecutor)
    self.executorThread.setDaemon(False)
    self.executorThread.start()

  def _doDeactivate(self):
    super(_QueuedMixIn, self)._doDeactivate()
    self.executorThread.join()

  def _dataExecutor(self):
    while True:
      if not self._active:
        break
      try:
        data = self.queue.get()
      except QueueTimeout:
        continue
      except socket.error:
        continue
      self._processData(data)
      data = None # decrement reference

  def _handleData(self, sock):
    data = self._getData(sock)
    if data:
      self.queue.put(data)


class QueuedTCPServer(_QueuedMixIn, TCPServer): pass
class QueuedUDPServer(_QueuedMixIn, UDPServer): pass


class _ThreadingMixIn(object):

  def __init__(self, hostList, port, handler):
    self.daemonMode = False
    super(_ThreadingMixIn, self).__init__(hostList, port, handler)

  def _processData(self, data):
    t = threading.Thread(target = self._doProcessData, args = (data,))
    t.setDaemon(self.daemonMode)
    t.start()

  @makeProperty(bool)
  def daemonMode():
    pass


class ThreadingTCPServer(_ThreadingMixIn, TCPServer): pass
class ThreadingUDPServer(_ThreadingMixIn, UDPServer): pass

class QueuedThreadingTCPServer(_QueuedMixIn, ThreadingTCPServer): pass
class QueuedThreadingUDPServer(_QueuedMixIn, ThreadingUDPServer): pass

if hasattr(os, 'fork'):
  class _ForkingMixIn(object):

    activeChildren = None
    maxChildren = 40

    def _processData(self, data):
      """Fork a new subprocess to process the data."""
      self._collectChildren()
      pid = os.fork()
      if pid:
        # Parent process
        if self.activeChildren is None:
          self.activeChildren = []
        self.activeChildren.append(pid)
        self.clear(data)
        return
      else:
        # Child process.
        # This must never return, hence os._exit()!
        try:
          self.handler.process(data)
          os._exit(0)
        except:
          try:
            self.logInternalError()
          finally:
            os._exit(1)

    def _collectChildren(self):
      """Internal routine to wait for died children."""
      while self.activeChildren:
        if len(self.activeChildren) < self.maxChildren:
          options = os.WNOHANG
        else:
          # If the maximum number of children are already
          # running, block while waiting for a child to exit
          options = 0
        try:
          pid, status = os.waitpid(0, options)
        except os.error:
          pid = None
        if not pid: break
        self.activeChildren.remove(pid)

  class ForkingTCPServer(_ForkingMixIn, TCPServer): pass
  class ForkingUDPServer(_ForkingMixIn, UDPServer): pass

  class QueuedForkingTCPServer(_QueuedMixIn, ForkingTCPServer): pass
  class QueuedForkingUDPServer(_QueuedMixIn, ForkingUDPServer): pass
