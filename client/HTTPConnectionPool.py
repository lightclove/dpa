import threading
from time import time, sleep

from dpa.lib.URITools import splitHost
from dpa.lib.makeProperty import makeProperty
from dpa.client.AuthManager import BaseAuthManager
from dpa.client.HTTPConnection import HTTPConnection


class _ConListObj(object):
  def __init__(self):
    self._conLock = threading.Lock()
    self._availConNum = 0
    self._curConNum = 0
    self._availTimestamp = 0
    self._conList = []


class HTTPConnectionPool(object):

  ConnectionClass = HTTPConnection
  defaultHTTPPort = 80

  maxConnectionsToPeerLimit = 50
  decreaseTime = 120
  idleTime = 0.005
  socketTimeout = 120

  def __init__(self, maxConnectionsToPeer=10):
    self.maxConnectionsToPeer = maxConnectionsToPeer
    self._conDictLock = threading.Lock()
    self._conListDict = {}
    self.authManager = None
    self.setDefaultTimeouts()

  @makeProperty(int)
  def maxConnectionsToPeer():
    def prepare(self, value):
      if value < 1 or value > self.maxConnectionsToPeerLimit:
        raise ValueError, "'maxConnectionsToPeer' must be integer between 1 and %s " % \
                                                      self.maxConnectionsToPeerLimit
      return value

  @makeProperty(BaseAuthManager, None)
  def authManager():
    pass

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

  def setDefaultTimeouts(self):
    self.socketTimeout = 120
    self.requestTimeout = 300
    self.continueTimeout = 30

  def customizeConnection(self, connection):
    connection.authManager = self.authManager
    connection.socketTimeout = self.socketTimeout
    connection.requestTimeout = self.requestTimeout
    connection.continueTimeout = self.continueTimeout

  def _makeSearchTuple(self, hostName, port):
    return (hostName, port)

  def getConnection(self, host, proxyHost):
    try:
      if proxyHost:
        hostName, port = splitHost(proxyHost)
      else:
        hostName, port = splitHost(host)
    except:
      return None
    if not port:
      port = self.defaultHTTPPort
    con = None
    t = self._makeSearchTuple(hostName, port)
    self._conDictLock.acquire()
    try:
      conListObj = self._conListDict[t]
    except KeyError:
      conListObj = self._conListDict[t] = _ConListObj()
    self._conDictLock.release()
    startTime = time()
    while time() < startTime + self.socketTimeout:
      if conListObj._conLock.acquire(0):
        if conListObj._availConNum:
          conListObj._availConNum -= 1
          con = conListObj._conList.pop()
          if conListObj._availConNum:
            conListObj._availTimestamp = 0
          conListObj._conLock.release()
          break
        elif conListObj._curConNum < self.maxConnectionsToPeer:
          conListObj._curConNum += 1
          con = self.ConnectionClass(host, proxyHost)
          conListObj._conLock.release()
          break
        conListObj._conLock.release()
      sleep(self.idleTime)
    if con:
      self.customizeConnection(con)
      con.host = host
      con.proxyHost = proxyHost
    return con

  def putConnection(self, con):
    if con.proxyHost:
      hostName = con.proxyHostName
      port = con.proxyPort
    else:
      hostName = con.hostName
      port = con.port
    t = self._makeSearchTuple(hostName, port)
    self._conDictLock.acquire()
    try:
      conListObj = self._conListDict[t]
    except KeyError:
      conListObj = self._conListDict[t] = _ConListObj()
    self._conDictLock.release()
    conListObj._conLock.acquire()
    if con in conListObj._conList:
      conListObj._conLock.release()
      return
    if not conListObj._availTimestamp or \
       time() - conListObj._availTimestamp < self.decreaseTime:
      conListObj._conList.append(con)
      conListObj._availConNum += 1
      if not conListObj._availTimestamp:
        conListObj._availTimestamp = time()
    elif conListObj._curConNum:
      conListObj._curConNum -= 1
      conListObj._availTimestamp = time()
    conListObj._conLock.release()
