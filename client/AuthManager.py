from dpa.lib.makeProperty import makeProperty
from dpa.lib.SharedLock import SharedLock


class BaseAuthManager(object):

  def __init__(self):
    self._lock = SharedLock()
    self._authItemCache = {}

  def updateAuthItem(self, host, port, realm, authItem):
    # authItem is instance of _AuthItem from HTTPConnection module
    self._lock.acquireWrite()
    self._authItemCache[self._makeCacheKey(host, port, realm)] = authItem
    self._lock.release()

  def getAuthItem(self, host, port, realm):
    self._lock.acquireRead()
    try:
      res = self._authItemCache[self._makeCacheKey(host, port, realm)]
    except KeyError:
      res = None
    self._lock.release()
    return res

  def deleteAuthItem(self, host, port, realm):
    self._lock.acquireWrite()
    try:
      del self._authItemCache[self._makeCacheKey(host, port, realm)]
    except:
      pass
    self._lock.release()

  def requestLoginAndPassword(self, host, port, realm):
    raise NotImplementedError, "'requestLoginAndPassword' method is not defined"

  def _makeCacheKey(self, host, port, realm):
    return (host, port, realm)


class StaticAuthManager(BaseAuthManager):

  def __init__(self):
    super(StaticAuthManager, self).__init__()
    self._lpDict = {}
    self.defaultLogin = None
    self.defaultPassword = None

  @makeProperty(str, None)
  def defaultLogin():
    def prepare(self, value):
      if value is None:
        return None
      val = value.strip()
      if not val:
        raise ValueError, "'defaultPassword' can't be empty"
      else:
        return val

  @makeProperty(str, None)
  def defaultPassword():
    def prepare(self, value):
      if value is None:
        return None
      val = value.strip()
      if not val:
        raise ValueError, "'defaultPassword' can't be empty"
      else:
        return val

  def updateLoginAndPassword(self, host, port, realm, login, password):
    self._lock.acquireWrite()
    self._lpDict[(host, port, realm)] = (login, password)
    try:
      del self._authItemCache[self._makeCacheKey(host, port, realm)]
    except:
      pass
    self._lock.release()

  def deleteLoginAndPassword(self, host, port, realm):
    self._lock.acquireWrite()
    try:
      del self._lpDict[(host, port, realm)]
      del self._authItemCache[self._makeCacheKey(host, port, realm)]
    except:
      pass
    self._lock.release()

  def requestLoginAndPassword(self, host, port, realm):
    self._lock.acquireRead()
    try:
      res = self._lpDict[(host, port, realm)]
    except KeyError:
      try :
        res = self._lpDict[(host, port, None)]
      except KeyError:
        res = self.defaultLogin, self.defaultPassword
    self._lock.release()
    return res
