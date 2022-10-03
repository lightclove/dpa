from posixpath import normpath, dirname

from dpa.lib.IOBuffer import IOBuffer
from dpa.lib.SharedLock import SharedLock

from HTTPProcessor import BaseHTTPProcessor


class BaseHTTPDispatcher(object):

  def __init__(self):
    pass

  def dispatch(self, request):
  # Must be redefined in childs
    return None


class HTTPRequestPathDispatcher(BaseHTTPDispatcher):

  def __init__(self):
    super(HTTPRequestPathDispatcher, self).__init__()
    self._processors = {}
    self._proc_keys_sorted = []
    self._lock = SharedLock()

  def addProcessor(self, path, processor):
    if not isinstance(processor, BaseHTTPProcessor):
      raise TypeError, "'processor' must be instance of 'BaseHTTPProcessor' class"
    if path != '/': # '/' is good path
      if path[-1] != '/':
        path = path + '/'
      pth = path[:-1]
      if path[0] != '/' or normpath(path) != pth or dirname(path) != pth:
        raise ValueError, \
            "'path' value must be string, contained normalized absolute directory path"
    if self._processors.has_key(path):
      raise ValueError, "processor for path '%s' already registered" % path
    self._lock.acquireWrite()
    self._processors[path] = processor
    self._proc_keys_sorted = self._processors.keys()
    self._proc_keys_sorted.sort()
    self._proc_keys_sorted.reverse() # more specificals path will be checked first
    self._lock.release()

  def delProcessor(self, path):
    self._lock.acquireWrite()
    try:
      del self._processors[path]
    finally:
      self._lock.release()

  def getProcessor(self, path):
    self._lock.acquireRead()
    try:
      p = self._processors[path]
    except KeyError:
      p = None
    self._lock.release()
    return p

  def enumerateProcessors(self):
    self._lock.acquireRead()
    p = self._proc_keys_sorted[:]
    self._lock.release()
    return p

  def dispatch(self, request):
    if request.path == '*':
      return None
    proc = None
    pathDir = request.pathDir
    self._lock.acquireRead()
    for pth in self._proc_keys_sorted:
      if pathDir.startswith(pth):
        proc = self._processors[pth]
        break
    self._lock.release()
    return proc
