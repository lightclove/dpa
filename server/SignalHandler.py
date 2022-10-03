import sys, signal
import threading

from dpa.lib.makeProperty import makeProperty

class SignalHandler(object):
  def __init__(self):
    self._sig_dict = {}
    self._lock = threading.Lock()
    self.checkInterval = 100

  @makeProperty()
  def checkInterval():
    def fget(self):
      return sys.getcheckinterval()
    def fset(self, value):
      return sys.setcheckinterval(value)

  def setHandler(self, signame, func, args=()):
    self._check_signame(signame)
    if not callable(func):
      raise TypeError, "'func' must be callable"
    self._lock.acquire()
    if signame in self._sig_dict:
      ofunc, oargs = self._sig_dict[signame]
    else:
      ofunc = None
    self._sig_dict[signame] = (func, args)
    ohand = signal.signal(getattr(signal, signame), lambda x,y: func(*args))
    self._lock.release()
    if ofunc:
      return (ofunc, oargs)
    elif ohand in (0, 1):
      return ohand
    else:
      return 0 # SIG_DFL

  def setDefaultHandler(self, signame):
    self._check_signame(signame)
    self._lock.acquire()
    if signame in self._sig_dict:
      ofunc, oargs = self._sig_dict[signame]
      del self._sig_dict[signame]
    else:
      ofunc = None
    ohand = signal.signal(getattr(signal, signame), signal.SIG_DFL)
    self._lock.release()
    if ofunc:
      return (ofunc, oargs)
    elif ohand in (0, 1):
      return ohand
    else:
      return 0 # SIG_DFL

  def setIgnoreHandler(self, signame):
    self._check_signame(signame)
    self._lock.acquire()
    if signame in self._sig_dict:
      ofunc, oargs = self._sig_dict[signame]
      del self._sig_dict[signame]
    else:
      ofunc = None
    ohand = signal.signal(getattr(signal, signame), signal.SIG_IGN)
    self._lock.release()
    if ofunc:
      return (ofunc, oargs)
    elif ohand in (0, 1):
      return ohand
    else:
      return 0 # SIG_DFL

  def _check_signame(self, signame):
    if not hasattr(signal, signame):
      raise ValueError,  "signal '%s' is not supported" % signame
    if len(signame) < 4 or signame[:3] != 'SIG' or signame[3] == '_':
      raise ValueError,  "'%s' is bad signal name" % signame
