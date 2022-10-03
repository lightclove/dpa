from types import MethodType

from AuthInfo import getAuthInfo


class BaseService(object):

  def __init__(self):
    self._dictOfAPIs = {}
    self.makeAPIDeclarations()

  def makeAPIDeclarations(self):
    raise TypeError, "can't create instance of abstract class"

  def declareAPI(self, nameOfAPI, methodList):
    if self._dictOfAPIs.has_key(nameOfAPI):
      raise ValueError,  "API '%s' already declared" % nameOfAPI
    if isinstance(methodList, str):
      methodList = (methodList,)
    elif not hasattr(methodList, '__len__'):
      raise TypeError, "'methodList' must be string or sequence of strings"
    mDict = {}
    for meth in methodList:
      try:
        method = getattr(self, meth)
      except AttributeError:
        raise ValueError,  "method '%s' not found" % meth
      if type(method) != MethodType:
        raise TypeError,  "attribute '%s' must be instance method" % meth
      mDict[meth] = method
    self._dictOfAPIs[nameOfAPI] = mDict

  def enumerateAPIs(self):
    return self._dictOfAPIs.keys()

  def getAPI(self, nameOfAPI):
    try:
      return self._dictOfAPIs[nameOfAPI]
    except KeyError:
      return None

  def getAPIMethodList(self, nameOfAPI):
    try:
      return self._dictOfAPIs[nameOfAPI].keys()
    except KeyError:
      return None

  def getUser(self):
    return getAuthInfo().user

  def getRole(self):
    return getAuthInfo().role
  
