from threading import local


class _AuthInfo(local):
  
  user = None
  role = None
#  def __init__(self):
#  self.user = None
#  self.role = None
    
  def  __setattr__(self, name, value):
    if name in ('user', 'role'):
      super(_AuthInfo, self).__setattr__(name, value)
    else:
      raise AttributeError, "can't set attribute"


_authInfo = _AuthInfo()

def clearAuthInfo():
  global _authInfo
  _authInfo.user = None
  _authInfo.role = None

def getAuthInfo():
  global _authInfo
  return _authInfo
