import re

from dpa.lib.makeProperty import makeProperty
from dpa.lib.SharedLock import SharedLock


RE_PATTERN_TYPE = type(re.compile(''))


class PermissionCheckerOperationalError(Exception): pass


class BasePermissionChecker(object):

  def __init__(self, authInfoField='user'):
    if authInfoField in ('user', 'role'):
      self._authInfoField_property_value = authInfoField
    else:
      raise ValueError, "bad 'autInfoField' value"

  authInfoField = property(lambda self: self._authInfoField_property_value)

  def checkPermissions(self, methodName, permission):
    raise NotImplementedError, "'checkPermissions' method is not defined"


class StaticPermissionChecker(BasePermissionChecker):

  def __init__(self, authInfoField='user'):
    super(StaticPermissionChecker, self).__init__(authInfoField)
    self._permDict = {}
    self._lock = SharedLock()
    self.defaultPermissions = None

  def _verifyPermissions(self, permissions):
    msg = "permissions must be sequence of strings"
    if isinstance(permissions, (list, tuple)):
      for item in permissions:
        if not isinstance(item, str):
          raise ValueError, msg
    else:
      raise ValueError, msg

  @makeProperty()
  def defaultPermissions():
    def prepare(self, value):
      if value is None:
        return None
      self._verifyPermissions(value)
      return value

  def updatePermissions(self, method, permissions):
    self._lock.acquireWrite()
    try:
      self._verifyPermissions(permissions)
      self._permDict[method] = permissions
    finally:
      self._lock.release()

  def deletePermissions(self, method):
    self._lock.acquireWrite()
    try:
      del self._permDict[method]
    except:
      pass
    self._lock.release()

  def enumeratePermissions(self):
    self._lock.acquireRead()
    methodList = self._permDict.keys()
    self._lock.release()
    return methodList

  def getPermissions(self, method):
    self._lock.acquireRead()
    try:
      permissions = self._permDict[method]
    except:
      permissions = None
    self._lock.release()
    return permissions

  def checkPermissions(self, method, permission):
    permissions = self.getPermissions(method)
    if permissions is None:
      if self.defaultPermissions and permission in self.defaultPermissions:
        return True
    elif permission in permissions:
      return True
    return False


class StaticRegExpPermissionChecker(StaticPermissionChecker):

  def _verifyPermissions(self, permissions):
    if type(permissions) != RE_PATTERN_TYPE:
      raise ValueError, "permissions must be compiled regular expression pattern"

  def checkPermissions(self, method, permission):
    permissions = self.getPermissions(method)
    if permissions is None:
      if self.defaultPermissions and self.defaultPermissions.match(permission):
        return True
    elif permissions.match(permission):
      return True
    return False
