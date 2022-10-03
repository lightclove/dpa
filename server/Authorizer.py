from RoleStorage import BaseRoleStorage


class AuthorizerOperationalError(Exception): pass


class BaseAuthorizer(object):

  def authorize(self, realm, user, data):
    role = self.extractRole(data)
    if role and not self.checkAuthority(realm, user, role):
      role = None
    return role

  def checkAuthority(self, realm, user, role):
    raise NotImplementedError, "'checkAuthority' method is not defined"

  def extractRole(self, data):
    raise NotImplementedError, "'extractRole' method is not defined"


class _StorageMixIn(object):

  def __init__(self, roleStorage):
    if not isinstance(roleStorage, BaseRoleStorage):
      raise TypeError, "'roleStorage' must be subclass of 'BaseRoleStorage'"
    self.roleStorage = roleStorage

  def checkAuthority(self, realm, user, role):
    try:
      roleList = self.roleStorage.readRoleList(realm, user)
    except:
      raise AuthorizerOperationalError, "Error during role list reading"
    if role in roleList:
      return True
    else:
      return False
