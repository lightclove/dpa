import os

class BaseRoleStorage(object):

  def __init__(self):
    pass

  def readRoleList(self, realm, username):
    raise NotImplementedError, "'readRoleList' method is not defined"

  def writeRoleList(self, realm, username, roleList):
    raise NotImplementedError, "'writeRoleList' method is not defined"

  def removeRoleList(self, realm, username):
    raise NotImplementedError, "'removeRoleList' method is not defined"

  def listUsers(self, realm):
    raise NotImplementedError, "'listUsers' method is not defined"


class FileRoleStorage(BaseRoleStorage):

  def __init__(self, cfn):
    super(FileRoleStorage, self).__init__()
    self._cfn = cfn

  def _openStorage(self, mode='r'):
    if mode not in ('r', 'w'):
      raise ValueError, "Bad role storage open mode (must be 'r' or 'w')"
    if not os.path.isfile(self._cfn) and (mode == 'r' or os.path.exists(self._cfn)):
      raise ValueError, "Bad role storage file '%s'" % self._cfn
    from dpa.lib.Config import Config
    return Config(self._cfn, delimiter=':', caseSensitive=1)

  def readRoleList(self, realm, username):
    conf = self._openStorage()
    return conf.readStrList('/%s/%s'%(realm, username), [])

  def writeRoleList(self, realm, username, roleList):
    if not roleList:
      raise ValueError, "'roleList' can't be empty"
    if not isinstance(roleList, tuple) and not isinstance(roleList, list):
      raise ValueError, "'roleList' must be list or tuple"
    conf = self._openStorage(mode='w')
    conf.writeStrList('/%s/%s'%(realm, username), roleList)
    conf.flush()

  def removeRoleList(self, realm, username):
    conf = self._openStorage(mode='w')
    try:
      conf.deleteEntry('/%s/%s'%(realm, username))
    except:
      pass
    conf.flush()

  def listUsers(self, realm):
    conf = self._openStorage()
    users = conf.enumerateEntries('/%s/' % realm)
    users.sort()
    return users


class BsdDbRoleStorage(BaseRoleStorage):

  def __init__(self, cfn):
    super(BsdDbRoleStorage, self).__init__()
    self._cfn = cfn

  def _openStorage(self, mode='r'):
    if mode not in ('r', 'w'):
      raise ValueError, "Bad secret storage open mode (must be 'r' or 'w')"
    if mode == 'w':
      mode = 'c'
    import bsddb
    try:
      return bsddb.btopen(self._cfn, mode)
    except:
      raise ValueError, "Bad role storage file '%s'" % self._cfn

  def readRoleList(self, realm, username):
    db = self._openStorage()
    try:
      roleList = db['/%s/%s'%(realm, username)]
      roleList = [x.strip() for x in roleList.split(',')]
    except KeyError:
      roleList = []
    return roleList

  def writeRoleList(self, realm, username, roleList):
    if not roleList:
      raise ValueError, "'roleList' can't be empty"
    if not isinstance(roleList, tuple) and not isinstance(roleList, list):
      raise TypeError, "'roleList' must be list or tuple"
    for x in roleList:
      x = x.strip()
    db = self._openStorage(mode='w')
    db['/%s/%s'%(realm, username)] = ','.join(roleList)
    db.sync()

  def removeRoleList(self, realm, username):
    db = self._openStorage(mode='w')
    try:
      del db['/%s/%s'%(realm, username)]
    except:
      pass
    db.sync()

  def listUsers(self, realm):
    key_s = '/%s/' % realm
    db = self._openStorage()
    users = []
    try:
      user, roleList = db.set_location(key_s)
      while user.startswith(key_s):
        users.append(user.split('/')[2])
        user, roleList = db.next()
    except:
      pass
    return users
