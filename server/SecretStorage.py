import os

class BaseSecretStorage(object):

  def __init__(self):
    pass

  def readSecret(self, realm, username):
    raise NotImplementedError, "'readSecret' method is not defined"

  def writeSecret(self, realm, username, secret):
    raise NotImplementedError, "'writeSecret' method is not defined"

  def removeSecret(self, realm, username):
    raise NotImplementedError, "'removeSecret' method is not defined"

  def listUsers(self, realm):
    raise NotImplementedError, "'listUsers' method is not defined"


class FileSecretStorage(BaseSecretStorage):

  def __init__(self, cfn):
    super(FileSecretStorage, self).__init__()
    self._cfn = cfn

  def _openStorage(self, mode='r'):
    if mode not in ('r', 'w'):
      raise ValueError, "Bad secret storage open mode (must be 'r' or 'w')"
    if not os.path.isfile(self._cfn) and (mode == 'r' or os.path.exists(self._cfn)):
      raise ValueError, "Bad secret storage file '%s'" % self._cfn
    from dpa.lib.Config import Config
    return Config(self._cfn, delimiter=':', caseSensitive=1)

  def readSecret(self, realm, username):
    conf = self._openStorage()
    return conf.readStr('/%s/%s'%(realm, username), '')

  def writeSecret(self, realm, username, secret):
    if not secret:
      raise ValueError, "secret can't be empty"
    if not isinstance(secret, str):
      raise TypeError,  "secret must be string"
    conf = self._openStorage(mode='w')
    conf.writeStr('/%s/%s'%(realm, username), secret)
    conf.flush()

  def removeSecret(self, realm, username):
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


class BsdDbSecretStorage(BaseSecretStorage):

  def __init__(self, cfn):
    super(BsdDbSecretStorage, self).__init__()
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
      raise ValueError, "Bad secret storage file '%s'" % self._cfn

  def readSecret(self, realm, username):
    db = self._openStorage()
    try:
      secret = db['/%s/%s'%(realm, username)]
    except KeyError:
      secret = ''
    return secret

  def writeSecret(self, realm, username, secret):
    if not secret:
      raise ValueError, "secret can't be empty"
    if not isinstance(secret, str):
      raise TypeError,  "secret must be string"
    db = self._openStorage(mode='w')
    db['/%s/%s'%(realm, username)] = secret
    db.sync()

  def removeSecret(self, realm, username):
    db = self._openStorage(mode='w')
    try:
      del db['/%s/%s'%(realm, username)]
    except KeyError:
      pass
    db.sync()

  def listUsers(self, realm):
    key_s = '/%s/' % realm
    db = self._openStorage()
    users = []
    try:
      user, secret = db.set_location(key_s)
      while user.startswith(key_s):
        users.append(user.split('/')[2])
        user, secret = db.next()
    except:
      pass
    return users
