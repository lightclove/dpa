try:
  from hashlib import md5, sha1
except ImportError:
  from md5 import new as md5
  from sha import new as sha1

from dpa.lib.makeProperty import makeProperty

from SecretStorage import BaseSecretStorage


def makeSecret(realm, user, password, alg='md5'):
  if not realm:
    raise ValueError, "'realm' must be specified"
  if not user:
    raise ValueError, "'user' must be specified"
  if not password:
    raise ValueError, "'password' must be specified"
  if alg not in ('md5', 'sha1'):
    raise ValueError, "Hash algorithm is not known"
  if alg == 'md5':
    s = md5()
  elif alg == 'sha1':
    s = sha1()
  s.update(user)
  s.update(':')
  s.update(realm)
  s.update(':')
  s.update(password)
  return '$%s$%s' % (alg, s.hexdigest())


class AuthRealmOperationalError(Exception): pass


class BaseAuthRealm(object):

  def __init__(self, realm, authorizer=None):
    if not isinstance(realm, str):
      raise TypeError,  "'realm' must be string"
    self.realm = realm
    self.authorizer = authorizer

  @makeProperty()
  def authorizer():
    def prepare(self, value):
      from Authorizer import BaseAuthorizer
      if value is None or isinstance(value, BaseAuthorizer):
        return value
      else:
        raise TypeError, "'authorizer' must be BaseAuthorizer instance or None"

  def authenticate(self, data):
    user, credentials = self.extractUserAndCredentials(data)
    if user:
      if not self.checkAuthenticity(user, credentials):
        user = None # authenticity failed
    return user

  def extractUserAndCredentials(self, data):
    raise NotImplementedError, "'extractUserAndCredentials' method is not defined"

  def checkAuthenticity(self, user, credentials):
    raise NotImplementedError, "'checkAuthenticity' method is not defined"


class _StorageMixIn(object):

  def __init__(self, realm, secretStorage, authorizer=None):
    super(_StorageMixIn, self).__init__(realm, authorizer)
    if not isinstance(secretStorage, BaseSecretStorage):
      raise TypeError, "'secretStorage' must be subclass of 'BaseSecretStorage'"
    self.secretStorage = secretStorage


  def checkAuthenticity(self, user, password):
    auth = False
    try:
      secret = self.secretStorage.readSecret(self.realm, user)
    except:
      raise AuthRealmOperationalError, "Error during secret reading"
    if secret and secret[0] == '$':
      l = secret[1:].split('$')
      if len(l) == 2:
        try:
          secrComputed = makeSecret(self.realm, user, password, l[0])
        except:
          secrComputed = None
        if secrComputed == secret:
          auth = True
    return auth
