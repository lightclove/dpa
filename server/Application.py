import sys, os, threading, errno
import traceback
from time import sleep

from dpa.lib.PathProvider import PathProvider, atSERVER
from dpa.lib.makeProperty import makeProperty
from dpa.lib import log
from dpa.lib.SharedLock import SharedLock

from Task import BaseTask
from SignalHandler import SignalHandler

_application = None


class Application(object):
    sleepTime = 0.5
    stopOnActivateError = True

    def __init__(self, name=None):
        global _application
        if _application is not None:
            raise RuntimeError, 'Application object already initialized'
        if not isinstance(name, str) and name is not None:
            raise ValueError, "'name' must be string or None"
        _application = self
        self._execName = os.path.splitext(os.path.basename(sys.argv[0]))[0]
        if name is None:
            self._name = self._execName
        else:
            self._name = name
        self._running = False
        self._servers = {}
        self._tasks = {}
        self._lock = SharedLock()
        self._stopEvent = threading.Event()
        self.loggerName = 'messages'
        self.errorLoggerName = 'unhandledExceptions'
        self.pathProvider = PathProvider(appType=atSERVER)
        self.signalHandler = SignalHandler()

    def getName(self):
        return self._name

    def getExecutableName(self):
        return self._execName

    @makeProperty(PathProvider, None)
    def pathProvider(self):
        pass

    @makeProperty(str, None)
    def loggerName(self):
        pass

    @makeProperty(str, None)
    def errorLoggerName(self):
        pass

    def addServer(self, name, server):
        from Server import BaseServer
        if not isinstance(server, BaseServer):
            raise TypeError, "'server' must be 'BaseServer' instance"
        self._lock.acquireWrite()
        try:
            if name in self._servers:
                raise ValueError, "Server name '%s' is duplicated" % name
            self._servers[name] = server
            if self.running():
                self._activateServer(name)
        finally:
            self._lock.release()

    def deleteServer(self, name):
        self._lock.acquireWrite()
        if self.running():
            self._deactivateServer(name)
        try:
            del self._servers[name]
        except:
            pass
        self._lock.release()

    def getServer(self, name):
        self._lock.acquireRead()
        try:
            s = self._servers[name]
        except:
            s = None
        self._lock.release()
        return s

    def enumerateServers(self):
        self._lock.acquireRead()
        s = self._servers.keys()
        self._lock.release()
        return s

    def addTask(self, name, task):
        if not isinstance(task, BaseTask):
            raise TypeError, "'task' must be BaseTask instance"
        self._lock.acquireWrite()
        try:
            if name in self._tasks:
                raise ValueError, "Task name '%s' is duplicated" % name
            self._tasks[name] = task
            if self.running():
                self._activateTask(name)
        finally:
            self._lock.release()

    def deleteTask(self, name):
        self._lock.acquireWrite()
        if self.running():
            self._deactivateTask(name)
        try:
            del self._tasks[name]
        except:
            pass
        self._lock.release()

    def getTask(self, name):
        self._lock.acquireRead()
        try:
            t = self._tasks[name]
        except KeyError:
            t = None
        self._lock.release()
        return t

    def enumerateTasks(self):
        self._lock.acquireRead()
        t = self._tasks.keys()
        self._lock.release()
        return t

    def shutDown(self):
        self._running = False

    def running(self):
        return self._running

    def notifyStartUp(self):
        log.info(self.loggerName, '%s started.', self.getName())

    def notifyShutDown(self):
        log.info(self.loggerName, '%s stopped.', self.getName())

    def generateAbortMsg(self):
        return '%s aborted.' % self.getName()

    def activate(self):
        for name in self.enumerateServers():
            self._activateServer(name)
        for name in self.enumerateTasks():
            self._activateTask(name)

    def deactivate(self):
        for name in self.enumerateServers():
            self._deactivateServer(name)
        for name in self.enumerateTasks():
            self._deactivateTask(name)

    def run(self):
        try:
            self._lock.acquireWrite()
            try:
                self.activate()
            finally:
                self._lock.release()
            self._running = True
            self.notifyStartUp()
            try:
                while self._running:
                    sleep(self.sleepTime)
            except Exception, e:
                if isinstance(e, KeyboardInterrupt) or \
                                isinstance(e, IOError) and e.errno == errno.EINTR:  # Interrupted system call. It's OK
                    pass
                else:
                    raise
            self._lock.acquireWrite()
            try:
                self.deactivate()
            finally:
                self._lock.release()
            self.notifyShutDown()
        except:
            self.logInternalError()
            msg = self.generateAbortMsg()
            self.fatalError(msg)

    def logInternalError(self):
        exc = '\n  '.join(traceback.format_exc().split('\n'))
        log.error(self.errorLoggerName, "Unhandled exception:\n  %s\n", exc)

    def fatalError(self, msg):
        log.critical(self.loggerName, msg)
        sys.stdout.flush()
        sys.stderr.flush()
        if sys.platform.startswith('win'):
            rc = 1
        else:
            rc = os.EX_SOFTWARE
        os._exit(rc)

    def _activateServer(self, name):
        try:
            self._servers[name].activate()
        except Exception, e:
            msg = "Error during server '%s' activation: %s" % (name, str(e))
            if self.stopOnActivateError:
                self.fatalError(msg)
            else:
                log.error(self.loggerName, msg)

    def _deactivateServer(self, name):
        try:
            self._servers[name].deactivate()
        except Exception, e:
            msg = "Error during server '%s' deactivation: %s"
            log.error(self.loggerName, msg, name, str(e))

    def _activateTask(self, name):
        try:
            self._tasks[name].activate()
        except Exception, e:
            msg = "Error during task '%s' activation: %s" % (name, str(e))
            if self.stopOnActivateError:
                self.fatalError(msg)
            else:
                log.error(self.loggerName, msg)

    def _deactivateTask(self, name):
        try:
            self._tasks[name].deactivate()
        except Exception, e:
            msg = "Error during task '%s' deactivation: %s"
            log.error(self.loggerName, msg, name, str(e))


def getApplication():
    return _application
