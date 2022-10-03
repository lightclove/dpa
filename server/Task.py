import threading, time, datetime
import traceback

from dpa.lib.makeProperty import makeProperty
from dpa.lib import log


class BaseTask(object):

  def __init__(self, func, args=(), kwargs={}):
    if not callable(func):
      raise TypeError, "'func' must be callable"
    if not isinstance(args, (list, tuple)):
      raise TypeError, "'args' must be list or tuple"
    if not isinstance(kwargs, dict):
      raise TypeError, "'kwargs' must be dict"
    self.loggerName = 'messages'
    self.errorLoggerName = 'unhandledExceptions'
    self._func = func
    self._args = args
    self._kwargs = kwargs
    self._active = False
    self._event = threading.Event()
    self._lastExecTime = 0
    self._thread = None
    self.daemonMode = False

  def computeSleepTime(self):
    # must return number of seconds to sleep before next execution
    raise NotImplementedError, "'computeSleepTime' method not implemented"

  @makeProperty(str)
  def loggerName():
    pass

  @makeProperty(str)
  def errorLoggerName():
    pass

  @makeProperty(bool)
  def daemonMode():
    def fset(self, value):
      self._daemonMode_property_value = value
      if self._active:
        self.deactivate()
        self.activate()

  def activate(self):
    if not self._active:
      if self._thread:
        self._thread.join() # wait previous iteration if active
      self._active = True
      self._thread = threading.Thread(target=self._runMethod)
      self._thread.setDaemon(self.daemonMode)
      self._thread.start()

  def deactivate(self):
    if self._active:
      self._active = False
      self._event.set()

  def logInternalError(self):
    exc = '\n  '.join(traceback.format_exc().split('\n'))
    log.error(self.errorLoggerName, "Unhandled exception:\n  %s\n", exc)

  def _runMethod(self):
    while True:
      self._event.wait(self.computeSleepTime())
      if self._event.isSet():
        self._event.clear()
        if not self._active:
          break
      else:
        try:
          self._lastExecTime = time.time()
          self._func(*self._args, **self._kwargs)
        except:
          self.logInternalError()


class PeriodicTask(BaseTask):
  def __init__(self, func, args=(), kwargs={}, interval=1, pause=0):
    super(PeriodicTask, self).__init__(func, args, kwargs)
    self.interval = interval
    self.pause = pause

  @makeProperty(float, int)
  def interval():
    def fset(self, value):
      if value < 0:
        raise ValueError,  "'interval' must be non-negative value"
      self._interval_property_value = value
      if self._active:
        self._event.set()

  @makeProperty(float, int)
  def pause():
    def fset(self, value):
      if value < 0:
        raise ValueError,  "'pause' must be non-negative value"
      self._pause_property_value = value
      if self._active:
        self._event.set()

  def computeSleepTime(self):
    if self._lastExecTime:
      return max(self._lastExecTime + self.interval - time.time(), self.pause)
    else:
      return 0


class CronTask(BaseTask):
  def __init__(self, func, args=(), kwargs={}, schedule=None):
    super(CronTask, self).__init__(func, args, kwargs)
    self._fieldNames = ('minutes', 'hours', 'days', 'months', 'weekdays')
    self._fieldMaxRanges = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 6))
    self.schedule = schedule
    self._lastExecTime = time.time()
    self._firstExecution = True

  @makeProperty(str, None)
  def schedule():
    def fset(self, value):
      self._parseSchedule(value)
      self._schedule_property_value = value
      if self._active:
        self._event.set()

  def computeSleepTime(self):
    wDT = datetime.datetime.fromtimestamp(self._lastExecTime)
    wDT = wDT.replace(second=0, microsecond=0)
    if self._firstExecution:
      self._firstExecution = False
    else:
      wDT = wDT + datetime.timedelta(seconds=60)
    curValues = [wDT.minute, wDT.hour, wDT.day, wDT.month]
    curYear = wDT.year
    self._recomputeDays(curYear, wDT.month)
    notFound = False
    ready = False
    for idx in range(3, -1, -1):
      val = curValues[idx]
      values = self._values[idx]
      if val > values[-1]:
        for j in range(idx+1):
          self._indexes[j] = 0
        notFound = True
        break
      for i in range(len(values)):
        if val <= values[i]:
          self._indexes[idx] = i
          if val < values[i]:
            for j in range(idx):
              self._indexes[j] = 0
            if idx >= 3:
              self._recomputeDays(curYear, self._values[3][self._indexes[3]])
            ready = True
          break
      if ready:
        break
    if notFound:
      if idx >= 3:
        curYear += 1
        self._recomputeDays(curYear, self._values[3][self._indexes[3]])
      else:
        idx += 1
        for i in range(idx, 4):
          self._indexes[i] += 1
          if self._indexes[i] >= len(self._values[i]):
            for j in range(i+1):
              self._indexes[j] = 0
            if i >= 3:
              curYear += 1
              self._recomputeDays(curYear, self._values[3][self._indexes[3]])
          else:
            break
    nDT = datetime.datetime(curYear,
                            self._values[3][self._indexes[3]],
                            self._values[2][self._indexes[2]],
                            self._values[1][self._indexes[1]],
                            self._values[0][self._indexes[0]],
                            1) # 1 sec: don't want see on microseconds in timedelta
    cDT = datetime.datetime.now()
    if cDT > nDT:
      return 0
    else:
      td = nDT - cDT
      return td.days * 86400 + td.seconds

  def _recomputeDays(self, year, month):
    if month >= 12:
      m = 1
      y = year + 1
    else:
      m = month + 1
      y = year
    maxDay = (datetime.date(y, m, 1) - datetime.timedelta(1)).day
    daysInMonth = range(1, maxDay + 1)
    if self._dows:
      daysForDows = []
      d = datetime.date(year, month, 1)
      for v in daysInMonth:
        if d.replace(day=v).weekday() in self._dows:
          daysForDows.append(v)
    if self._days is None:
      if self._dows is None:
        self._values[2] = daysInMonth
      else:
        self._values[2] = daysForDows
    else:
      acceptableDays = []
      for day in self._days:
        if day <= maxDay:
          acceptableDays.append(day)
        else:
          break
      if not acceptableDays:
        # Day list can't be empty
        # if no acceptable days for current month, use last day of month
        acceptableDays = [maxDay]
      if self._dows is None:
        self._values[2] = acceptableDays
      else:
        resDays = acceptableDays
        resDays.extend(daysForDows)
        resDict = {}
        for val in resDays:
          resDict[val] = None
        resDays = resDict.keys()
        resDays.sort()
        self._values[2] = resDays

  def _parseSchedule(self, schedule):
    if schedule:
      fields = schedule.strip().split()
    else:
      fields = '* * * * *'.split()
    fields = [x.strip() for x in fields]
    if len(fields) != 5:
      raise ValueError, "'schedule': incorrect number of fields"
    fLists = []
    for i in range(len(fields)):
      f = fields[i]
      pos = f.rfind('/')
      if pos == -1:
        step = 1
      else:
        try:
          step = int(f[pos+1:])
        except:
          raise ValueError, \
            "'schedule': incorrect step value in '%s' field" % self._fieldNames[i]
        if step < 1:
          raise ValueError, \
            "'schedule': incorrect step value in '%s' field" % self._fieldNames[i]
        f = f[:pos]
      if f == '*':
        if (i == 2 or i == 4) and step == 1:
          valList = None
        else:
          valList = range(self._fieldMaxRanges[i][0], self._fieldMaxRanges[i][1]+1)
      else:
        valList = []
        fRanges = f.strip().split(',')
        for r in fRanges:
          pos = r.find('-')
          if pos == -1: # not range, single value
            try:
              val = int(r)
            except:
              raise ValueError, \
                "'schedule': non-integer value in '%s' field" % self._fieldNames[i]
            if i == 4:
              if val == 0:
                val = 7
              val -= 1
            if val < self._fieldMaxRanges[i][0] or val > self._fieldMaxRanges[i][1]:
              raise ValueError, \
                "'schedule': unacceptable value in '%s' field" % self._fieldNames[i]
            valList.append(val)
          else:
            try:
              lBound = int(r[:pos])
            except:
              raise ValueError, \
                "'schedule': non-integer lower bound of range in '%s' field" % self._fieldNames[i]
            try:
              uBound = int(r[pos+1:])
            except:
              raise ValueError, \
                "'schedule': non-integer upper bound of range in '%s' field" % self._fieldNames[i]
            skipRange = False
            if i == 4:
              if lBound == 0:
                valList.append(6) # Sunday
                if uBound == 0:
                  skipRange = True
              else:
                lBound -= 1
              if uBound == 0:
                valList.append(6) # Sunday
                skipRange = True
              else:
                uBound -= 1
            if lBound < self._fieldMaxRanges[i][0] or lBound > self._fieldMaxRanges[i][1]:
              raise ValueError, \
                "'schedule': unacceptable lower bound of range in '%s' field" % \
                self._fieldNames[i]
            if uBound < self._fieldMaxRanges[i][0] or uBound > self._fieldMaxRanges[i][1]:
              raise ValueError, \
                "'schedule': unacceptable upper bound of range in '%s' field" % \
                self._fieldNames[i]
            if lBound > uBound:
              raise ValueError, \
                "'schedule': field '%s' - lower bound of range can't be greater than upper" % \
                self._fieldNames[i]
            if not skipRange:
              valList.extend(range(lBound, uBound+1))
        # remove duplicate
        valDict = {}
        for val in valList:
          valDict[val] = None
        valList = valDict.keys()
        valList.sort()
      if step > 1:
        valList = valList[::step]
      if valList is not None and not valList:
        raise ValueError, \
          "'schedule': can't find acceptable values for '%s' field" % self._fieldNames[i]
      fLists.append(valList)
    self._fieldValues = fLists
    self._values = [fLists[0], fLists[1], None, fLists[3]]
    self._days = fLists[2]
    self._dows = fLists[4]
    self._indexes = [-1, -1, -1, -1]


class PersistentCronTask(CronTask):
  def __init__(self, func, args=(), kwargs={}, schedule=None, statusFile=None):
    super(PersistentCronTask, self).__init__(func, args, kwargs, schedule)
    if not statusFile:
      raise ValueError, "'statusFile' not specified"
    else:
      self.statusFile = statusFile
    self.readLastExecTime()

  def computeSleepTime(self):
    self.writeLastExecTime()
    return super(PersistentCronTask, self).computeSleepTime()

  def writeLastExecTime(self):
    try:
      sf = file(self.statusFile, 'w')
      sf.write(time.strftime('%Y%m%dT%H:%M:%S', time.localtime(self._lastExecTime)))
      sf.close()
    except Exception, e:
      log.error(self.loggerName, "Error during persistent cron task status writing: %s", str(e))

  def readLastExecTime(self):
    try:
      sf = file(self.statusFile, 'r')
      status = sf.read()
      sf.close()
      self._lastExecTime = time.mktime(time.strptime(status, '%Y%m%dT%H:%M:%S'))
      self._firstExecution = False
    except:
      self._lastExecTime = time.time()
      self.writeLastExecTime()
