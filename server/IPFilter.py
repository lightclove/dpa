from dpa.lib import IPy

class IPFilter:

  def __init__(self):
    self.allowed_list = []
    self.denied_list = []

  def addAllowed(self, ip_addr):
    try:
      if not isinstance(ip_addr, IPy.IP):
        ip_addr = IPy.IP(ip_addr)
    except:
      raise ValueError, 'Bad IP address: %r' % ip_addr
    self.allowed_list.append(ip_addr)

  def addDenied(self, ip_addr):
    try:
      if not isinstance(ip_addr, IPy.IP):
        ip_addr = IPy.IP(ip_addr)
    except:
      raise ValueError, 'Bad IP address: %r' % ip_addr
    self.denied_list.append(ip_addr)

  def check(self, ip_addr):
    if not isinstance(ip_addr, IPy.IP):
      try:
       ip_addr = IPy.IP(ip_addr)
      except:
        raise ValueError, 'Bad IP address'
    good = False
    if self.allowed_list:
      for ip_mask in self.allowed_list:
        if ip_addr in ip_mask:
          good = True
          break
    else:
      good = True
    if good:
      if self.denied_list:
        for ip_mask in self.denied_list:
          if ip_addr in ip_mask:
            good = False
            break
    return good
