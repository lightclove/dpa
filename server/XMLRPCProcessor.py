import sys

from dpa.lib.XMLRPCTools import XMLRPCParser, XMLRPCGenerator, \
                                XMLRPCParseError, XMLRPCParseEncodingError, \
                                XMLRPCParseDataTypeError, XMLRPCParseValueError, \
                                XMLRPCGenerateError, XMLRPCGenerateEncodingError, \
                                XMLRPCGenerateDataTypeError, XMLRPCGenerateValueError, \
                                Fault
from dpa.lib.IOBuffer import IOBuffer
from dpa.lib.makeProperty import makeProperty

from HTTPProcessor import HTTPProcessor, ServiceUnavailableError
from RPCProcessor import *


# Error constants (from Dan Libby's specification at
# http://xmlrpc-epi.sourceforge.net/specs/rfc.fault_codes.php)

# Ranges of errors
ecPARSE_ERROR = -32700
ecSERVER_ERROR = -32600
ecAPPLICATION_ERROR = -32500
ecSYSTEM_ERROR = -32400
ecTRANSPORT_ERROR = -32300

# Specific errors
ecUNSUPPORTED_ENCODING = -32701
ecINVALID_ENCODING_CHAR = -32702
#ecINVALID_PAYLOAD = -32600  # don't want mask ecSERVER_ERROR
ecMETHOD_NOT_FOUND = -32601
ecINVALID_METHOD_PARAMS = -32602
ecINTERNAL_ERROR = -32603

# dpa specific errors
ecPERMISSION_DENIED = -32099

errorDescr = {
  ecPARSE_ERROR: 'Parse error',
  ecSERVER_ERROR: 'Server error',
  ecAPPLICATION_ERROR: 'Internal application error',
  ecSYSTEM_ERROR: 'System error',
  ecTRANSPORT_ERROR: 'Transport error',
  ecUNSUPPORTED_ENCODING: 'Unsupported encoding',
  ecINVALID_ENCODING_CHAR: 'Invalid character for encoding',
#  ecINVALID_PAYLOAD: 'Invalid payload',  # don't want mask ecSERVER_ERROR
  ecMETHOD_NOT_FOUND: 'Function not found',
  ecINVALID_METHOD_PARAMS: 'Invalid parameters',
  ecINTERNAL_ERROR: 'Internal  server error',
  ecPERMISSION_DENIED: 'Permission denied'
}


class XMLRPCProcessor(HTTPProcessor, BaseRPCProcessor):

  def __init__(self, parserClass=None, generatorClass=None):
    HTTPProcessor.__init__(self)
    BaseRPCProcessor.__init__(self)
    if parserClass is not None and not issubclass(parserClass, XMLRPCParser):
      raise TypeError, "'parserClass' must be subclass of 'XMLRPCParser' or None"
    if parserClass:
      self.parserClass = parserClass
    else:
      self.parserClass = XMLRPCParser
    if generatorClass is not None and \
                               not issubclass(generatorClass, XMLRPCGenerator):
      raise TypeError, \
        "'generatorClass' must be subclass of 'XMLRPCGenerator' or None"
    if generatorClass:
      self.generatorClass = generatorClass
    else:
      self.generatorClass = XMLRPCGenerator

  def do_POST(self, request, response):
    self.makeRPCCall(request, response)

  def parseRequest(self, request):
    p = self.parserClass(request.stream)
    p.parse()
    return p.getMethodName(), p.getParams(), p.getEncoding()

  def generateResponse(self, response, result, encoding=None):
    try:
      stream = IOBuffer()
      self.generatorClass(stream, encoding).generateResponse(result)
      stream.seek(0)
    except XMLRPCGenerateEncodingError:  
      stream = IOBuffer()
      self.generatorClass(stream).generateResponse(result) # use utf-8
      stream.seek(0)
    response.headers['Content-type'] = 'text/xml'
    response.headers['Content-length'] = str(len(stream))
    response.stream = stream

  def processError(self, exception, errorSource):
    msg = None
    if hasattr(exception, 'faultCode') and hasattr(exception, 'faultString'):
      return exception, 'Fault: %d. %s' % (exception.faultCode, exception.faultString)
    if isinstance(exception, PermissionCheckerOperationalError):
      raise ServiceUnavailableError, str(exception)
    elif isinstance(exception, PermissionDenied):
      code = ecPERMISSION_DENIED
    elif isinstance(exception, MethodNotSupported):
      code = ecMETHOD_NOT_FOUND
    elif isinstance(exception, (XMLRPCParseEncodingError, XMLRPCGenerateEncodingError)):
      code = ecINVALID_ENCODING_CHAR
    elif  isinstance(exception, (XMLRPCParseDataTypeError, XMLRPCParseValueError)):
      code = ecINVALID_METHOD_PARAMS
    elif isinstance(exception, XMLRPCParseError):
      code = ecPARSE_ERROR
    elif isinstance(exception, XMLRPCGenerateError):
      code = ecSERVER_ERROR
    else:
      if errorSource == esSERVER:
        code = ecINTERNAL_ERROR # internal server error
        msg = 'Internal server error'
        self.logInternalError()
      else:
        if isinstance(exception, TypeError) and str(exception).endswith('given)') and \
           not sys.exc_info()[2].tb_next:
          code = ecINVALID_METHOD_PARAMS
        else:
          code = ecAPPLICATION_ERROR # internal application error
          msg = 'Internal application error'
          self.logInternalError()
    if not msg:
      msg = '%s. %s' % (errorDescr[code], str(exception))
    return Fault(code, errorDescr[code]), 'Fault: %d. %s' % (code, msg)
