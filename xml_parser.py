import xml.sax.handler
import pprint
import sys

class Argument:
	def __init__(self):
		self.name = ""
		self.description = ""
	def __str__(self):
		return ("(%s, %s)" % (self.name, self.description)).encode("ISO-8859-1")
	def __repr__(self):
		return self.__str__()
 
class Function:
	def __init__(self):
		self.name = ""
		self.dll = ""
		self.description = ""
		self.arguments = []
		self.returns = ""
	def __str__(self):
		return self.name
	def __repr__(self):
		return self.__str__()

class FunctionHandler(xml.sax.handler.ContentHandler):
	IN_FUNCTION = 1
	IN_FUNCTION_NAME = 2
	IN_DLL = 3
	IN_FUNCTION_DESCRIPTION = 4
	IN_ARGUMENTS = 5
	IN_ARGUMENT = 6
	IN_ARGUMENT_NAME = 7
	IN_ARGUMENT_DESCRIPTION = 8
	IN_RETURNS = 9

	def __init__(self):
		self.inTitle = 0
		self.mapping = {}
		self.current_step = 0
		self.functions = [ ]
 
	def startElement(self, name, attributes):
		if name == "msdn":
			pass
		elif name == "functions":
			pass
		elif name == "function":
			self.current_step = FunctionHandler.IN_FUNCTION
			self.function = Function()
		elif self.current_step == FunctionHandler.IN_FUNCTION and name == "name":
			self.current_step = FunctionHandler.IN_FUNCTION_NAME
		elif self.current_step == FunctionHandler.IN_ARGUMENT and name == "name":
			self.current_step = FunctionHandler.IN_ARGUMENT_NAME
		elif name == "dll":
			self.current_step = FunctionHandler.IN_DLL
		elif self.current_step == FunctionHandler.IN_FUNCTION and name == "description":
			self.current_step = FunctionHandler.IN_FUNCTION_DESCRIPTION
		elif self.current_step == FunctionHandler.IN_ARGUMENT and name == "description":
			self.current_step = FunctionHandler.IN_ARGUMENT_DESCRIPTION
		elif name == "arguments":
			self.current_step = FunctionHandler.IN_ARGUMENTS
		elif name == "argument":
			self.current_step = FunctionHandler.IN_ARGUMENT
			self.current_argument = Argument()
		elif name == "returns":
			self.current_step = FunctionHandler.IN_RETURNS
		else:
			print "Error: ", name
			sys.exit(0)
			
	def characters(self, data):
		if self.current_step == FunctionHandler.IN_FUNCTION_NAME:
			self.function.name = self.function.name + data
		elif self.current_step == FunctionHandler.IN_DLL:
			self.function.dll = self.function.dll + data
		elif self.current_step == FunctionHandler.IN_FUNCTION_DESCRIPTION:
			self.function.description = self.function.description + data
		elif self.current_step == FunctionHandler.IN_ARGUMENT_NAME:
			self.current_argument.name = self.current_argument.name + data
		elif self.current_step == FunctionHandler.IN_ARGUMENT_DESCRIPTION:
			self.current_argument.description = self.current_argument.description + data
		elif self.current_step == FunctionHandler.IN_RETURNS:
			self.function.returns = self.function.returns + data

	def endElement(self, name):
		if name in ["function", "functions", "msdn"]:
			self.functions.append(self.function)
		elif self.current_step in [FunctionHandler.IN_ARGUMENT_NAME, FunctionHandler.IN_ARGUMENT_DESCRIPTION]:
			self.current_step = FunctionHandler.IN_ARGUMENT
		elif name in ["name", "dll", "description", "arguments", "returns"]:
			self.current_step = FunctionHandler.IN_FUNCTION
		elif name == "argument":
			self.current_step = FunctionHandler.IN_ARGUMENT
			self.function.arguments.append(self.current_argument)
		else:
			print "Error: ", name
			sys.exit(0)
		
def parse(xmlfile):
	parser = xml.sax.make_parser()
	handler = FunctionHandler()
	parser.setContentHandler(handler)
	parser.parse(xmlfile)
	
	return handler.functions

#for function in handler.functions:
#	print function.name.encode("ISO-8859-1")
#	print function.dll.encode("ISO-8859-1")
#	print function.description.encode("ISO-8859-1")
#	print function.returns.encode("ISO-8859-1")
#	
#	for argument in function.arguments:
#		print argument