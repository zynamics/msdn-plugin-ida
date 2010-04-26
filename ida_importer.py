from xml_parser import parse, FunctionHandler
from textwrap import *

wrapper = TextWrapper(break_long_words=False, width=70)

functions = parse("C:\\Programme\\IDA56\\bincrowd-plugin-ida\\msdn.xml")

library = idc.GetInputFile().lower()

library_functions = sorted([function for function in functions if function.dll.lower() == library])

functions_map = { }

for lf in library_functions:
	functions_map[lf.name] = lf

assigned = 0
not_assigned = 0
	
for ea in Functions(0, 0xFFFFFFFF):
	function = idaapi.get_func(ea)
	if not function:
		continue
	
	name = Demangle(idc.GetFunctionName(ea), idc.GetLongPrm(INF_SHORT_DN))
	
	if not name:
		continue
		
	first_parens = name.find("(")
	if first_parens != -1:
		name = name[0:first_parens]

	if functions_map.has_key(name):
		description = functions_map[name].description.encode("UTF-8")
		idaapi.set_func_cmt(function, "\n".join(wrapper.wrap(description)), True)
		print "Assigned to %s" % name
		assigned = assigned + 1
	elif functions_map.has_key(name[0:-1]): # hack for 'we have document for Foo' but function is FooA/FooW
		description = functions_map[name[0:-1]].description.encode("UTF-8")
		idaapi.set_func_cmt(function, "\n".join(wrapper.wrap(description)), True)
		print "Assigned to %s" % name
		assigned = assigned + 1
	else:
		print "Not assigned to %s" % name
		not_assigned = not_assigned + 1
		
print "Total %d" % len(library_functions)
print "Assigned %d" % assigned
print "Not assigned %d" % not_assigned
		

#dll_names = sets.Set([function.dll for function in functions])
#for dll in sorted(dll_names):
#	print dll