# zynamics msdn-ida (http://github.com/zynamics/msdn-plugin-ida)
# Copyright (C) 2010
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

from xml_parser import parse, FunctionHandler
from textwrap import *

wrapper = TextWrapper(break_long_words=False, width=70)

functions = parse("C:\\code\\tools\\msdn-crawler\\msdn.xml")

library = idc.GetInputFile().lower()

functions_map = { }

for lf in functions:
    functions_map[lf.name] = lf

assigned = 0
not_assigned = 0
    
for ea in Functions(0, 0xFFFFFFFF):
    function_object = idaapi.get_func(ea)
    if not function_object:
        continue
    
    name = Demangle(idc.GetFunctionName(ea), idc.GetLongPrm(INF_SHORT_DN))
    
    if not name:
        continue
        
    first_parens = name.find("(")
    if first_parens != -1:
        name = name[0:first_parens]

    if functions_map.has_key(name):
        function = functions_map[name];
        if function.dll.lower() == library:
            description = function.description.encode("UTF-8")
            idaapi.set_func_cmt(function_object, "\n".join(wrapper.wrap(description)), True)
            print "Assigned to %s" % name
            assigned = assigned + 1
    elif functions_map.has_key(name[0:-1]): # hack for 'we have document for Foo' but function is FooA/FooW
        function = functions_map[name[0:-1]]
        if function.dll.lower() == library:
            description = function.description.encode("UTF-8")
            idaapi.set_func_cmt(function_object, "\n".join(wrapper.wrap(description)), True)
            print "Assigned to %s" % name
            assigned = assigned + 1
    else:
        print "Not assigned to %s" % name
        not_assigned = not_assigned + 1
        
current_dll = ""

def imported_functions_callback(ea, name, ord):
    """ Callback function for enumerating all imported functions of a module.
    """
    
    global assigned
    global not_assigned
    
    if functions_map.has_key(name):
        function = functions_map[name];
        if function.dll.lower() == current_dll:
            description = function.description.encode("UTF-8")
            idaapi.set_cmt(ea, "\n".join(wrapper.wrap(description)), True)
            print "Assigned to %s" % name
            assigned = assigned + 1
    elif functions_map.has_key(name[0:-1]): # hack for 'we have document for Foo' but function is FooA/FooW
        function = functions_map[name[0:-1]];
        if function.dll.lower() == current_dll:
            description = function.description.encode("UTF-8")
            idaapi.set_cmt(ea, "\n".join(wrapper.wrap(description)), True)
            print "Assigned to %s" % name
            assigned = assigned + 1
    else:
        print "Not assigned to %s" % name
        not_assigned = not_assigned + 1

    return 1

for import_index in xrange(idaapi.get_import_module_qty()):
    current_dll = idaapi.get_import_module_name(import_index).lower() + ".dll"
    idaapi.enum_import_names(import_index, imported_functions_callback)

print "Assigned %d" % assigned
print "Not assigned %d" % not_assigned

