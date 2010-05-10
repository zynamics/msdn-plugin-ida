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
import re

def set_frame_information(ea, arguments):
    index = 0
    frame = idc.GetFrame(ea)
    next_argument = -1
            
    if frame != None:
        start = idc.GetFirstMember(frame)
        end = idc.GetLastMember(frame)
            
        # The second check is important for stack frames ending in " r" or " s"
        while start <= end and next_argument < len(arguments):
            size = idc.GetMemberSize(frame, start)
            name = idc.GetMemberName(frame, start)
            
            if size == None:
                start = start + 1
                continue
                   
            if name in [" r", " s"]:
                # Skip return address and base pointer
                start += size
                next_argument = 0
                continue
            
            if next_argument == -1:
                start += size
                continue
                
            name = idaapi.scr2idb(arguments[next_argument].name.encode("iso-8859-1", "ignore"))
            description = "\n".join(wrapper.wrap(idaapi.scr2idb(arguments[next_argument].description.encode("iso-8859-1", "ignore"))))
                
            idc.SetMemberName(frame, start, name)
            idc.SetMemberComment(frame, start, description, True)
                   
            index = index + 1
            start += size
            next_argument = next_argument + 1

def get_frame_information(ea):
    local_variables = [ ]
    arguments = [ ]
    current = local_variables

    frame = idc.GetFrame(ea)
    
    if frame == None:
        return [[], []]
    
    start = idc.GetFirstMember(frame)
    end = idc.GetLastMember(frame)
    count = 0 # Some stack frames are screwed up and gigantic
    
    while start <= end and count <= 10000:
        size = idc.GetMemberSize(frame, start)
        count = count + 1
        if size == None:
            start = start + 1
            continue

        name = idc.GetMemberName(frame, start)
            
        start += size
        
        if name in [" r", " s"]:
            # Skip return address and base pointer
            current = arguments
            continue
        
        current.append({'name' : name})

    return (local_variables, arguments)

wrapper = TextWrapper(break_long_words=False, width=70)

filename = os.path.join(os.path.split(sys.modules[__name__].__file__)[0], "msdn.xml")
functions = parse(filename)

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
        
    arguments_idb = get_frame_information(ea)[1]
    
    first_parens = name.find("(")
    if first_parens != -1:
        name = name[0:first_parens]

    if functions_map.has_key(name):
        function = functions_map[name];
        arguments = functions_map[name].arguments
        
        if function.dll.lower() == library:
            description = function.description.encode("UTF-8")
            idaapi.set_func_cmt(function_object, "\n".join(wrapper.wrap(description)), True)
            
            if len(arguments) != len(arguments_idb):
                print "Error: Differing number of arguments in %s (documented: %d - disassembled: %d)" % (name, len(arguments), len(arguments_idb))
            else:
                set_frame_information(ea, arguments)
                
            print "Assigned to %s" % name
            assigned = assigned + 1
    elif functions_map.has_key(name[0:-1]): # hack for 'we have document for Foo' but function is FooA/FooW
        function = functions_map[name[0:-1]]
        arguments = functions_map[name[0:-1]].arguments
        if function.dll.lower() == library:
            description = function.description.encode("UTF-8")
            idaapi.set_func_cmt(function_object, "\n".join(wrapper.wrap(description)), True)
            
            if len(arguments) != len(arguments_idb):
                print "Error: Differing number of arguments in %s (documented: %d - disassembled: %d)" % (name, len(arguments), len(arguments_idb))
            else:
                set_frame_information(ea, arguments)
            
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

