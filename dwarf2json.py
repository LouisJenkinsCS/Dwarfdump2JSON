import re
import json

with open("dwarfdump.out") as f:
    # Read header (first line)
    line = f.readline().strip()
    assert len(line) > 0, "Missing ELF header!"
    m = re.match(r'(.*):.*', line)
    assert m is not None, "Failed to match for executable name!"
    execName = m[1]
    jsonMap = {"exec_name" : execName}
    
    # Begin reading up to '.debug_info' labels
    while f.readline():
        line = f.readline()
        if line == "":
            break
        line = line.strip()

        # Begin reading debug_info
        if line == ".debug_info contents:":
            jsonMap[".debug_info"] = {}
            _line = f.readline().strip()

            while True:
                if _line == "":
                    _line = f.readline().strip()
                    continue
                m = re.match("(0x([0-9]|[a-f])+): (.*)", _line)
                if m is None:
                    print(json.dumps(jsonMap, indent=4))
                    exit()
                addr = m[1]
                contents = m[3].strip()
                if contents.startswith("Compile Unit:"):
                    m = re.match("Compile Unit: (.*) \(.*\)", contents)
                    jsonMap[".debug_info"][addr] = m[1]
                    _line = f.readline().strip()
                elif contents.startswith("DW_TAG_"):
                    m = re.match("(DW_TAG_[A-z]+)", contents)
                    label = m[1]
                    jsonMap[".debug_info"][addr] = { "name" : label, "children" : {}}
                    __line = f.readline().strip()
                    while __line != "":
                        m = re.match("(\S+)\t\((.*)\)", __line)
                        assert m is not None, __line
                        jsonMap[".debug_info"][addr]["children"][m[1]] = m[2]
                        __line = f.readline().strip()
                    _line = f.readline().strip()
                elif contents == "NULL":
                    jsonMap[".debug_info"][addr] = "NULL"
                    _line = f.readline().strip()
                    
