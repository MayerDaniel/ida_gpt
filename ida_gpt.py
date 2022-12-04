import idaapi
import idautils
import idc
import re
import requests

def wordwrap(string: str) -> str:
    # logic to wrap the comments to be readable in IDA
    # written by GTP!
    result = ""
    words = string.split(" ")
    line_length = 0
    for word in words:
        if line_length + len(word) > 60:
            result += "\n"
            line_length = 0
        result += word + " "
        line_length += len(word) + 1
    return result

def rename_stack_variable(func_addr, var_name, new_var_name):
    # Get frame to iterate over stack variables.
    # https://reverseengineering.stackexchange.com/questions/30622/renaming-a-local-stack-variable-with-idapython
    func = idaapi.get_func(func_addr)
    frame = idaapi.get_frame(func)
    # this naively assumes a max stack variable size of 1024 bytes, this could be "smarter" by checking each
    # var's size and jumping to the end of it.
    for i in range(0, len(list(frame.members)) * 1024):
        name = idc.get_member_name(frame.id, i)
        if var_name == name:
            print(name)
            print(idc.set_member_name(frame.id, i, new_var_name))
            break
    return None

def chat(s):
    # sends a chat request to GPT via https://github.com/taranjeet/chatgpt-api
    return requests.get('http://localhost:5001/chat', params={'q':s}).content.decode()

def get_disasm(addr):
     # get the instructions of the function
    instructions = list(FuncItems(addr))

    # print the instructions
    return '\n'.join([ idc.GetDisasm(instruction) for instruction in instructions])

def get_description(addr):
    # format the query with the appropriate disassembly
    disasm = get_disasm(addr)

    query = '''Write a summary of the following disassembly.
Reference notable constants used.
Provide a description of what it could be used for, or a name for the function if it is familiar to any know purpose.
Please write this succinctly and in present tense.
Do not say anything you are unsure of.
Start the response with "The function" and respond in less than 200 words.
Disassembly:
{0}'''.format(disasm)

    # write the response as a comment
    response = chat(query)
    idc.set_func_cmt(addr, wordwrap(response), 1)
    return wordwrap(response)

def rename_vars(addr, response):

    # search for local variable to rename
    pattern = '(var_\d+?):(.+?)(?:\s|$)'
    matches = re.findall(pattern, response)
    print(matches)

    # rename the variables
    for m in matches:
        rename_stack_variable(addr, m[0], m[1])

def rename_locs(addr,response):

    # search for locations to rename
    pattern1 = 'loc_([0-9A-F]+?):(.+?)(?:\s|$)'
    pattern2 = 'func_(.+)(?:\s|$)'
    matches = re.findall(pattern1, response)
    print(matches)

    for m in matches:
        idc.set_name(int(m[0], 16),m[1])

    match = re.search(pattern2, response)
    if match:
        idc.set_name(addr, match.group(1))


def refactor(addr):
    # format the query with the appropriate disassembly
    disasm = get_disasm(addr)

    query ='''Analyze the following disassembly.
For any variable name you identify starting with "var", "loc", "arg" or "sub", please suggest a more helpful name in a list format.
The format of the list should be in the format "old_variable_name:new_variable_name", with each list entry on a new line.
Do not print anything besides the list and a suggested name for the function, starting with "func_", which should be at the end.
Disassembly:
{0}'''.format(disasm)

    response = chat(query)
    rename_vars(addr, response)
    rename_locs(addr,response)

    # refresh the view to display the new variables
    idaapi.refresh_idaview_anyway()
    return response
