# ida_tool
ancestor_re.py 
copy from auto_re.py and add functions:
1) shift+N rename this function and its parents. naming by : replace the sub_xxxx to new_function_name_xxx, keep the address, and replace all the caller prefix
  to new_function_name_p1_xxxx if the original function name is sub_, if repname success, repeat on its caller to new_function_name_p2_xxx. until reach the end.
  purpose of this function is to know from the very far parent whats the function inside from the very beginning.
  
