import angr


def checkInputType(binary_name):
    # Check for libpwnableharness
    p = angr.Project(binary_name)
    if any(['libpwnable' in str(x.binary) for x in p.loader.all_elf_objects]):
        return "LIBPWNABLE"

    p = angr.Project(binary_name, load_options={"auto_load_libs": False})

    # Functions which MIGHT grab from STDIN
    reading_functions = ['fgets', 'gets', 'scanf']
    socket_functions = ['socket', 'bind', 'listen']
    file_functions = ['fopen', 'fread', 'fscanf']
    binary_functions = p.loader.main_object.imports.keys()

    # Match reading functions against local functions
    for x in binary_functions:
        if x == 'read':
            if any([b in socket_functions for b in binary_functions]):
                return 'SOCKET'
            else:
                return 'STDIN'
        elif x in file_functions:
            return 'FILE'
        elif x in reading_functions:
            return 'STDIN'
    return 'ARG'

    # TODO remove this
    #if any([x in reading_functions for x in binary_functions]):
    #    return "STDIN"
    #return "ARG"
