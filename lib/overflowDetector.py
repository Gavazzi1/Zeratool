from __future__ import print_function
import angr
import claripy
import timeout_decorator

from lib.hookFour import hookFour


def overflow_filter(simgr):
    for state in simgr.unconstrained:
        inputType = state.globals['inputType']

        # Check satisfiability
        if state.solver.symbolic(state.regs.pc):  # basically the same as checking for all bytes == 0x41
            if inputType == "LIBPWNABLE":
                print("[+] Vulnerable path found from stdin: {}".format(state.posix.dumps(0)))
            elif inputType in ['STDIN', 'FILE', 'SOCKET']:
                print("[+] Vulnerable path found from one of many possible sources:")
                if state.posix.dumps(0):
                    print("        stdin: {}".format(state.posix.dumps(0)))

                fds = list(state.posix.fd)

                # ignore fd 0, 1, and 2 as they are stdin, stdout, and stderr
                for i in range(3):
                    fds.remove(i)

                for fd in fds:
                    if state.posix.dumps(fd):
                        print("        file descriptor {}: {}".format(fd, state.posix.dumps(fd)))

                # TODO check socket dumps
            elif inputType == 'ARG':
                arg = state.globals['arg']
                constraintstr = state.solver.eval(arg, cast_to=bytes)
                print("[+] Vulnerable path found from argv: {}".format(constraintstr))
            else:
                print("[-] Unsupported input type")
                return simgr

            state.globals['type'] = "Overflow"
            simgr.stashes['found'].append(state)
            simgr.stashes['unconstrained'].remove(state)
    return simgr


def checkOverflow(binary_name, inputType="STDIN"):
    p = angr.Project(binary_name, auto_load_libs=False)

    # Hook rands for performance (?)
    p.hook_symbol('rand', hookFour)
    p.hook_symbol('srand', hookFour)

    # Setup state based on input type
    argv = [binary_name]
    if inputType in ["STDIN", "FILE", "SOCKET"]:
        state = p.factory.full_init_state(args=argv)
    elif inputType == "LIBPWNABLE":
        handle_connection = p.loader.main_object.get_symbol('handle_connection')
        state = p.factory.entry_state(addr=handle_connection.rebased_addr)
    elif inputType == "ARG":
        arg = claripy.BVS("arg1", 256 * 8)
        argv.append(arg)
        state = p.factory.full_init_state(args=argv)
        state.globals['arg'] = arg
    else:
        print("[x] Unsupported inputType:", inputType)
        exit(1)
        return  # for IDE

    # setting max packet size may be essential for detecting vulnerabilities, but as it increases, performance tanks
    state.libc.max_packet_size = 256  # must be increased to allow exploits requiring large reads
    state.globals['inputType'] = inputType
    simgr = p.factory.simgr(state, save_unconstrained=True)

    run_environ = dict()
    run_environ['type'] = None
    end_state = None

    # Lame way to do a timeout
    try:
        @timeout_decorator.timeout(300)
        def exploreBinary(simgr):
            simgr.explore(find=lambda s: 'type' in s.globals, step_func=overflow_filter)

        exploreBinary(simgr)
        if 'found' in simgr.stashes and len(simgr.found):
            end_state = simgr.found[0]
            run_environ['type'] = end_state.globals['type']
    except KeyboardInterrupt:
        print("[~] Keyboard Interrupt")
    except timeout_decorator.TimeoutError:
        print("[~] Timeout")

    if end_state is None:
        print("[-] Could not find an unconstrained end state")
    elif inputType in ["STDIN", "LIBPWNABLE"]:
        stdin_str = end_state.posix.dumps(0)
        run_environ['input'] = stdin_str
    elif inputType in ['FILE', 'SOCKET']:
        # TODO search through fds to find some data
        file_str = b''  # this is never actually used by the program. keeping it around just in case
        run_environ['input'] = file_str
    elif inputType == 'ARG':
        arg_str = end_state.solver.eval(arg, cast_to=bytes)
        run_environ['input'] = arg_str
    else:
        # duplicate check so that i don't forget
        print("[x] Unsupported inputType:", inputType)
        exit(1)

    return run_environ
