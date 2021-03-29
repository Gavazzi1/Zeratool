from __future__ import print_function
import angr
import claripy
import timeout_decorator

from lib.hookFour import hookFour


def overflow_filter(simgr):
    for path in simgr.unconstrained:
        state = path.state

        eip = state.regs.pc
        bits = state.arch.bits
        state_copy = state.copy()

        # Constrain pc to 0x41414141 or 0x41414141414141
        constraints = []
        for i in range(int(bits / 8)):
            curr_byte = eip.get_byte(i)
            constraint = claripy.And(curr_byte == 0x41)
            constraints.append(constraint)

        # Check satisfiability
        if state_copy.se.satisfiable(extra_constraints=constraints):
            for constraint in constraints:
                state_copy.add_constraints(constraint)

            constraintstr = ''
            if state_copy.globals['inputType'] in ["STDIN", "LIBPWNABLE"]:
                constraintstr = state_copy.posix.dumps(0).replace('\x00', '').replace('\x01', '')
            elif state_copy.globals['inputType'] == "ARG":
                arg = state.globals['arg']
                constraintstr = str(state_copy.solver.eval(arg, cast_to=str)).replace('\x00', '').replace('\x01', '')

            if 'A' in constraintstr:
                inputlen = 0
                inputsrc = None
                if state_copy.globals['inputType'] in ["STDIN", "LIBPWNABLE"]:
                    stdin = state.posix.files[0]
                    stdin_size = 300
                    stdin.length = stdin_size
                    stdin.seek(0)
                    inputlen = stdin_size
                    inputsrc = stdin
                elif state_copy.globals['inputType'] == "ARG":
                    inputlen = arg.length
                    inputsrc = arg

                for i in range(inputlen):
                    curr_byte = inputsrc.read_from(1)
                    constraint = claripy.And(curr_byte > 0x2F, curr_byte < 0x7F)
                    if state.se.satisfiable(extra_constraints=[constraint]):
                        constraints.append(constraint)

                if state.se.satisfiable(extra_constraints=constraints):
                    for constraint in constraints:
                        state.add_constraints(constraint)

                if state_copy.globals['inputType'] in ["STDIN", "LIBPWNABLE"]:
                    constraintstr = repr(str(state.posix.dumps(0).replace('\x00', '').replace('\x01', '')))
                elif state_copy.globals['inputType'] == "ARG":
                    constraintstr = repr(str(state.solver.eval(arg, cast_to=str)).replace('\x00', '').replace('\x01', ''))

                print("[+] Vulnerable path found {}".format(constraintstr))
                state.globals['type'] = "Overflow"
                simgr.stashes['found'].append(path)
                simgr.stashes['unconstrained'].remove(path)
    return simgr


def checkOverflow(binary_name, inputType="STDIN"):
    p = angr.Project(binary_name, load_options={"auto_load_libs": False})

    # Hook rands
    p.hook_symbol('rand', hookFour)
    p.hook_symbol('srand', hookFour)

    # Setup state based on input type
    argv = [binary_name]
    if inputType == "STDIN":
        state = p.factory.full_init_state(args=argv)
    elif inputType == "LIBPWNABLE":
        handle_connection = p.loader.main_object.get_symbol('handle_connection')
        state = p.factory.entry_state(addr=handle_connection.rebased_addr)
    elif inputType == "ARG":
        arg = claripy.BVS("arg1", 300 * 8)
        argv.append(arg)
        state = p.factory.full_init_state(args=argv)
        state.globals['arg'] = arg
    else:
        print("[x] Unsupported inputType:", inputType)
        exit(1)
        return  # for IDE

    state.libc.max_packet_size = 8192  # approx twice a page size. assume nobody is gonna allocate a bigger buffer
    state.globals['inputType'] = inputType
    simgr = p.factory.simgr(state, immutable=False, save_unconstrained=True)

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
    elif inputType == "STDIN" or inputType == "LIBPWNABLE":
        stdin_str = repr(str(end_state.posix.dumps(0).replace('\x00', '').replace('\x01', '')))
        run_environ['input'] = stdin_str
        print("[+] Triggerable with STDIN : {}".format(stdin_str))
    elif inputType == "ARG":
        arg_str = repr(str(end_state.solver.eval(arg, cast_to=str)).replace('\x00', '').replace('\x01', ''))
        run_environ['input'] = arg_str
        print("[+] Triggerable with arg : {}".format(arg_str))

    return run_environ
