from queue import Queue
from angr.project import Project


def maxbuf(p: Project) -> int:
    """
    Estimates the largest buffer allocated in the given angr project

    For all instructions like "sub %esp, <VAL>", returns the biggest <VAL> in the program

    Only tested for x86, but presumably the logic would be easy to factor out for other architectures
    """
    maxsz = 0
    cfg = p.analyses.CFGFast()
    seen = set()
    q = Queue()
    for node in cfg.model.get_all_nodes(p.entry):
        q.put(node)

    while not q.empty():
        node = q.get()
        seen.add(node)  # avoid loops
        if node.block is not None:
            for instr in node.block.capstone.insns:
                instr_str = str(instr)
                if 'sub\tesp' in instr_str:
                    idx = instr_str.index(', ')
                    offset = int(instr_str[idx + 2:], base=16)  # gets the amount esp is offset by
                    maxsz = max(offset, maxsz)

        for succ in node.successors:
            if succ not in seen:
                q.put(succ)

    return maxsz
