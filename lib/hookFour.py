import angr


# hookable function that returns 4 for any random function call
# presumably this is used for performance reasons when symbolically executing, but maybe it's just a meme?
class hookFour(angr.SimProcedure):
    IS_FUNCTION = True

    def run(self):
        return 4  # Fair dice roll