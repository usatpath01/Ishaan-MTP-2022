class PassByReference:
    def __init__(self):
        self.variable = 'Original'
        self.change(self.variable)
        print(self.variable)

    def change(self, var):
        var = 'Changed'

o = PassByReference()