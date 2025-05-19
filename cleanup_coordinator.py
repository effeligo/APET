class CleanupCoordinator:
    def __init__(self, selection):
        self.selection = selection
        self.instances = []

    def get_sel(self):
        return self.selection

    def set_sel(self, selection):
        self.selection = selection

    def register(self, instance, priority):
        self.instances.append((instance, priority))

    def cleanup_all(self):
        self.selection = True
        self.instances = sorted(self.instances, key=lambda x:x[1])
        for el in self.instances:
            el[0].cleanup()
