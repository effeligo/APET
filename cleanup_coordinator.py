class CleanupCoordinator:
    def __init__(self):
        self.instances = []

    def register(self, instance, priority):
        self.instances.append((instance, priority))

    def cleanup_all(self):
        self.instances = sorted(self.instances, key=lambda x:x[1])
        for el in self.instances:
            el[0].cleanup()
