class TemporalFusion:
    def __init__(self, window=10):
        self.window = window
        self.buffer = []
    def update(self, features):
        self.buffer.append(features)
        if len(self.buffer) > self.window:
            self.buffer.pop(0)
    def fuse(self):
        return np.mean(self.buffer, axis=0) if self.buffer else None
