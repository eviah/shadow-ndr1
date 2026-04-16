class AttentionFusion:
    def fuse(self, features_list):
        return features_list[0] if features_list else None
