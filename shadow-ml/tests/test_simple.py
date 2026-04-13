"""
Simple tests for Shadow NDR ML
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_imports():
    print("Testing imports...")
    try:
        from app.fusion.multimodal_fusion import MultimodalFusionEngine
        print("✅ Fusion imported")
    except Exception as e:
        print(f"❌ Fusion failed: {e}")
    
    try:
        from app.rl_agent.defense_agent import PPODefenseAgent
        print("✅ RL Agent imported")
    except Exception as e:
        print(f"❌ RL Agent failed: {e}")
    
    try:
        from app.streaming.streaming_engine import StreamingMLEngine
        print("✅ Streaming imported")
    except Exception as e:
        print(f"❌ Streaming failed: {e}")

if __name__ == "__main__":
    test_imports()
    print("\n🎉 Tests ready!")