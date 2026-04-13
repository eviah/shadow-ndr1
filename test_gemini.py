# test_gemini.py
from google import genai
import json

API_KEY = "AIzaSyBsX8C3k0wUDy56nL3RrdVvm7HSNvCRydQ"

print("🔑 Initializing Gemini client...")
client = genai.Client(api_key=API_KEY)

print("\n📡 Testing models...")

# בדיקת מודל 2.5-flash
print("\n1. Testing gemini-2.5-flash:")
try:
    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents="Say 'Hello from Shadow NDR' in Hebrew"
    )
    print(f"   ✅ Success!")
    print(f"   Response: {response.text}")
except Exception as e:
    print(f"   ❌ Failed: {e}")

# בדיקת מודל 2.5-pro
print("\n2. Testing gemini-2.5-pro:")
try:
    response = client.models.generate_content(
        model="gemini-2.5-pro",
        contents="What is aviation security? Answer in one sentence."
    )
    print(f"   ✅ Success!")
    print(f"   Response: {response.text}")
except Exception as e:
    print(f"   ❌ Failed: {e}")

# בדיקת ניתוח התראה (היי-טק!)
print("\n3. Testing security alert analysis:")
test_alerts = [
    {
        "type": "ADS_B_SPOOFING",
        "icao24": "4CA123",
        "confidence": 0.95,
        "timestamp": "2026-03-27T12:00:00Z"
    }
]

prompt = f"""
Analyze this aviation security alert and return JSON:

Alerts: {json.dumps(test_alerts, indent=2)}

Return ONLY JSON with:
- severity (critical/high/medium/low)
- summary (short description)
- recommendation (one action)
"""

try:
    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt,
        config={"temperature": 0.1}
    )
    print(f"   ✅ Success!")
    print(f"   Response: {response.text}")
except Exception as e:
    print(f"   ❌ Failed: {e}")

print("\n✅ Test complete!")