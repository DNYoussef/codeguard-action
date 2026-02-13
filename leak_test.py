
import sys
import os
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent / "src"))

try:
    import wasmtime
    print(f"wasmtime found at {wasmtime.__file__}")
except ImportError:
    print("ERROR: wasmtime not found!")
    print(f"sys.path: {sys.path}")

from pii_shield import PIIShieldClient

def main():
    print("Running PII-Shield WASM Leak Test...")
    
    # Setup
    client = PIIShieldClient(
        enabled=True,
        endpoint="http://ignored.local",
        api_key="ignored",
        mode="auto" # triggers remote path if endpoint set
    )
    
    # Test Data
    # A high entropy secret
    secret = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" 
    # High entropy string that looks like a key
    
    print(f"Input: {secret}")
    
    try:
        # We force "remote" mode if that's what triggers _sanitize_remote
        # OR we just call the method directly if we can't control it easily via public API
        
        # client.mode = "remote" # auto + endpoint does it
        
        result = client.sanitize_text(
            text=secret,
            input_format="text",
            purpose="leak_test"
        )
        
        print(f"Output: {result.sanitized_text}")
        
        if "[HIDDEN" in result.sanitized_text:
            print("SUCCESS: Secret was redacted.")
            sys.exit(0)
        else:
            print("FAILURE: Secret was NOT redacted.")
            print(f"Details: {result}")
            sys.exit(1)
            
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(2)

if __name__ == "__main__":
    main()
