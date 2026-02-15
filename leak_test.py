
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
    # Direct WASM Client Test
    try:
        from src.adapters.pii_wasm_client import PIIWasmClient
    except ImportError:
         # Fallback for when running from different CWD
        from adapters.pii_wasm_client import PIIWasmClient

    client = PIIWasmClient()
    
    # Test Data
    secret = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" 
    print(f"Input: {secret}")

    try:
        sanitized = client.redact(secret)
        print(f"Output: {sanitized}")
        
        if "[HIDDEN" in sanitized:
            print("SUCCESS: Secret was redacted.")
            sys.exit(0)
        else:
            print("FAILURE: Secret was NOT redacted.")
            sys.exit(1)
            
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(2)

if __name__ == "__main__":
    main()
