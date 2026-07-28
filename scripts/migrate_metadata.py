import argparse
import json
import sys
from pathlib import Path

# Add backend to path so we can import envelope
sys.path.append(str(Path(__file__).parent.parent / "backend"))

try:
    from envelope import canonical_encode, validate, SchemaValidationError
except ImportError as e:
    print(f"Error importing envelope: {e}", file=sys.stderr)
    sys.exit(1)

def migrate(input_path: Path, output_path: Path):
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            metadata = json.load(f)
    except Exception as e:
        print(f"Failed to read input file: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Ensure it meets V1 requirements
    if "version" not in metadata:
        metadata["version"] = 1
    
    try:
        encoded = canonical_encode(metadata)
    except SchemaValidationError as e:
        print(f"Validation failed: {e}", file=sys.stderr)
        sys.exit(1)
        
    try:
        with open(output_path, 'wb') as f:
            f.write(encoded)
        print(f"Successfully migrated {input_path} -> {output_path}")
    except Exception as e:
        print(f"Failed to write output file: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Migrate legacy metadata to canonically encoded format.")
    parser.add_argument("input", type=Path, help="Path to input legacy JSON metadata file.")
    parser.add_argument("output", type=Path, help="Path to output canonically encoded binary file.")
    
    args = parser.parse_args()
    migrate(args.input, args.output)

if __name__ == "__main__":
    main()
