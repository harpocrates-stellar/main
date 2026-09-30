import os
import glob
import re

for root, _, files in os.walk('zk/noir'):
    for file in files:
        if file.endswith('.nr'):
            filepath = os.path.join(root, file)
            with open(filepath, 'r') as f:
                content = f.read()

            content = content.replace('\"credential root mismatch\"', '\"malformed\"')
            content = content.replace('\"nullifier mismatch\"', '\"malformed\"')
            content = content.replace('\"revocation root mismatch\"', '\"malformed\"')
            content = re.sub(r'\"credential is in revocation set \(leaf \d+\)\"', '\"revoked\"', content)
            content = content.replace('\"domain tag mismatch\"', '\"unsupported\"')
            
            # selective disclosure
            content = content.replace('\"unknown predicate type\"', '\"unsupported\"')
            content = content.replace('\"equality predicate failed\"', '\"malformed\"')
            content = content.replace('\"set membership predicate failed\"', '\"malformed\"')
            content = content.replace('\"range predicate: below lower bound\"', '\"malformed\"')
            content = content.replace('\"range predicate: above upper bound\"', '\"malformed\"')
            content = content.replace('\"at least one attribute required\"', '\"malformed\"')
            content = content.replace('\"too many attributes\"', '\"oversized\"')
            content = content.replace('\"too many predicates\"', '\"oversized\"')
            content = content.replace('\"predicate attribute index out of range\"', '\"malformed\"')
            content = content.replace('\"set membership predicate requires non-empty set\"', '\"malformed\"')
            content = content.replace('\"set membership predicate: too many set values\"', '\"oversized\"')
            content = content.replace('\"verifier digest must be non-zero\"', '\"malformed\"')

            with open(filepath, 'w') as f:
                f.write(content)
