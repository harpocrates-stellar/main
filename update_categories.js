const fs = require('fs');
const path = require('path');

function walk(dir) {
    let results = [];
    const list = fs.readdirSync(dir);
    list.forEach(function(file) {
        file = path.resolve(dir, file);
        const stat = fs.statSync(file);
        if (stat && stat.isDirectory()) { 
            results = results.concat(walk(file));
        } else { 
            if(file.endsWith('.nr')) results.push(file);
        }
    });
    return results;
}

const files = walk('zk/noir');
for(const file of files) {
    let content = fs.readFileSync(file, 'utf8');
    
    content = content.replace(/"credential root mismatch"/g, '"malformed"');
    content = content.replace(/"nullifier mismatch"/g, '"malformed"');
    content = content.replace(/"revocation root mismatch"/g, '"malformed"');
    content = content.replace(/"credential is in revocation set \(leaf \d+\)"/g, '"revoked"');
    content = content.replace(/"domain tag mismatch"/g, '"unsupported"');
    
    content = content.replace(/"unknown predicate type"/g, '"unsupported"');
    content = content.replace(/"equality predicate failed"/g, '"malformed"');
    content = content.replace(/"set membership predicate failed"/g, '"malformed"');
    content = content.replace(/"range predicate: below lower bound"/g, '"malformed"');
    content = content.replace(/"range predicate: above upper bound"/g, '"malformed"');
    content = content.replace(/"at least one attribute required"/g, '"malformed"');
    content = content.replace(/"too many attributes"/g, '"oversized"');
    content = content.replace(/"too many predicates"/g, '"oversized"');
    content = content.replace(/"predicate attribute index out of range"/g, '"malformed"');
    content = content.replace(/"set membership predicate requires non-empty set"/g, '"malformed"');
    content = content.replace(/"set membership predicate: too many set values"/g, '"oversized"');
    content = content.replace(/"verifier digest must be non-zero"/g, '"malformed"');
    content = content.replace(/"root \d+ mismatch"/g, '"malformed"');
    content = content.replace(/"nullifier \d+ mismatch"/g, '"malformed"');

    fs.writeFileSync(file, content);
}
