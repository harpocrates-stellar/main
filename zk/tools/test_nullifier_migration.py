import unittest
from nullifier_migration import compute_scoped_nullifier_old, compute_scoped_nullifier_new

class TestNullifierMigration(unittest.TestCase):
    def test_migration_properties(self):
        cs = 12345
        ns = 67890
        vhi = 22685491128062564230891640495451214097
        vlo = 45370982256125128461783280990902428194
        scope = 0
        ep = 0
        
        old_val = compute_scoped_nullifier_old(cs, ns, vhi, vlo, scope, ep)
        new_val = compute_scoped_nullifier_new(cs, ns, vhi, vlo, scope, ep)
        
        self.assertNotEqual(old_val, new_val, "Old and new policies should be distinct")

if __name__ == '__main__':
    unittest.main()
