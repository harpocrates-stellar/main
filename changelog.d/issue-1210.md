### Added

- Bound selective-disclosure predicate (`MAX_PREDICATES = 8`), set-member (`MAX_SET_MEMBERS = 8`), and attribute (`MAX_ATTRIBUTES = 16`) list sizes before padded witness allocation and proving in `zk/tools/disclosure_witness.py` and `frontend/src/selectiveDisclosure.ts`, preserving supported predicate order and encoding (#1210).
