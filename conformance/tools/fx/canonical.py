from .common import Area, sha256_hex

# Canonical JSON, `hpx-cj/1` (matches the recursive `canonicalize()` in the
# signed-receipt code, the only recursive canonicalizer in the repo):
#   * UTF-8, no insignificant whitespace, object keys sorted recursively by
#     UTF-16 code-unit order (JavaScript's default), arrays keep their order
#   * strings escaped like JSON.stringify: \" \\ \b \f \n \r \t, other control
#     characters as lowercase \u00xx, everything else (incl. U+2028/9) literal
#   * integers only, |n| <= 2^53-1
# Expected strings below are literals written by hand, never computed by an
# adapter, so the fixture is an independent oracle.


def build() -> Area:
    a = Area("canonical-json", "Canonical JSON (hpx-cj/1) byte-exactness")

    def pos(n, slug, text, canonical, desc):
        a.add(f"cj-pos-{n:03d}-{slug}", "canonicalize", {"json_text": text},
              ok={"canonical": canonical, "sha256": sha256_hex(canonical)}, desc=desc)

    pos(1, "flat-sorted", '{"b":1,"a":2}', '{"a":2,"b":1}', "Keys are sorted.")
    pos(2, "nested-sorted", '{"z":{"y":1,"x":{"d":1,"c":2}},"a":[{"q":1,"p":2}]}',
        '{"a":[{"p":2,"q":1}],"z":{"x":{"c":2,"d":1},"y":1}}',
        "Sorting is recursive, including objects inside arrays.")
    pos(3, "array-order-kept", '[3,1,2,{"b":1,"a":2}]', '[3,1,2,{"a":2,"b":1}]',
        "Array element order is significant and preserved.")
    pos(4, "input-whitespace", ' {\n "b" : [ 1 , 2 ],\t"a" : null } ', '{"a":null,"b":[1,2]}',
        "Insignificant input whitespace never reaches the output.")
    pos(5, "utf8-literal", '{"k":"caf\\u00e9"}', '{"k":"caf\u00e9"}',
        "Non-ASCII is emitted literally, not as \\uXXXX (ensure_ascii=False).")
    pos(6, "astral-literal", '{"k":"\\ud83d\\ude00"}', '{"k":"\U0001F600"}',
        "Surrogate-pair escapes decode to one literal astral character.")
    pos(7, "key-order-utf16", '{"\\uff5e":1,"\\ud83d\\ude00":2}',
        '{"\U0001F600":2,"\uff5e":1}',
        "Keys sort by UTF-16 code units: U+1F600 (D83D..) sorts before U+FF5E. "
        "Code-point order (the Python default) puts them the other way round.")
    pos(8, "control-escapes", '{"k":"a\\u001fb\\nc\\u0000d\\u007f"}',
        '{"k":"a\\u001fb\\nc\\u0000d\x7f"}',
        "Control chars use short escapes or lowercase \\u00xx; DEL is literal.")
    pos(9, "solidus-literal", '{"k":"a\\/b"}', '{"k":"a/b"}', "Solidus is never escaped.")
    pos(10, "line-separators", '{"k":"\\u2028\\u2029"}', '{"k":"\u2028\u2029"}',
        "U+2028/U+2029 stay literal (JSON.stringify does not escape them).")
    pos(11, "negative-and-zero", '{"a":-5,"b":0,"c":-0}', '{"a":-5,"b":0,"c":0}',
        "Negative zero canonicalizes to 0.")
    pos(12, "literals", '{"t":true,"f":false,"n":null}', '{"f":false,"n":null,"t":true}',
        "true/false/null pass through.")
    pos(13, "empty-containers", '{"o":{},"a":[]}', '{"a":[],"o":{}}', "Empty containers.")
    pos(14, "max-safe-int", '[9007199254740991,-9007199254740991]',
        '[9007199254740991,-9007199254740991]', "Largest exactly-representable integers.")
    pos(15, "escaped-key", '{"\\u0062":1,"a":2}', '{"a":2,"b":1}', "Keys are unescaped before sorting.")
    pos(16, "combining-not-normalized", '{"k":"e\\u0301"}', '{"k":"e\u0301"}',
        "No Unicode normalization: e + U+0301 stays two code points.")

    def neg(n, slug, text, code, desc, tier="required", why=None):
        a.add(f"cj-neg-{n:03d}-{slug}", "canonicalize", {"json_text": text},
              code=code, desc=desc, tier=tier, why=why)

    neg(20, "trailing-comma", '{"a":1,}', "invalid_json", "Trailing comma.")
    neg(21, "empty-text", "", "invalid_json", "Empty input.")
    neg(22, "trailing-garbage", '{"a":1} x', "invalid_json", "Trailing bytes after the value.")
    neg(23, "nan-literal", '{"a":NaN}', "invalid_json", "NaN is not JSON.")
    neg(24, "bom-prefix", '\ufeff{"a":1}', "invalid_json", "A byte-order mark is not JSON whitespace.")
    neg(25, "single-quotes", "{'a':1}", "invalid_json", "Single-quoted strings.")
    neg(26, "unquoted-key", "{a:1}", "invalid_json", "Unquoted key.")
    neg(27, "leading-zero", '{"a":01}', "invalid_json", "Leading zero.")
    neg(28, "raw-control-in-string", '{"a":"x\ty"}', "invalid_json", "Raw TAB inside a string.")
    # Advisory: not pinned by deployed behavior, but each is a real cross-language trap.
    neg(30, "float-integral", '{"a":1.0}', "unsupported_number",
        "1.0 prints as 1 in JS and 1.0 in Python; forbid non-integers.", "advisory", "proposed_hardening")
    neg(31, "exponent", '{"a":1e2}', "unsupported_number",
        "Exponent form is engine-dependent.", "advisory", "proposed_hardening")
    neg(32, "beyond-safe-int", '{"a":9007199254740992}', "unsupported_number",
        "JS rounds beyond 2^53-1 silently; Python keeps the exact value.", "advisory", "proposed_hardening")
    neg(33, "duplicate-keys", '{"a":1,"a":2}', "duplicate_key",
        "JS and Python keep the last value, Rust serde rejects; ambiguity must be an error.",
        "advisory", "proposed_hardening")
    neg(34, "lone-surrogate", '{"a":"\\ud800"}', "invalid_unicode",
        "A lone surrogate has no UTF-8 encoding; Python raises on encode, JS emits \\ud800.",
        "advisory", "proposed_hardening")
    neg(35, "nesting-too-deep", "[" * 65 + "]" * 65, "nesting_too_deep",
        "Bounded resource use: depth > 64 is rejected.", "advisory", "proposed_hardening")
    return a
