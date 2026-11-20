# Tests

Run the suite from the repository root:

```bash
python3 -m pytest tests -q
TELBER_FULL_SCALE=1 python3 -m pytest tests/test_scale.py -q
```

Modules:

| file | focus |
| --- | --- |
| `conftest.py` | fixtures: strict schema builder, small products |
| `test_ber_wire.py` | tag/length encoding, minimality, indefinite rules |
| `test_schema.py` | directory strictness, ambiguity, depth/field limits, revisions |
| `test_codec.py` | decoding against independently built bytes and provenance |
| `test_nesting.py` | all definite/indefinite nestings, depth 32 |
| `test_stream.py` | block-size invariance, truncation, bounded memory, no resync |
| `test_repository.py` | product binding, relation rows, partial imports |
| `test_service.py` | artifact recompilation, presence/type preservation |
| `test_demo_truth.py` | demo relation table against independent truth |
| `test_scale.py` | 100 MiB / 1 MiB records / 2 MiB body cap (opt-in) |
