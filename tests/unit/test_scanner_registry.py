from ps4debug.memory.scanner import compare_function


def test_fuzzy_boundary():
    assert compare_function["fuzzy"](current=1.000001, value=1.0)
    assert not compare_function["fuzzy"](current=1.1, value=1.0)


def test_between_exclusive():
    fn = compare_function["between"]
    assert fn(current=5, value=1, extra=10)
    assert not fn(current=1, value=1, extra=10)
    assert not fn(current=10, value=1, extra=10)


def test_previous_none_cases():
    fn = compare_function["increased"]
    assert not fn(current=10, previous=None)


def test_exact():
    fn = compare_function["exact"]
    assert fn(current=5, value=5)
    assert not fn(current=5, value=4)


def test_bigger_smaller():
    bigger = compare_function["bigger_than"]
    smaller = compare_function["smaller_than"]

    assert bigger(current=10, value=5)
    assert not bigger(current=5, value=5)

    assert smaller(current=3, value=5)
    assert not smaller(current=5, value=5)


def test_increased_decreased():
    inc = compare_function["increased"]
    dec = compare_function["decreased"]

    assert inc(current=10, previous=5)
    assert not inc(current=5, previous=5)

    assert dec(current=5, previous=10)
    assert not dec(current=10, previous=10)


def test_increased_by_decreased_by():
    inc_by = compare_function["increased_by"]
    dec_by = compare_function["decreased_by"]

    assert inc_by(current=10, previous=5, value=5)
    assert not inc_by(current=10, previous=5, value=4)

    assert dec_by(current=5, previous=10, value=5)
    assert not dec_by(current=5, previous=10, value=4)


def test_changed_unchanged():
    changed = compare_function["changed"]
    unchanged = compare_function["unchanged"]

    assert changed(current=10, previous=5)
    assert not changed(current=5, previous=5)

    assert unchanged(current=5, previous=5)
    assert not unchanged(current=10, previous=5)


def test_unknown_initial():
    fn = compare_function["unknown_initial"]
    assert fn(current=1, value=2, previous=3, initial=4, extra=5)


def test_registry_contains_all():
    expected = {
        "exact", "fuzzy", "bigger_than", "smaller_than",
        "between", "increased", "increased_by",
        "decreased", "decreased_by",
        "changed", "unchanged", "unknown_initial"
    }
    assert expected.issubset(set(compare_function.keys()))
