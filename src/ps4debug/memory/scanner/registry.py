from typing import Any

from autoregistry import Registry


compare_function = Registry()

# compare(*, current: Any, value: Any, previous: Any, initial: Any, extra: Any) -> bool


@compare_function
def exact(*, current: Any, value: Any, **_) -> bool:
    return current == value


@compare_function
def fuzzy(*, current: Any, value: Any, **_) -> bool:
    epsilon = 1e-5
    return abs(current - value) <= epsilon


@compare_function
def bigger_than(*, current: Any, value: Any, **_) -> bool:
    return current > value


@compare_function
def smaller_than(*, current: Any, value: Any, **_) -> bool:
    return current < value


@compare_function
def between(*, current: Any, value: Any, extra: Any, **_) -> bool:
    return value < current < extra


@compare_function
def increased(*, current: Any, previous: Any, **_):
    return previous is not None and current > previous


@compare_function
def increased_by(*, current, previous, value, **_):
    return previous is not None and (current - previous) == value


@compare_function
def decreased(*, current: Any, previous: Any, **_):
    return previous is not None and current < previous


@compare_function
def decreased_by(*, current, previous, value, **_):
    return previous is not None and (previous - current) == value


@compare_function
def changed(*, current, previous, **_):
    return previous is not None and current != previous


@compare_function
def unchanged(*, current, previous, **_):
    return previous is not None and current == previous


@compare_function
def unknown_initial(**_):
    return True
