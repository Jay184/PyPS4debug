from invoke import task
import shutil
import os


@task
def test(c):
    """Run all tests."""
    c.run("pytest -v")


@task
def test_cov(c):
    """Run tests with coverage report."""
    c.run("coverage run -m pytest")
    c.run("coverage report -m")
    c.run("coverage html")


@task
def lint(c, fix: bool = False):
    """Run ruff linting."""
    c.run("ruff check --fix" if fix else "ruff check")


@task
def type_check(c):
    """Run mypy type checks."""
    c.run("mypy src")


@task(pre=[lint, type_check, test_cov])
def dev(c):
    """Run all dev checks."""
    print("All checks completed.")


@task
def build(c):
    """Build the Python package (sdist + wheel)."""
    c.run("uv build")


@task
def publish(c, repository="pypi"):
    """
    Publish the package to a repository.
    :param repository: Default is 'pypi', could be 'testpypi' for testing.
    """
    c.run(f"uv publish --repository {repository}")


@task
def bump(c, part="patch"):
    """
    Bump the project version.
    :param part: 'major', 'minor', or 'patch'
    """
    c.run(f"uv version --bump={part}")


@task
def clean(c):
    """Remove build artifacts."""
    for folder in ["dist", "build", "*.egg-info"]:
        if os.path.exists(folder):
            shutil.rmtree(folder, ignore_errors=True)
    print("Cleaned build artifacts.")


@task(pre=[clean, build, publish])
def release(c, repository="pypi"):
    """Clean, build, and publish the package in one step."""
    print(f"Released package to {repository}.")
