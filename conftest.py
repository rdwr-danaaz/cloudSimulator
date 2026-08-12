"""Pytest bootstrap.

Placing a ``conftest.py`` at the repository root makes pytest insert this
directory into ``sys.path`` during collection. Without it, the bare
``pytest tests/test_ci.py`` invocation used in CI cannot import the top-level
application modules (``cloud_mock_server``, ``permanent_responses``,
``response_template``) and fails collection with ``ModuleNotFoundError`` /
exit code 2 — even though ``python -m pytest`` works locally (that form adds
the current directory to ``sys.path`` automatically).

Keep this file at the repo root so tests import the app the same way whether
they are run via ``pytest`` or ``python -m pytest``.
"""

