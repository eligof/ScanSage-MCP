"""Unit tests for preflight recommendation planning."""

from preflight import Capabilities, PreflightContext, plan_recommendation


def test_system_python_recommends_creating_venv() -> None:
    """A system interpreter should tell us to bootstrap .venv before rerunning."""

    context = PreflightContext(context="system", in_venv=False, venv_exists=False)
    capabilities = Capabilities(False, False, False, False, False, False, "")
    recommendation = plan_recommendation("any", context, capabilities)
    assert recommendation.path is None
    assert (
        recommendation.next_step
        == "python -m venv .venv && .venv/bin/python preflight.py --mode any"
    )


def test_venv_without_pip_recommends_ensurepip() -> None:
    """A venv that lacks pip should run ensurepip before retrying."""

    context = PreflightContext(context="venv", in_venv=True, venv_exists=True)
    capabilities = Capabilities(True, False, False, False, False, False, "")
    recommendation = plan_recommendation("host", context, capabilities)
    assert recommendation.path is None
    assert "ensurepip --upgrade" in recommendation.next_step


def test_setuptools_missing_recommends_os_or_wheelhouse() -> None:
    """Missing setuptools should point to OS packages or the wheelhouse path."""

    context = PreflightContext(context="venv", in_venv=True, venv_exists=True)
    capabilities = Capabilities(True, True, False, True, False, False, "")
    recommendation = plan_recommendation("host", context, capabilities)
    assert recommendation.path is None
    assert "install your OS python-setuptools" in recommendation.next_step


def test_docker_permission_failure_reports_troubleshooting() -> None:
    """Docker daemon problems produce the troubleshooting guidance."""

    context = PreflightContext(context="system", in_venv=False, venv_exists=False)
    capabilities = Capabilities(
        True, True, True, True, True, False, "permission denied"
    )
    recommendation = plan_recommendation("docker", context, capabilities)
    assert recommendation.path is None
    assert "Docker troubleshooting" in recommendation.next_step
    assert recommendation.notes
