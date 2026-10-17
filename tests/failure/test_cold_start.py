"""Cold start — all modules import with no side effects."""


def test_all_modules_import() -> None:
    import nti_attack
    import nti_attack.adapters
    import nti_attack.adapters.base
    import nti_attack.adapters.callable_adapter
    import nti_attack.adapters.http_adapter
    import nti_attack.adapters.langchain_adapter
    import nti_attack.attestation
    import nti_attack.core
    import nti_attack.runner
    import nti_attack.signing

    assert nti_attack is not None
