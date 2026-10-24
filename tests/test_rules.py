from __future__ import annotations

from pkginspect.rules import RulesConfig, load_rules


def test_load_bundled_rules():
    config = load_rules()
    assert isinstance(config, RulesConfig)
    assert config.weights["missing_checksums"] < 0
    assert config.caps["integrity"] < 0
    assert config.blockers["uses_sudo"] is True


def test_all_weight_keys_present():
    config = load_rules()
    expected = {
        "missing_checksums",
        "skip_checksum_some",
        "skip_checksum_all",
        "weak_hash",
        "insecure_url",
        "git_unpinned",
        "pipe_to_shell",
        "eval_exec",
        "obfuscation",
        "ld_preload",
        "network_fetch",
        "sudo_or_pacman",
        "privilege_escal",
        "setuid_bit",
        "no_license",
        "no_arch_field",
        "no_maintainer_tag",
        "namcap_error",
        "aur_low_votes_1",
        "aur_low_votes_2",
        "aur_low_votes_3",
        "aur_orphaned",
        "aur_out_of_date",
        "aur_new_package",
        "aur_very_new_package",
        "aur_out_of_date_recent",
        "persistence_service",
        "skip_checksum_docs",
        "reverse_shell",
        "persistence",
        "suspicious_host",
        "tmp_usage",
    }
    missing = expected - set(config.weights.keys())
    assert not missing, f"Missing weight keys: {missing}"


def test_bundled_path():
    assert load_rules().path == "bundled"


def test_user_rules_merge_over_defaults(tmp_path):
    """An older user file without the newer keys must not lose them."""
    user = tmp_path / "rules.yaml"
    user.write_text(
        "weights:\n  pipe_to_shell: -99\ncaps:\n  integrity: -10\nblockers:\n  uses_sudo: false\n"
    )
    config = load_rules(str(user))
    assert config.path == str(user)
    assert config.weights["pipe_to_shell"] == -99  # overridden
    assert config.weights["reverse_shell"] < 0  # inherited from the bundled file
    assert config.caps["integrity"] == -10
    assert config.caps["community"] == -40
    assert config.blockers["uses_sudo"] is False
    assert config.blockers["reverse_shell"] is True


def test_user_rules_file_may_be_empty(tmp_path):
    user = tmp_path / "rules.yaml"
    user.write_text("")
    assert load_rules(str(user)).weights == load_rules().weights
