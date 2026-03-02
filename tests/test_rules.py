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
    }
    missing = expected - set(config.weights.keys())
    assert not missing, f"Missing weight keys: {missing}"
