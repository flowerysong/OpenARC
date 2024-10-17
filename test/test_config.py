#!/usr/bin/env python3

import subprocess


def test_config(milter_config, milter_cmdline):
    """A basic config should parse without error"""
    res = subprocess.run(milter_cmdline + ['-n'], cwd=milter_config['cwd'], capture_output=True, text=True, timeout=4)
    assert res.returncode == 0


def test_config_fail(milter_config, milter_cmdline):
    """An invalid config should fail and return an error"""
    res = subprocess.run(milter_cmdline + ['-n'], cwd=milter_config['cwd'], capture_output=True, text=True, timeout=4)
    assert res.returncode != 0
    assert 'parameter "KeyFile" required when signing' in res.stderr


def test_config_requiresafekeys(milter_config, milter_cmdline):
    """World-readable keys should be rejected"""
    res = subprocess.run(milter_cmdline + ['-n'], cwd=milter_config['cwd'], capture_output=True, text=True, timeout=4)
    assert res.returncode != 0
    assert 'can be read or written by other users' in res.stderr


def test_config_requiresafekeys_false(milter_config, milter_cmdline):
    """World-readable keys are okay if the user said they're okay."""
    res = subprocess.run(milter_cmdline + ['-n'], cwd=milter_config['cwd'], capture_output=True, text=True, timeout=4)
    assert res.returncode == 0
