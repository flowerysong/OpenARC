#!/usr/bin/env python3

import stat
import subprocess

import pytest


@pytest.mark.parametrize(
    'python_version',
    [
        'python3',
        'python3.7',
        'python3.8',
        'python3.9',
        'python3.10',
        'python3.11',
        'python3.12',
        'python3.13',
    ],
)
def test_keygen(tool_path, tmp_path, python_version):
    """Basic test that it works under the supported versions of Python"""
    binargs = [
        python_version,
        tool_path('contrib/openarc-keygen'),
        '--directory',
        str(tmp_path),
        '--domain',
        'example.com',
        '--selector',
        'foo',
    ]

    try:
        subprocess.run(binargs, check=True)
    except FileNotFoundError:
        assert python_version != 'python3'
        pytest.skip(f'{python_version} not found')

    keystat = tmp_path.joinpath('foo._domainkey.example.com.key').stat()
    # verify that the key has restrictive permissions
    assert keystat.st_mode & stat.S_IRWXG == 0
    assert keystat.st_mode & stat.S_IRWXO == 0
    assert tmp_path.joinpath('foo._domainkey.example.com.txt').exists()
