#!/usr/bin/env python3

import os
import subprocess

import pytest


@pytest.fixture()
def private_key(scope='session'):
    filepath = os.path.dirname(os.path.realpath(__file__))
    filepath = os.path.join(filepath, 'files', 'private.key')
    binargs = [
        'openssl',
        'genrsa',
        '-out', filepath,
        '2048',
    ]
    subprocess.run(binargs)


@pytest.fixture()
def tool_path(scope='session'):
    def _tool_path(tool):
        binpath = os.path.dirname(os.path.realpath(__file__))
        binpath = os.path.join(binpath, '..', tool)
        return os.path.realpath(binpath)
    return _tool_path


@pytest.fixture()
def milter_config(request, private_key):
    base_path = os.path.join(request.fspath.dirname, 'files')
    for candidate in [
        request.fspath.basename,    # test file
        request.function.__name__,  # test function
    ]:
        fname = os.path.join(base_path, '.'.join([candidate, 'conf']))
        if os.path.isfile(fname):
            return fname

    return os.path.join(base_path, 'milter.conf')


@pytest.fixture
def milter(tmp_path, tool_path, milter_config):
    binargs = [
        tool_path('openarc/openarc'),
        '-f',
        '-v',
        '-c', milter_config,
        '-p', tmp_path.joinpath('milter.sock'),
    ]

    milter_proc = subprocess.Popen(binargs)

    yield milter_proc

    milter_proc.terminate()
