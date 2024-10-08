#!/usr/bin/env python3

import os
import subprocess
import time

import pytest


@pytest.fixture()
def private_key(scope='session'):
    basepath = os.path.dirname(os.path.realpath(__file__))
    keypath = os.path.join(basepath, 'files', 'private.key')
    binargs = [
        'openssl',
        'genrsa',
        '-out', keypath,
        '2048',
    ]
    subprocess.run(binargs)

    pubpath = os.path.join(basepath, 'files', 'public.key')
    binargs = [
        'openssl',
        'rsa',
        '-in', keypath,
        '-pubout',
    ]
    res = subprocess.run(binargs, capture_output=True, text=True)
    with open(pubpath, 'w') as f:
        key = ''.join(res.stdout.splitlines()[1:-1])
        f.write(f'elpmaxe._domainkey.example.com v=DKIM1; k=rsa; p={key}\n')


@pytest.fixture()
def tool_path(scope='session'):
    def _tool_path(tool):
        binpath = os.path.dirname(os.path.realpath(__file__))
        binpath = os.path.join(binpath, '..', tool)
        return os.path.realpath(binpath)
    return _tool_path


@pytest.fixture()
def milter_config(request, tmp_path, private_key):
    base_path = os.path.join(request.fspath.dirname, 'files')
    config = {
        'cwd': base_path,
        'file': os.path.join(base_path, 'milter.conf'),
        'sock': tmp_path.joinpath('milter.sock'),
    }
    for candidate in [
        request.fspath.basename,    # test file
        request.function.__name__,  # test function
    ]:
        fname = os.path.join(base_path, '.'.join([candidate, 'conf']))
        if os.path.isfile(fname):
            config['file'] = fname
            return config

    return config


@pytest.fixture()
def milter_cmdline(tmp_path, tool_path, milter_config):
    return [
        tool_path('openarc/openarc'),
        '-f',
        '-v',
        '-c', milter_config['file'],
        '-p', milter_config['sock'],
    ]


@pytest.fixture()
def milter(milter_cmdline, milter_config):
    milter_proc = subprocess.Popen(milter_cmdline, cwd=milter_config['cwd'])
    while not milter_proc.poll() and not os.path.exists(milter_config['sock']):
        time.sleep(0.1)

    yield milter_proc

    milter_proc.terminate()
