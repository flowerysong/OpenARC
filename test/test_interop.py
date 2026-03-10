#!/usr/bin/env python3

import subprocess

import pytest

from dirty_equals import IsStr
from inline_snapshot import snapshot

HAS_DKIMPY = True
try:
    from dkim import ARC
except ImportError:
    HAS_DKIMPY = False


@pytest.fixture(scope='session')
def dkimpy():
    if not HAS_DKIMPY:
        pytest.skip('dkimpy not found')


@pytest.fixture(scope='session')
def perl_mail_dkim():
    try:
        subprocess.run(['perl', '-MMail::DKIM', '-e', ''], check=True)
    except Exception:
        pytest.skip('Mail::DKIM not found')


def test_dkimpy_sign(run_miltertest, private_key, dkimpy):
    hdrs = [
        ['Subject', ' test message from dkimpy'],
        ['From', ' testsender@example.com'],
        ['To', ' testrcpt@example.com'],
        ['Authentication-Results', ' dkimpy.example.com; none'],
    ]

    msg = b''
    for h, v in hdrs:
        msg += f'{h}: {v}\r\n'.encode()
    msg += b'\r\ntest body\r\n'

    res = ARC(msg).sign(b'dkimpy', b'example.com', private_key['basepath'].joinpath('dkimpy._domainkey.example.com.key').read_bytes(), b'dkimpy.example.com')

    hdrs = [
        *[h.decode().rstrip().split(':', 1) for h in res],
        *hdrs,
    ]
    res = run_miltertest(hdrs, False)

    assert res['headers'] == snapshot(
        [
            ['Authentication-Results', ' example.com; arc=pass header.oldest-pass=0 smtp.remote-ip=127.0.0.1'],
            ['ARC-Seal', IsStr(regex=r' i=2; d=example\.com; s=elpmaxe; a=rsa-sha256; cv=pass; t=1234567890;\s+(?s:.+)')],
            [
                'ARC-Message-Signature',
                IsStr(regex=r' i=2; d=example\.com; s=elpmaxe; a=rsa-sha256;\s+c=relaxed/simple; t=1234567890;\s+h=Subject:From:To;\s+(?s:.+)'),
            ],
            ['ARC-Authentication-Results', ' i=2; example.com; arc=pass header.oldest-pass=0 smtp.remote-ip=127.0.0.1'],
        ]
    )


def test_dkimpy_verify(run_miltertest, private_key, dkimpy):
    # we don't test simple/simple because dkimpy uses the wrong default
    for i in range(0, 3):
        res = run_miltertest(milter_instance=i)

        msg = b''
        for h, v in [*res['headers'], *res['msg_headers']]:
            msg += f'{h}:{v}\r\n'.encode()
        msg += f'\r\n{res["msg_body"]}'.encode()

        def dnsfunc(domain, timeout=5):
            with open(private_key['public_keys'], 'rb') as f:
                for line in f:
                    if line.startswith(domain[:-1]):
                        return line.split(None, 1)[1]

            return ''

        res = ARC(msg).verify(dnsfunc)
        assert res[0] == b'pass'


def test_perl_sign(run_miltertest, private_key, perl_mail_dkim):
    hdrs = [
        ['Subject', ' test message from Mail::DKIM'],
        ['From', ' testsender@example.com'],
        ['To', ' testrcpt@example.com'],
        ['Authentication-Results', ' perl.example.com; none'],
    ]

    msg = ''
    for h, v in hdrs:
        msg += f'{h}:{v}\r\n'
    msg += '\r\ntest body\r\n'

    res = subprocess.run(
        [
            'perl',
            '-MMail::DKIM::ARC::Signer',
            '-E',
            f'my $arc = new Mail::DKIM::ARC::Signer(Domain => "example.com", Selector => "perl", SrvId => "perl.example.com", KeyFile => "{private_key["basepath"].joinpath("perl._domainkey.example.com.key")}", Chain => "ar"); while (<STDIN>) {{ $arc->PRINT($_) }}; $arc->CLOSE; say join("\n", $arc->as_strings)',  # noqa: E501
        ],
        input=msg,
        text=True,
        capture_output=True,
    )

    assert res.returncode == 0

    hdrs = [
        *[x.split(':', 1) for x in res.stdout.splitlines()],
        *hdrs,
    ]

    res = run_miltertest(hdrs, False)
    assert res['headers'] == snapshot(
        [
            ['Authentication-Results', ' example.com; arc=pass header.oldest-pass=0 smtp.remote-ip=127.0.0.1'],
            [
                'ARC-Seal',
                IsStr(regex=r' i=2; d=example.com; s=elpmaxe; a=rsa-sha256; cv=pass; t=1234567890;\s+(?s:.+)'),
            ],
            [
                'ARC-Message-Signature',
                IsStr(regex=r' i=2; d=example.com; s=elpmaxe; a=rsa-sha256;\s+c=relaxed/simple; t=1234567890;\s+h=Subject:From:To;\s+(?s:.+)'),
            ],
            ['ARC-Authentication-Results', ' i=2; example.com; arc=pass header.oldest-pass=0 smtp.remote-ip=127.0.0.1'],
        ]
    )
