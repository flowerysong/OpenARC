#!/usr/bin/env python3

import socket

import libmilter
import pytest


@pytest.fixture
def run_miltertest(request, milter, milter_config):
    def _run_miltertest(headers=None):
        headers = headers or []
        headers.extend(
            [
                ['From', 'user@example.com\n'],
                ['Date', 'Fri, 04 Oct 2024 10:11:12 -0400'],
                ['Subject', request.function.__name__],
            ]
        )

        # Connect
        sock = socket.socket(family=socket.AF_UNIX)
        sock.connect(bytes(milter_config['sock']))
        conn = libmilter.MilterConnection(sock)
        conn.optneg_mta(protocol=libmilter.SMFI_V6_PROT ^ libmilter.SMFIP_HDR_LEADSPC)
        conn.send(libmilter.SMFIC_CONNECT, hostname='localhost', address='127.0.0.1', family=libmilter.SMFIA_INET, port=666)
        conn.send(libmilter.SMFIC_HELO, helo='mx.example.com')

        # Envelope data
        conn.send(libmilter.SMFIC_MAIL, args=['<sender@example.com>'])
        conn.send(libmilter.SMFIC_RCPT, args=['<recipient@example.com>'])

        # Send headers
        conn.send(libmilter.SMFIC_DATA)
        conn.send_headers(headers)
        conn.send(libmilter.SMFIC_EOH)

        # Send body
        conn.send_body('test body\r\n')
        resp = conn.send_eom()
        ins_headers = []
        for msg in resp:
            if msg[0] == libmilter.SMFIR_INSHEADER:
                ins_headers.insert(msg[1]['index'], [msg[1]['name'], msg[1]['value']])
            elif msg[0] in libmilter.DISPOSITION_REPLIES:
                assert msg[0] == libmilter.SMFIR_ACCEPT
            else:
                pytest.fail(f'Unexpected EOM response {msg}')

        return {
            'headers': ins_headers,
        }

    return _run_miltertest


def test_milter_basic(run_miltertest):
    """Basic signing"""
    res = run_miltertest()

    assert res['headers'][0] == ['Authentication-Results', 'example.com; arc=none smtp.remote-ip=127.0.0.1']
    assert res['headers'][1][0] == 'ARC-Seal'
    assert 'cv=none' in res['headers'][1][1]
    assert res['headers'][2][0] == 'ARC-Message-Signature'
    assert res['headers'][3] == ['ARC-Authentication-Results', 'i=1; example.com; arc=none']


def test_milter_resign(run_miltertest):
    """Extend the chain as much as possible"""
    res = run_miltertest()

    headers = []
    for i in range(2, 52):
        headers = [*res['headers'], *headers]
        res = run_miltertest(headers)

        assert res['headers'][0] == ['Authentication-Results', 'example.com; arc=pass smtp.remote-ip=127.0.0.1']

        if i <= 50:
            assert res['headers'][3] == ['ARC-Authentication-Results', f'i={i}; example.com; arc=pass']
            assert 'cv=pass' in res['headers'][1][1]
        else:
            assert len(res['headers']) == 1


def test_milter_mode_s(run_miltertest):
    """Sign mode"""
    res = run_miltertest()

    assert len(res['headers']) == 3
    assert 'cv=none' in res['headers'][0][1]
    assert res['headers'][1][0] == 'ARC-Message-Signature'
    assert res['headers'][2] == ['ARC-Authentication-Results', 'i=1; example.com; arc=none']


def test_milter_mode_v(run_miltertest):
    """Verify mode"""
    res = run_miltertest()

    assert len(res['headers']) == 1
    assert res['headers'][0] == ['Authentication-Results', 'example.com; arc=none smtp.remote-ip=127.0.0.1']


def test_milter_mode_none_verify(run_miltertest):
    """No configured mode, from a host that's not in InternalHosts"""
    res = run_miltertest()

    assert len(res['headers']) == 1
    assert res['headers'][0] == ['Authentication-Results', 'example.com; arc=none smtp.remote-ip=127.0.0.1']


def test_milter_mode_none_sign(run_miltertest):
    """No configured mode, from a host that's in InternalHosts"""
    res = run_miltertest()

    assert len(res['headers']) == 3
    assert 'cv=none' in res['headers'][0][1]
    assert res['headers'][1][0] == 'ARC-Message-Signature'
    assert res['headers'][2] == ['ARC-Authentication-Results', 'i=1; example.com; arc=none']

@pytest.mark.parametrize(
    'data',
    [
        # Single header
        [
            ['example.com; iprev=pass\n\tpolicy.iprev=192.0.2.1 (mail.example.com);\n\tspf=pass (domain of foo@example.com\n\t designates 192.0.2.1 as permitted sender); dkim=pass header.i=@example.com header.s=foo'],
            # FIXME: should the folded whitespace in the comment be removed?
            'iprev=pass policy.iprev=192.0.2.1; spf=pass (domain of foo@example.com\n\t designates 192.0.2.1 as permitted sender); dkim=pass header.i=@example.com header.s=foo; arc=none',
        ],
        # Multiple headers
        [
            [
                'example.com; iprev=pass\n\tpolicy.iprev=192.0.2.1 (mail.example.com)',
                'example.com; spf=pass (domain of foo@example.com\n\t designates 192.0.2.1 as permitted sender)',
                'example.com; dkim=pass header.i=@example.com header.s=foo',
            ],
            'iprev=pass policy.iprev=192.0.2.1; spf=pass (domain of foo@example.com\n\t designates 192.0.2.1 as permitted sender); dkim=pass header.i=@example.com header.s=foo; arc=none',
        ],
        # Multiple headers for the same method
        [
            [
                'example.com; spf=pass',
                'example.com; spf=fail',
                'example.com; spf=none',
            ],
            'spf=pass',
        ],
    ]
)
def test_milter_ar(run_miltertest, data):
    """Test Authentication-Results parsing"""
    res = run_miltertest([['Authentication-Results', x] for x in data[0]])

    assert res['headers'][3] == ['ARC-Authentication-Results', f'i=1; example.com; {data[1]}']


def test_milter_ar_override(run_miltertest):
    """Override the chain validation state with Authentication-Results"""
    res = run_miltertest()

    # override the result to "fail"
    headers = res['headers']
    headers[0][1] = 'example.com; arc=fail'

    res = run_miltertest(headers)

    assert res['headers'][0] == ['Authentication-Results', 'example.com; arc=fail smtp.remote-ip=127.0.0.1']
    assert 'cv=fail' in res['headers'][1][1]
    assert res['headers'][3] == ['ARC-Authentication-Results', 'i=2; example.com; arc=fail']

    # override the result to "pass"
    headers = [*res['headers'], *headers]
    headers[0][1] = 'example.com; arc=pass'
    res = run_miltertest(headers)

    # the chain is dead because it came in as failed, no matter what A-R says
    assert res['headers'][0] == ['Authentication-Results', 'example.com; arc=fail smtp.remote-ip=127.0.0.1']
    assert len(res['headers']) == 1


def test_milter_ar_override_disabled(run_miltertest):
    """`PermitAuthenticationOverrides = no` preserves the actual state"""
    res = run_miltertest()

    # override the result to "fail"
    headers = res['headers']
    headers[0][1] = 'example.com; arc=fail'

    res = run_miltertest(headers)

    assert res['headers'][0] == ['Authentication-Results', 'example.com; arc=pass smtp.remote-ip=127.0.0.1']
    assert 'cv=pass' in res['headers'][1][1]
    assert res['headers'][3] == ['ARC-Authentication-Results', 'i=2; example.com; arc=pass']


def test_milter_ar_override_multi(run_miltertest):
    """Only the most recent A-R header should matter"""
    res = run_miltertest()

    headers = [
        ['Authentication-Results', 'example.com; arc=pass'],
        ['Authentication-Results', 'example.com; arc=fail'],
        *[x for x in res['headers'] if x[0] != 'Authentication-Results'],
    ]
    res = run_miltertest(headers)

    assert res['headers'][0] == ['Authentication-Results', 'example.com; arc=pass smtp.remote-ip=127.0.0.1']
    assert 'cv=pass' in res['headers'][1][1]
    assert res['headers'][3] == ['ARC-Authentication-Results', 'i=2; example.com; arc=pass']


def test_milter_peerlist(run_miltertest):
    """Connections from peers just get `accept` back immediately"""
    with pytest.raises(libmilter.MilterError, match='unexpected response: a'):
        run_miltertest()
