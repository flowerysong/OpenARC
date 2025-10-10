#!/usr/bin/env python3

import miltertest
import pytest


def test_milter_basic(run_miltertest):
    """Basic signing"""
    res = run_miltertest()

    assert res['headers'][0] == ['Authentication-Results', ' example.com; arc=none smtp.remote-ip=127.0.0.1']
    assert res['headers'][1][0] == 'ARC-Seal'
    assert 'cv=none' in res['headers'][1][1]
    assert res['headers'][2][0] == 'ARC-Message-Signature'
    assert res['headers'][3] == ['ARC-Authentication-Results', ' i=1; example.com; arc=none smtp.remote-ip=127.0.0.1']


def test_milter_v2(run_miltertest):
    """Basic signing"""
    res = run_miltertest(protocol=miltertest.SMFI_V2_PROT)

    assert res['headers'][0] == ['Authentication-Results', 'example.com; arc=none smtp.remote-ip=127.0.0.1']
    assert res['headers'][1][0] == 'ARC-Seal'
    assert 'cv=none' in res['headers'][1][1]
    assert res['headers'][2][0] == 'ARC-Message-Signature'
    assert res['headers'][3] == ['ARC-Authentication-Results', 'i=1; example.com; arc=none smtp.remote-ip=127.0.0.1']


def test_milter_canon_simple(run_miltertest):
    """Sign a message with simple canonicalization and then verify it"""
    res = run_miltertest()
    assert 'c=relaxed' not in res['headers'][1][1]

    res = run_miltertest(res['headers'])
    assert 'cv=pass' in res['headers'][0][1]
    assert res['headers'][2] == ['ARC-Authentication-Results', ' i=2; example.com; arc=pass header.oldest-pass=0 smtp.remote-ip=127.0.0.1']


def test_milter_resign(run_miltertest):
    """Extend the chain as much as possible"""
    res = run_miltertest()

    headers = []
    for i in range(2, 52):
        headers = [*res['headers'], *headers]
        res = run_miltertest(headers)

        assert res['headers'][0] == ['Authentication-Results', ' example.com; arc=pass header.oldest-pass=0 smtp.remote-ip=127.0.0.1']

        if i <= 50:
            assert res['headers'][3] == ['ARC-Authentication-Results', f' i={i}; example.com; arc=pass header.oldest-pass=0 smtp.remote-ip=127.0.0.1']
            assert 'cv=pass' in res['headers'][1][1]

            # quick and dirty parsing
            ams = {x[0].strip(): x[1].strip() for x in [y.split('=', 1) for y in ''.join(res['headers'][2][1].splitlines()).split(';')]}
            ams_h = [x.strip() for x in ams['h'].lower().split(':')]
            assert not any(x in ams_h for x in ['authentication-results', 'arc-seal', 'arc-message-signature', 'arc-authentication-results'])
        else:
            assert len(res['headers']) == 1


def test_milter_mode_s(run_miltertest):
    """Sign mode"""
    res = run_miltertest()

    assert len(res['headers']) == 3
    assert 'cv=none' in res['headers'][0][1]
    assert res['headers'][1][0] == 'ARC-Message-Signature'
    assert res['headers'][2] == ['ARC-Authentication-Results', ' i=1; example.com; arc=none smtp.remote-ip=127.0.0.1']

    res = run_miltertest(res['headers'])
    assert len(res['headers']) == 3
    assert 'cv=pass' in res['headers'][0][1]
    assert res['headers'][2] == ['ARC-Authentication-Results', ' i=2; example.com; arc=pass header.oldest-pass=0 smtp.remote-ip=127.0.0.1']


def test_milter_resign_s(run_miltertest):
    """Extend the chain as much as possible in pure signing mode"""
    res = run_miltertest()

    headers = []
    for i in range(2, 52):
        headers = [*res['headers'], *headers]
        res = run_miltertest(headers)

        if i <= 50:
            assert res['headers'][2] == ['ARC-Authentication-Results', f' i={i}; example.com; arc=pass header.oldest-pass=0 smtp.remote-ip=127.0.0.1']
            assert 'cv=pass' in res['headers'][0][1]

            # quick and dirty parsing
            ams = {x[0].strip(): x[1].strip() for x in [y.split('=', 1) for y in ''.join(res['headers'][1][1].splitlines()).split(';')]}
            ams_h = [x.strip() for x in ams['h'].lower().split(':')]
            assert not any(x in ams_h for x in ['authentication-results', 'arc-seal', 'arc-message-signature', 'arc-authentication-results'])
        else:
            assert len(res['headers']) == 0


def test_milter_mode_v(run_miltertest):
    """Verify mode"""
    res = run_miltertest()

    assert len(res['headers']) == 1
    assert res['headers'][0] == ['Authentication-Results', ' example.com; arc=none smtp.remote-ip=127.0.0.1']


def test_milter_mode_none_verify(run_miltertest):
    """No configured mode, from a host that's not in InternalHosts"""
    res = run_miltertest()

    assert len(res['headers']) == 1
    assert res['headers'][0] == ['Authentication-Results', ' example.com; arc=none smtp.remote-ip=127.0.0.1']


def test_milter_mode_none_sign(run_miltertest):
    """No configured mode, from a host that's in InternalHosts"""
    res = run_miltertest()

    assert len(res['headers']) == 3
    assert 'cv=none' in res['headers'][0][1]
    assert res['headers'][1][0] == 'ARC-Message-Signature'
    assert res['headers'][2] == ['ARC-Authentication-Results', ' i=1; example.com; arc=none smtp.remote-ip=127.0.0.1']


@pytest.mark.parametrize(
    'data',
    [
        # Single header
        [
            [
                (
                    'example.com;'
                    ' iprev=pass\n\tpolicy.iprev=192.0.2.1 (mail.example.com);'
                    '\n\tspf=pass (domain of foo@example.com\n\t designates 192.0.2.1 as permitted sender);'
                    ' dkim=pass header.i=@example.com header.s=foo'
                )
            ],
            (
                'iprev=pass policy.iprev=192.0.2.1 (mail.example.com);'
                '\n\tspf=pass (domain of foo@example.com designates 192.0.2.1 as permitted sender);'
                '\n\tdkim=pass header.i=@example.com header.s=foo;'
                '\n\tarc=none smtp.remote-ip=127.0.0.1'
            ),
        ],
        # Multiple headers
        [
            [
                'example.com; iprev=pass\n\tpolicy.iprev=192.0.2.1 (mail.example.com)',
                'example.com; spf=pass (domain of foo@example.com\n\t designates 192.0.2.1 as permitted sender)',
                'example.com; dkim=pass header.i=@example.com header.s=foo',
            ],
            (
                'iprev=pass policy.iprev=192.0.2.1 (mail.example.com);'
                '\n\tspf=pass (domain of foo@example.com designates 192.0.2.1 as permitted sender);'
                '\n\tdkim=pass header.i=@example.com header.s=foo;'
                '\n\tarc=none smtp.remote-ip=127.0.0.1'
            ),
        ],
        # Multiple headers for the same method
        [
            [
                'example.com; spf=pass',
                'example.com; spf=fail',
                'example.com; spf=none',
            ],
            'spf=pass;\n\tarc=none smtp.remote-ip=127.0.0.1',
        ],
        # Same method multiple times
        [
            ['example.com; spf=pass; spf=fail; spf=none'],
            'spf=pass;\n\tarc=none smtp.remote-ip=127.0.0.1',
        ],
        # Header with more results than we're willing to store
        [
            [
                (
                    'example.com;'
                    ' dkim=pass header.i=@example.com header.s=foo;'
                    ' dkim=pass header.i=@example.com header.s=bar;'
                    ' dkim=pass header.i=@example.com header.s=baz;'
                    ' dkim=pass header.i=@example.com header.s=qux;'
                    ' dkim=pass header.i=@example.com header.s=quux;'
                    ' dkim=pass header.i=@example.com header.s=quuux;'
                    ' dkim=fail header.i=@example.com header.s=foo;'
                    ' dkim=fail header.i=@example.com header.s=bar;'
                    ' dkim=fail header.i=@example.com header.s=baz;'
                    ' dkim=fail header.i=@example.com header.s=qux;'
                    ' dkim=fail header.i=@example.com header.s=quux;'
                    ' dkim=fail header.i=@example.com header.s=quuux;'
                    ' dkim=policy header.i=@example.com header.s=foo;'
                    ' dkim=policy header.i=@example.com header.s=bar;'
                    ' dkim=policy header.i=@example.com header.s=baz;'
                    ' dkim=policy header.i=@example.com header.s=qux;'
                    ' dkim=policy header.i=@example.com header.s=quux;'
                    ' dkim=policy header.i=@example.com header.s=quuux;'
                    ' spf=pass'
                )
            ],
            (
                'dkim=pass header.i=@example.com header.s=foo;'
                '\n\tdkim=pass header.i=@example.com header.s=bar;'
                '\n\tdkim=pass header.i=@example.com header.s=baz;'
                '\n\tdkim=pass header.i=@example.com header.s=qux;'
                '\n\tdkim=pass header.i=@example.com header.s=quux;'
                '\n\tdkim=pass header.i=@example.com header.s=quuux;'
                '\n\tdkim=fail header.i=@example.com header.s=foo;'
                '\n\tdkim=fail header.i=@example.com header.s=bar;'
                '\n\tdkim=fail header.i=@example.com header.s=baz;'
                '\n\tdkim=fail header.i=@example.com header.s=qux;'
                '\n\tdkim=fail header.i=@example.com header.s=quux;'
                '\n\tdkim=fail header.i=@example.com header.s=quuux;'
                '\n\tdkim=policy header.i=@example.com header.s=foo;'
                '\n\tdkim=policy header.i=@example.com header.s=bar;'
                '\n\tdkim=policy header.i=@example.com header.s=baz;'
                '\n\tdkim=policy header.i=@example.com header.s=qux;'
                '\n\tarc=none smtp.remote-ip=127.0.0.1'
            ),
        ],
        # Non-matching authserv-id
        [
            [
                'example.com.example.net; spf=pass',
                'otheradmd.example.com; spf=tempfail',
                'example.net; spf=permfail',
            ],
            'arc=none smtp.remote-ip=127.0.0.1',
        ],
        # CFWS
        [
            ['example.com; (a)spf (Sender Policy Framework) = pass (good) smtp (mail transfer) . (protocol) mailfrom = foo@example.com;'],
            'spf=pass (good) smtp.mailfrom=foo@example.com;\n\tarc=none smtp.remote-ip=127.0.0.1',
        ],
        # Unknown method
        [
            ['example.com; spf=pass; superspf=pass; arc=pass; superarc=fail policy.krypton=foo;'],
            'spf=pass;\n\tarc=pass',
        ],
        # Unknown ptype
        [
            [
                'example.com; spf=pass imap.override=true',
                'example.com; spf=pass; iprev=pass dnssec.signed=true',
            ],
            'arc=none smtp.remote-ip=127.0.0.1',
        ],
        # reason
        [
            ['example.com; spf=pass (ip4)reason="192.0.2.1 matched ip4:192.0.2.0/27 in _spf.example.com"; dmarc=pass'],
            'spf=pass reason="192.0.2.1 matched ip4:192.0.2.0/27 in _spf.example.com" (ip4);\n\tdmarc=pass;\n\tarc=none smtp.remote-ip=127.0.0.1',
        ],
        # misplaced reason
        [
            ['example.com; spf=pass; iprev=pass policy.iprev=192.0.2.1 reason="because"'],
            'arc=none smtp.remote-ip=127.0.0.1',
        ],
        # no-result
        [
            [
                'example.com; none',
                'example.com; none; spf=pass',
                'example.com; spf=fail; none',
            ],
            'arc=none smtp.remote-ip=127.0.0.1',
        ],
        # truncations
        [
            [
                'example.com',
                'example.com; spf',
                'example.com; spf=',
                'example.com; dmarc=pass; iprev=pass policy',
                'example.com; dmarc=pass; iprev=pass policy.',
                'example.com; dmarc=pass; iprev=pass policy.iprev',
                'example.com; dmarc=pass; iprev=pass policy.iprev=',
                'example.com; dmarc=pass; iprev=pass policy.iprev="',
                'example.com; dmarc=pass; iprev=pass policy.iprev="1',
                'example.com; dmarc=pass; iprev=pass policy.iprev="1" (',
                'example.com; dmarc=pass; iprev=pass policy.iprev="1" ( a c',
            ],
            'arc=none smtp.remote-ip=127.0.0.1',
        ],
        # bad sequences
        [
            [
                'example.com; dmarc=pass; spf pass;',
                'example.com; dmarc=pass; iprev=pass policy.iprev.192.0.2.1',
                'example.com; dmarc=pass; iprev=pass policy=iprev=192.0.2.1',
                'example.com; dmarc=pass reason "because";',
            ],
            'arc=none smtp.remote-ip=127.0.0.1',
        ],
        # RFC 8904
        [
            ['example.com; dnswl=pass dns.zone=accept.example.com policy.ip=192.0.2.1 policy.txt="sure, yeah" dns.sec=yes'],
            'dnswl=pass dns.zone=accept.example.com policy.ip=192.0.2.1 policy.txt="sure, yeah" dns.sec=yes;\n\tarc=none smtp.remote-ip=127.0.0.1',
        ],
        # quoted-string
        [
            ['example.com; auth=pass smtp.auth="花木蘭\\"\\\\ []"'],
            'auth=pass smtp.auth="花木蘭\\"\\\\ []";\n\tarc=none smtp.remote-ip=127.0.0.1',
        ],
        # version
        [
            [
                'example.com 1; spf=pass',
                'example.com 1 ; dmarc=pass',
            ],
            'spf=pass;\n\tdmarc=pass;\n\tarc=none smtp.remote-ip=127.0.0.1',
        ],
        # invalid version
        [
            [
                'example.com 12.0; spf=pass',
                'example.com a; spf=pass',
                'example.com 1 1; spf=pass',
            ],
            'arc=none smtp.remote-ip=127.0.0.1',
        ],
    ],
)
def test_milter_ar(run_miltertest, data):
    """Test Authentication-Results parsing"""
    res = run_miltertest([['Authentication-Results', x] for x in data[0]])

    assert res['headers'][3] == ['ARC-Authentication-Results', f' i=1; example.com; {data[1]}']


def test_milter_authrescomments(run_miltertest):
    """AuthResComments=false strips out even reasonably-placed comments"""
    res = run_miltertest(
        [
            [
                'Authentication-Results',
                'example.com; (a)spf (Sender Policy Framework) = pass (good) smtp (mail transfer) . (protocol) mailfrom = foo@example.com',
            ]
        ]
    )
    assert res['headers'][3] == [
        'ARC-Authentication-Results',
        ' i=1; example.com; spf=pass smtp.mailfrom=foo@example.com;\n\tarc=none smtp.remote-ip=127.0.0.1',
    ]


def test_milter_ar_override(run_miltertest):
    """Override the chain validation state with Authentication-Results"""
    res = run_miltertest()

    # override the result to "fail"
    headers = res['headers']
    headers[0][1] = 'example.com; arc=fail'

    res = run_miltertest(headers)

    assert res['headers'][0] == ['Authentication-Results', ' example.com; arc=fail smtp.remote-ip=127.0.0.1']
    assert 'cv=fail' in res['headers'][1][1]
    assert res['headers'][3] == ['ARC-Authentication-Results', ' i=2; example.com; arc=fail']

    # override the result to "pass"
    headers = [*res['headers'], *headers]
    headers[0][1] = 'example.com; arc=pass'
    res = run_miltertest(headers)

    # the chain is dead because it came in as failed, no matter what A-R says
    assert res['headers'][0] == ['Authentication-Results', ' example.com; arc=fail smtp.remote-ip=127.0.0.1']
    assert len(res['headers']) == 1


def test_milter_ar_override_disabled(run_miltertest):
    """`PermitAuthenticationOverrides = no` preserves the actual state"""
    res = run_miltertest()

    # override the result to "fail"
    headers = res['headers']
    headers[0][1] = ' example.com; arc=fail'

    res = run_miltertest(headers)

    assert res['headers'][0] == ['Authentication-Results', ' example.com; arc=pass header.oldest-pass=0 smtp.remote-ip=127.0.0.1']
    assert 'cv=pass' in res['headers'][1][1]
    assert res['headers'][3] == ['ARC-Authentication-Results', ' i=2; example.com; arc=pass header.oldest-pass=0 smtp.remote-ip=127.0.0.1']


def test_milter_ar_override_multi(run_miltertest):
    """Only the most recent A-R header should matter"""
    res = run_miltertest()

    headers = [
        ['Authentication-Results', 'example.com; arc=pass'],
        ['Authentication-Results', 'example.com; arc=fail'],
        *[x for x in res['headers'] if x[0] != 'Authentication-Results'],
    ]
    res = run_miltertest(headers)

    assert res['headers'][0] == ['Authentication-Results', ' example.com; arc=pass header.oldest-pass=0 smtp.remote-ip=127.0.0.1']
    assert 'cv=pass' in res['headers'][1][1]
    assert res['headers'][3] == ['ARC-Authentication-Results', ' i=2; example.com; arc=pass']


def test_milter_seal_failed(run_miltertest):
    """The seal for failed chains only covers the set from the sealer"""
    res = run_miltertest()

    # override the result to "fail"
    headers = res['headers']
    headers[0][1] = 'example.com; arc=fail'
    res1 = run_miltertest(headers)

    # mess with the seal
    headers[1][1] = 'foo'
    res2 = run_miltertest(headers)

    assert res1['headers'] == res2['headers']


def test_milter_duplicate_header(run_miltertest):
    """A set consists of exactly three headers with a given instance value"""
    res = run_miltertest()

    headers = [x for x in res['headers'] if x[0] != 'Authentication-Results']
    headers.append(headers[0])

    res = run_miltertest(headers)
    assert 'cv=fail' in res['headers'][1][1]


def test_milter_idna(run_miltertest):
    """U-labels in domains and selectors"""
    res = run_miltertest(
        [
            ['Authentication-Results', ' 시험.example.com; spf=pass smtp.mailfrom=привіт@시험.example.com'],
        ]
    )

    assert res['headers'][1][1].startswith(' i=1; d=시험.example.com; s=예;')
    assert res['headers'][2][1] == ' i=1; 시험.example.com; spf=pass smtp.mailfrom=привіт@시험.example.com;\n\tarc=none smtp.remote-ip=127.0.0.1'

    res = run_miltertest(res['headers'])
    assert 'cv=pass' in res['headers'][0][1]
    assert res['headers'][2] == ['ARC-Authentication-Results', ' i=2; 시험.example.com; arc=pass header.oldest-pass=0 smtp.remote-ip=127.0.0.1']


def test_milter_oldest_pass(run_miltertest):
    """oldest-pass points at the most recent message modification"""
    res = run_miltertest()

    headers = res['headers']
    res = run_miltertest(headers, body='second test body\r\n')

    # This doesn't have an oldest-pass because verification failed and was
    # overridden by A-R. In this situation we could try to parse it from A-R,
    # but currently that is not done.
    assert res['headers'][3] == ['ARC-Authentication-Results', ' i=2; example.com; arc=pass smtp.remote-ip=127.0.0.1']

    headers = [x for x in res['headers'] + headers if x[0] != 'Authentication-Results']

    res = run_miltertest(headers, body='second test body\r\n')

    assert res['headers'][3] == ['ARC-Authentication-Results', ' i=3; example.com; arc=pass header.oldest-pass=2 smtp.remote-ip=127.0.0.1']


def test_milter_authresip(run_miltertest):
    """AuthResIP false disables smtp.remote-ip"""
    res = run_miltertest()
    assert res['headers'][0][1] == ' example.com; arc=none'
    assert res['headers'][3][1] == ' i=1; example.com; arc=none'


def test_milter_finalreceiver(run_miltertest):
    """FinalReceiver adds arc.chain"""
    headers = []
    for i in range(0, 3):
        res = run_miltertest(headers)
        headers = [*res['headers'], *headers]

    assert res['headers'][0][1] == ' example.com; arc=pass header.oldest-pass=0 smtp.remote-ip=127.0.0.1 arc.chain="example.com:example.com"'


def test_milter_maximumheaders(run_miltertest):
    """Oversized headers result in message rejection"""
    with pytest.raises(miltertest.MilterError, match="Unexpected reply to L: \\('r'"):
        run_miltertest()


def test_milter_minimum_key_bits(run_miltertest):
    """A 2048-bit key passes when that is the minimum"""
    res = run_miltertest()
    res = run_miltertest(res['headers'])
    assert 'cv=pass' in res['headers'][0][1]


def test_milter_minimum_key_bits_fail(run_miltertest):
    """A 2048-bit key fails when the minimum is 2049"""
    res = run_miltertest()
    res = run_miltertest(res['headers'])
    assert 'cv=fail' in res['headers'][0][1]


def test_milter_peerlist(run_miltertest):
    """Connections from peers just get `accept` back immediately"""
    with pytest.raises(miltertest.MilterError, match='unexpected response: a'):
        run_miltertest()


def test_milter_responsedisabled(run_miltertest):
    """Configured to reject messages from peers"""
    with pytest.raises(miltertest.MilterError, match='unexpected response: r'):
        run_miltertest()


def test_milter_responseunwilling(run_miltertest):
    """Configured to accept messages with too many headers"""
    with pytest.raises(miltertest.MilterError, match="Unexpected reply to L: \\('a'"):
        run_miltertest()


def test_milter_signaturettl(run_miltertest):
    """Setting a TTL tags AMS with x="""
    ttl_res = run_miltertest()

    assert 'x=1234567895' in ttl_res['headers'][2][1]

    res = run_miltertest(ttl_res['headers'], milter_instance=1)
    assert 'cv=pass' in res['headers'][1][1]

    res = run_miltertest(ttl_res['headers'], milter_instance=2)
    assert 'cv=fail' in res['headers'][1][1]


def test_milter_softwareheader(run_miltertest):
    """Advertise software name, version"""
    res = run_miltertest()

    assert res['headers'][0][0] == 'ARC-Filter'
    assert res['headers'][0][1].startswith(' OpenARC Filter v')
