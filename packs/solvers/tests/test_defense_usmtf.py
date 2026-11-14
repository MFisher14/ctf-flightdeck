"""Published MCIP 3-03Di Appendix B sets and independent hand-built messages."""
import json
import random

import pytest
import defense_usmtf as d


def test_published_template():
    # Public USMC MCIP 3-03Di Appendix B: four template sets, no private data.
    msg = ('MSGID/GENADMIN/COMMARFORXXX/-/MONTH//\n'
           'SUBJ/SHORT DESCRIPTIVE SUBJ LINE//\n'
           'REF/A/ORDER/COMMAND/DTG (CLASSIFICATION)//\n'
           'REF/B/RFF/CDRXXXCOM/DTG (CLASSIFICATION)//')
    out = d.parse_usmtf(msg)
    assert out['message_type'] == 'GENADMIN'
    assert [s['name'] for s in out['sets']] == ['MSGID', 'SUBJ', 'REF', 'REF']
    assert out['sets'][0]['fields'] == ['GENADMIN', 'COMMARFORXXX', '-', 'MONTH']
    assert out['sets'][3]['fields'][0] == 'B'


def test_folding_envelope_and_narrative():
    msg = ('R 061300Z NOV 26\r\nFM EXERCISE\r\nTO RECIPIENT\r\nBT\r\nUNCLAS\r\n'
           'EXER/TOTAL WARFARE//\r\nMSGID/GENADMIN,USMTF,2007/EXERCISE//\n'
           'GENTEXT/REMARKS/A story\ncontinued/path CSCTF{FromBytes}//\nBT\nNNNN')
    out = d.parse_usmtf(msg.encode())
    assert out['envelope'].startswith('R 061300Z')
    assert out['message_type'] == 'GENADMIN,USMTF,2007'
    assert out['sets'][2]['text'] == 'A story continued/path CSCTF{FromBytes}'
    assert '\ncontinued' in out['sets'][2]['raw']
    assert out['trailer'] == 'BT\nNNNN'
    assert out['flags'] == ['CSCTF{FromBytes}']


@pytest.mark.parametrize('value', [None, 1, True, [], {}, b'\xff', '\ud800',
    '', 'hello', 'MSGID/GENADMIN', 'MSGID/GENADMIN//junk',
    'MSGID///', 'MSGID/X//MSGID/Y//', 'EXER/X//',
    'MSGID/X//GENTEXT/LABEL//', 'MSGID/X////',
    'MSGID/X//bad/field//', 'MSGID/X//SUBJ/\0//',
    'EXER/X//REF/A//MSGID/X//', 'prefix MSGID/X//\nMSGID/Y//'])
def test_malformed(value):
    with pytest.raises(d.DefenseUSMTFError):
        d.parse_usmtf(value)


def test_no_false_flag_assembly():
    out = d.parse_usmtf('MSGID/X//GENTEXT/REMARKS/CSCTF{one\ntwo}//')
    assert out['flags'] == []  # never reshape recovered bytes into a new flag


def test_caps(monkeypatch):
    monkeypatch.setattr(d, 'MAX_SETS', 1)
    with pytest.raises(d.DefenseUSMTFError):
        d.parse_usmtf('MSGID/X//REF/A//')
    monkeypatch.setattr(d, 'MAX_FIELDS', 1)
    with pytest.raises(d.DefenseUSMTFError):
        d.parse_usmtf('MSGID/X/Y//')
    monkeypatch.setattr(d, 'MAX_BYTES', 10)
    with pytest.raises(d.DefenseUSMTFError):
        d.parse_usmtf('MSGID/' + 'x' * 11)


def test_noise():
    rng = random.Random(6040)
    for _ in range(300):
        try:
            d.parse_usmtf(rng.randbytes(rng.randrange(200)))
        except d.DefenseUSMTFError:
            pass


def test_cli(tmp_path, capsys):
    assert d.main([]) == 2
    assert d.main(['--help']) == 0
    assert d.main([str(tmp_path / 'missing')]) == 2
    path = tmp_path / 'message.txt'
    path.write_text('MSGID/GENADMIN//')
    capsys.readouterr()
    assert d.main([str(path)]) == 0
    assert json.loads(capsys.readouterr().out)['message_type'] == 'GENADMIN'
