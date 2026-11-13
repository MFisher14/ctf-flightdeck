import pytest
import pynmea2
import transport_nmea0183 as nmea


def sentence(body):
    checksum = 0
    for byte in body.encode('ascii'):
        checksum ^= byte
    return f'${body}*{checksum:02X}'


def test_published_trimble_gll_fix():
    # https://receiverhelp.trimble.com/alloy-gnss/en-us/NMEA-0183messages_GLL.html
    raw = '$GPGLL,3953.88008971,N,10506.75318910,W,034138.00,A,D*7A'
    actual = nmea.parse_sentence(raw)
    oracle = pynmea2.parse(raw, check=True)
    assert actual['latitude'] == pytest.approx(39 + 53.88008971/60)
    assert actual['longitude'] == pytest.approx(-(105 + 6.75318910/60))
    assert actual['latitude'] == pytest.approx(oracle.latitude)
    assert actual['longitude'] == pytest.approx(oracle.longitude)
    assert actual['valid'] is True
    assert actual['time_utc'] == '03:41:38.00'


def test_published_trimble_gst_zda():
    # Same vendor reference pages named NMEA-0183messages_GST.html / _ZDA.html.
    gst = nmea.parse_sentence('$GPGST,172814.0,0.006,0.023,0.020,273.6,0.023,0.020,0.031*6A')
    assert gst['rms_m'] == .006
    assert gst['altitude_sigma_m'] == .031
    # Vendor page contains an erroneous *45 checksum. Independent pynmea2
    # computes 0x57; reject original and test the corrected checksum.
    with pytest.raises(nmea.TransportNMEAError):
        nmea.parse_sentence('$GPZDA,172809.456,12,07,1996,00,00*45')
    assert pynmea2.NMEASentence.checksum('GPZDA,172809.456,12,07,1996,00,00') == 0x57
    zda = nmea.parse_sentence('$GPZDA,172809.456,12,07,1996,00,00*57')
    assert zda['date'] == '1996-07-12'
    assert zda['time_utc'] == '17:28:09.456'
    assert zda['local_offset_minutes'] == 0


def test_route_waypoint_velocity_heading():
    route = nmea.parse_sentence(sentence('GPRTE,2,1,c,ROUTE1,DOCK,PIER'))
    assert route['waypoints'] == ['DOCK','PIER']
    assert route['total_messages'] == 2
    raw = sentence('GPWPL,4917.16,N,12310.64,W,DOCK')
    actual = nmea.parse_sentence(raw)
    oracle = pynmea2.parse(raw, check=True)
    assert actual['latitude'] == pytest.approx(pynmea2.dm_to_sd(oracle.lat))
    assert actual['longitude'] == pytest.approx(-pynmea2.dm_to_sd(oracle.lon))
    assert actual['waypoint'] == 'DOCK'
    vtg = nmea.parse_sentence(sentence('GPVTG,054.7,T,034.4,M,005.5,N,010.2,K'))
    assert vtg['speed_knots'] == 5.5
    assert vtg['speed_kmh'] == 10.2
    assert nmea.parse_sentence(sentence('GPHDT,123.5,T'))['heading_deg'] == 123.5


def test_satellite_information():
    gsv = nmea.parse_sentence(sentence('GPGSV,2,1,05,01,40,083,41,02,17,273,35,03,13,172,,04,09,304,32,1'))
    assert gsv['satellites'][0] == {'prn':1,'elevation_deg':40,'azimuth_deg':83,'snr_db':41}
    assert gsv['satellites'][2]['snr_db'] is None
    assert gsv['signal_id'] == 1
    gsa = nmea.parse_sentence(sentence('GPGSA,A,3,04,05,,,,,,,,,,,1.8,1.0,1.5'))
    assert gsa['satellites'] == [4,5]
    assert gsa['pdop'] == 1.8


def test_void_and_empty_coordinate_are_explicit():
    record = nmea.parse_sentence(sentence('GPGLL,,,,,034138.00,V,N'))
    assert record['latitude'] is None
    assert record['longitude'] is None
    assert record['valid'] is False
    assert nmea.parse_sentence(sentence('GPZDA,172809,12,07,1996,-00,30'))['local_offset_minutes'] == -30


@pytest.mark.parametrize('body', ['GPGLL,9160,N,18100,E,250000,A', 'GPGLL,3960,N,10500,W,010101,A', 'GPHDT,nan,T', 'GPHDT,123,M', 'GPZDA,120000,31,02,2026,00,00', 'GPGSV,1,2,02,01,40,083,41', 'GPGSA,A,9,,,,,,,,,,,,,1,1,1', 'GPRTE,1,2,c,route', 'GPVTG,1,T,2,M,3,N,4,X'])
def test_malformed_contract(body):
    with pytest.raises(nmea.TransportNMEAError):
        nmea.parse_sentence(sentence(body))


@pytest.mark.parametrize('value', [None, 42, b'abc', [], 'junk'])
def test_bad_types(value):
    with pytest.raises(nmea.TransportNMEAError):
        nmea.parse_sentence(value)


def test_existing_sentences_not_rebuilt():
    assert nmea.parse_sentence(sentence('GPRMC,ignored')) is None
    assert nmea.parse_text('') == []
    with pytest.raises(nmea.TransportNMEAError):
        nmea.parse_text(None)


def test_cli_guard(tmp_path):
    assert nmea.main(['--help']) == 0
    assert nmea.main(['--unknown']) == 2
    assert nmea.main([str(tmp_path/'missing')]) == 2


def test_nul_path():
    assert nmea.main(['bad\x00path']) == 2


@pytest.mark.parametrize('body', ['GPGLL,,,,,123456,A,A', 'GPGLL,4807.038,N,01131.000,E,123456,A,BOGUS', 'GPVTG,1,T,2,M,3,N,4,K,BOGUS'])
def test_invalid_active_fix_and_modes(body):
    with pytest.raises(nmea.TransportNMEAError):
        nmea.parse_sentence(sentence(body))
