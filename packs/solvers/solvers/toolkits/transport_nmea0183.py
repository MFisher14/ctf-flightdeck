"""Offline NMEA-0183 navigation depth beyond existing GGA/RMC support.

Strict checksummed GLL, WPL, RTE, VTG, ZDA, GSA, GSV, GST, HDT sentences.
Unknown sentence types return None; known malformed records raise the declared
error. This does not authenticate a fix or prove/disprove GPS spoofing.
Reference: https://receiverhelp.trimble.com/oem-gnss/nmea0183-messages-overview.html
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import re
import sys
from pathlib import Path


class TransportNMEAError(ValueError):
    """Invalid NMEA envelope or navigation data."""


_MAX_INPUT = 16 * 1024 * 1024
_SUPPORTED = {'GLL', 'WPL', 'RTE', 'VTG', 'ZDA', 'GSA', 'GSV', 'GST', 'HDT'}


def _number(value, low=None, high=None):
    if not value:
        return None
    result = float(value)
    if not math.isfinite(result) or (low is not None and result < low) or (high is not None and result > high):
        raise TransportNMEAError('numeric field outside its valid range')
    return result


def _integer(value, low, high, optional=False):
    if optional and value == '':
        return None
    if not re.fullmatch(r'[0-9]+', value):
        raise TransportNMEAError('invalid integer field')
    result = int(value)
    if not low <= result <= high:
        raise TransportNMEAError('integer outside its valid range')
    return result


def _time(value):
    if not value:
        return None
    if not re.fullmatch(r'\d{6}(?:\.\d+)?', value):
        raise TransportNMEAError('invalid UTC time')
    hour, minute, second = int(value[:2]), int(value[2:4]), float(value[4:])
    if hour > 23 or minute > 59 or second >= 61:
        raise TransportNMEAError('invalid UTC time')
    return f'{value[:2]}:{value[2:4]}:{value[4:]}'


def _coordinate(value, hemisphere, latitude):
    if not value and not hemisphere:
        return None
    digits = 4 if latitude else 5
    if not re.fullmatch(r'\d{' + str(digits) + r'}(?:\.\d+)?', value):
        raise TransportNMEAError('invalid coordinate shape')
    allowed = 'NS' if latitude else 'EW'
    if hemisphere not in allowed or len(hemisphere) != 1:
        raise TransportNMEAError('invalid hemisphere')
    degrees = int(value[:digits - 2])
    minutes = float(value[digits - 2:])
    limit = 90 if latitude else 180
    if minutes >= 60 or degrees > limit or (degrees == limit and minutes):
        raise TransportNMEAError('coordinate outside globe')
    return (degrees + minutes / 60) * (-1 if hemisphere in 'SW' else 1)


def _count(fields, low, high=None):
    if not low <= len(fields) <= (low if high is None else high):
        raise TransportNMEAError('wrong field count')


def parse_sentence(line: str) -> dict | None:
    """Decode one navigation sentence; GGA/RMC stay in transport.py."""
    try:
        return _parse_sentence(line)
    except TransportNMEAError:
        raise
    except (ValueError, TypeError, IndexError, KeyError, OverflowError) as exc:
        raise TransportNMEAError(f'invalid navigation record: {type(exc).__name__}') from exc


def _parse_sentence(line):
    if not isinstance(line, str) or len(line) > 1024:
        raise TransportNMEAError('sentence must be text of at most 1024 characters')
    match = re.fullmatch(r'\$([A-Z]{2})([A-Z]{3}),([ -~]*)\*([0-9A-Fa-f]{2})', line.strip())
    if not match:
        raise TransportNMEAError('invalid checksummed NMEA envelope')
    talker, kind, body, checksum = match.groups()
    if '*' in body or '$' in body:
        raise TransportNMEAError('embedded NMEA delimiter')
    actual = 0
    for char in talker + kind + ',' + body:
        actual ^= ord(char)
    if actual != int(checksum, 16):
        raise TransportNMEAError('NMEA checksum mismatch')
    if kind not in _SUPPORTED:
        return None
    f = body.split(',')
    out = {'talker': talker, 'sentence': kind, 'checksum_ok': True}
    if kind in ('GLL', 'WPL'):
        _count(f, 6, 7) if kind == 'GLL' else _count(f, 5)
        out.update(latitude=_coordinate(f[0], f[1], True), longitude=_coordinate(f[2], f[3], False))
        if kind == 'WPL':
            out['waypoint'] = f[4]
        else:
            if f[5] not in ('A', 'V'):
                raise TransportNMEAError('invalid GLL status')
            mode = f[6] if len(f) > 6 else None
            if mode is not None and mode not in ('A', 'D', 'E', 'F', 'M', 'N', 'P', 'R', 'S'):
                raise TransportNMEAError('invalid GLL mode')
            if f[5] == 'A' and (out['latitude'] is None or out['longitude'] is None):
                raise TransportNMEAError('active GLL fix lacks coordinates')
            out.update(time_utc=_time(f[4]), valid=f[5] == 'A', mode=mode)
    elif kind == 'VTG':
        _count(f, 8, 9)
        if f[1] != 'T' or f[3] != 'M' or f[5] != 'N' or f[7] != 'K':
            raise TransportNMEAError('invalid VTG units')
        if len(f) == 9 and f[8] not in ('A', 'D', 'E', 'F', 'M', 'N', 'P', 'R', 'S'):
            raise TransportNMEAError('invalid VTG mode')
        out.update(course_true_deg=_number(f[0], 0, 360), course_magnetic_deg=_number(f[2], 0, 360),
                   speed_knots=_number(f[4], 0), speed_kmh=_number(f[6], 0), mode=f[8] if len(f) == 9 else None)
    elif kind == 'ZDA':
        _count(f, 6)
        date = dt.date(_integer(f[3], 1, 9999), _integer(f[2], 1, 12), _integer(f[1], 1, 31))
        hours = int(f[4])
        minutes = _integer(f[5], 0, 59)
        if abs(hours) > 13 or not re.fullmatch(r'[+-]?\d{2}', f[4]):
            raise TransportNMEAError('invalid local zone offset')
        offset = (abs(hours) * 60 + minutes) * (-1 if f[4].startswith('-') else 1)
        out.update(date=date.isoformat(), time_utc=_time(f[0]), local_offset_minutes=offset)
    elif kind == 'HDT':
        _count(f, 2)
        if f[1] != 'T':
            raise TransportNMEAError('HDT must use true north')
        out['heading_deg'] = _number(f[0], 0, 360)
    elif kind == 'GST':
        _count(f, 8)
        out['time_utc'] = _time(f[0])
        names = ('rms_m', 'semimajor_m', 'semiminor_m', 'orientation_deg', 'latitude_sigma_m', 'longitude_sigma_m', 'altitude_sigma_m')
        out.update({name: _number(value, 0, 360 if name == 'orientation_deg' else None) for name, value in zip(names, f[1:])})
    elif kind == 'GSA':
        _count(f, 17, 18)
        if f[0] not in ('A', 'M'):
            raise TransportNMEAError('invalid GSA mode')
        out.update(mode=f[0], fix_dimension=_integer(f[1], 1, 3),
                   satellites=[_integer(value, 1, 999) for value in f[2:14] if value],
                   pdop=_number(f[14], 0), hdop=_number(f[15], 0), vdop=_number(f[16], 0))
        if len(f) == 18:
            out['system_id'] = _integer(f[17], 1, 9, optional=True)
    elif kind == 'GSV':
        if len(f) < 3 or len(f) > 20:
            raise TransportNMEAError('invalid GSV field count')
        total, number, count = _integer(f[0], 1, 9), _integer(f[1], 1, 9), _integer(f[2], 0, 99)
        if number > total:
            raise TransportNMEAError('invalid GSV fragment index')
        rest = f[3:]
        signal = None
        if len(rest) % 4 == 1:
            signal = _integer(rest[-1], 0, 9, optional=True)
            rest = rest[:-1]
        if len(rest) % 4 or len(rest) > 16:
            raise TransportNMEAError('incomplete GSV satellite block')
        satellites = []
        for index in range(0, len(rest), 4):
            block = rest[index:index + 4]
            if not any(block):
                continue
            satellites.append({'prn': _integer(block[0], 1, 999), 'elevation_deg': _integer(block[1], 0, 90, True),
                               'azimuth_deg': _integer(block[2], 0, 359, True), 'snr_db': _integer(block[3], 0, 99, True)})
        out.update(total_messages=total, message_number=number, satellites_in_view=count, satellites=satellites, signal_id=signal)
    elif kind == 'RTE':
        if len(f) < 4:
            raise TransportNMEAError('short route sentence')
        total, number = _integer(f[0], 1, 99), _integer(f[1], 1, 99)
        if number > total or f[2] not in ('c', 'w'):
            raise TransportNMEAError('invalid route fragment or mode')
        out.update(total_messages=total, message_number=number, mode=f[2], route_id=f[3], waypoints=f[4:])
    return out


def parse_text(text: str) -> list[dict]:
    """Decode saved NMEA lines, preserving fragment metadata without inventing joins."""
    if not isinstance(text, str) or len(text) > _MAX_INPUT:
        raise TransportNMEAError('input must be text of at most 16 MiB')
    output = []
    for line in text.splitlines():
        if line.strip():
            record = parse_sentence(line)
            if record is not None:
                output.append(record)
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', help='saved checksummed NMEA text file')
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with Path(args.file).open('rb') as handle:
            data = handle.read(_MAX_INPUT + 1)
        if len(data) > _MAX_INPUT:
            raise TransportNMEAError('input exceeds 16 MiB')
        print(json.dumps(parse_text(data.decode('ascii')), indent=2))
        return 0
    except (ValueError, OSError, UnicodeError) as exc:
        print(f'transport_nmea0183: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
