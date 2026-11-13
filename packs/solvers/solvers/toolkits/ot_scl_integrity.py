#!/usr/bin/env python3
"""Offline IEC 61850 SCL semantic integrity, diff, and GOOSE/SV correlation.

Extends ics_vendor_devices inventory and power_iec61850 decoding. This is a
communication-model projection, not XSD conformance or XML signature C14N.
FCDA order is significant; independent declarations and XML formatting are not.
No schemas, entities, network resources, or captured code are fetched/executed.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from functools import wraps
import hashlib
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

import ics_vendor_devices as vendor
import power_iec61850 as power
from ics_capture import iter_capture

MAX_INPUT = vendor.MAX_INPUT
MAX_RECORDS = 20000
MAX_FRAMES = 4096
MAX_CAPTURE = 64 << 20
MAX_OUTPUT = 32 << 20
SCL_NS = 'http://www.iec.ch/61850/2003/SCL'
_CORE = {'SCL', 'IED', 'AccessPoint', 'Server', 'LDevice', 'LN', 'LN0',
         'DataSet', 'FCDA', 'GSEControl', 'SampledValueControl', 'ReportControl',
         'Communication', 'SubNetwork', 'ConnectedAP', 'GSE', 'SMV', 'Address', 'P',
         'DataTypeTemplates', 'LNodeType', 'DOType', 'DAType', 'EnumType', 'DO',
         'SDO', 'DA', 'BDA', 'EnumVal', 'Inputs', 'ExtRef'}
_CONTEXT = ('ied', 'ap', 'ld', 'ln')


class SclError(ValueError):
    """Malformed, unsupported, ambiguous-to-parse, or excessive input."""


def _guard(fn):
    @wraps(fn)
    def checked(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except SclError:
            raise
        except Exception as exc:
            raise SclError(f'{fn.__name__}: {type(exc).__name__}: {exc}') from None
    return checked


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def _key(*parts):
    return _json(list(parts))


def _ctx(rec, count=4):
    return tuple(rec.get(k, '') for k in _CONTEXT[:count])


def _number(value, base=10, maximum=0xffffffff):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-fA-F]+' if base == 16 else '[0-9]+', value):
        raise SclError('invalid unsigned SCL number')
    if len(value) > 16:
        raise SclError('SCL number exceeds length cap')
    number = int(value, base)
    if number > maximum:
        raise SclError('SCL number exceeds range')
    return number


class _NamespaceTree(vendor._Tree):
    def start(self, tag, attrs):
        local = tag.rsplit('}', 1)[-1]
        namespace = tag[1:].split('}', 1)[0] if tag.startswith('{') else ''
        if self.depth == 0:
            self.namespace = namespace
        if local in _CORE and (namespace not in ('', SCL_NS) or namespace != self.namespace):
            raise SclError('foreign namespace shadows an SCL semantic element')
        for name in ('name', 'id', 'inst'):
            if any(c in attrs.get(name, '') for c in '/[]'):
                raise SclError('unsupported delimiter in SCL identifier')
        return super().start(tag, attrs)


def _inventory(data):
    if not isinstance(data, (bytes, str)) or len(data) > MAX_INPUT:
        raise SclError('SCL input must be bounded bytes or text')
    # Reuse the baseline's bounded, DTD-denying parser for QName checks too.
    root = ET.fromstring(data, parser=ET.XMLParser(target=_NamespaceTree()))
    if root.tag not in ('SCL', '{' + SCL_NS + '}SCL'):
        raise SclError('expected SCL root')
    inventory = vendor.parse(data, kind='scl')
    if len(inventory['records']) > MAX_RECORDS:
        raise SclError('semantic record cap exceeded')
    return inventory


def _canonical(data):
    inv = _inventory(data)
    records = inv['records']
    datasets_by_path = {row['path']: row for row in inv['datasets']}
    children = defaultdict(list)
    for rec in records:
        children[rec['path'].rsplit('/', 1)[0]].append(rec)
    model = {name: [] for name in ('ieds', 'access_points', 'connected_aps', 'logical_devices',
             'logical_nodes', 'datasets', 'controls', 'endpoints', 'templates', 'external_references')}
    domains = defaultdict(list)
    for rec in records:
        attrs, tag = rec['attributes'], rec['tag']
        context = dict(zip(_CONTEXT, _ctx(rec)))
        if tag == 'IED':
            model['ieds'].append({'key': _key(rec.get('ied', '')), 'attributes': attrs})
        elif tag == 'AccessPoint':
            model['access_points'].append({'key': _key(*_ctx(rec, 2)), 'attributes': attrs})
        elif tag == 'ConnectedAP':
            model['connected_aps'].append({'key': _key(rec.get('network', ''), *_ctx(rec, 2)),
                                          'ied': rec.get('ied', ''), 'ap': rec.get('ap', ''), 'attributes': attrs})
        elif tag == 'LDevice':
            domain = attrs.get('ldName') or rec.get('ied', '') + rec.get('ld', '')
            domains[_ctx(rec, 3)].append(domain)
            model['logical_devices'].append({'key': _key(*_ctx(rec, 3)), 'domain': domain, 'attributes': attrs})
        elif tag in ('LN', 'LN0'):
            normalized = {'prefix': '', 'inst': '', **attrs}
            model['logical_nodes'].append({'key': _key(*_ctx(rec)), **context, 'attributes': normalized})
        elif tag in ('LNodeType', 'DOType', 'DAType', 'EnumType'):
            entries = [{'kind': c['tag'], 'attributes': c['attributes'], 'text': c['text']}
                       for c in children[rec['path']]]
            # Type member order can determine the structure on the wire. Only
            # independent type declarations, not their members, are sorted.
            model['templates'].append({'key': _key(tag, attrs.get('id', '')), 'kind': tag,
                                       'attributes': attrs, 'children': entries})

    for rec in records:
        attrs, tag = rec['attributes'], rec['tag']
        context = dict(zip(_CONTEXT, _ctx(rec)))
        candidates = domains.get(_ctx(rec, 3), [])
        # Duplicates are reported by validation; do not select one arbitrarily.
        domain = candidates[0] if len(candidates) == 1 else None
        if tag == 'DataSet':
            members = []
            for member in datasets_by_path[rec['path']]['members']:
                members.append({'prefix': '', 'lnInst': '', 'daName': '', **member})
            name = attrs.get('name', '')
            model['datasets'].append({'key': _key(*_ctx(rec), name), **context,
                'attributes': attrs, 'members': members,
                'reference': f"{domain}/{context['ln']}${name}" if domain is not None else None})
        elif tag in ('GSEControl', 'SampledValueControl', 'ReportControl'):
            name = attrs.get('name', '')
            functional = {'GSEControl': 'GO', 'SampledValueControl': 'MS',
                          'ReportControl': 'BR' if attrs.get('buffered') in ('true', '1') else 'RP'}[tag]
            normalized = dict(attrs)
            for number in ('confRev', 'smpRate', 'nofASDU'):
                if number in attrs:
                    normalized[number] = _number(attrs[number])
            if tag == 'GSEControl':
                normalized.setdefault('type', 'GOOSE')
            elif tag == 'SampledValueControl':
                normalized.setdefault('smpMod', 'SmpPerPeriod')
            model['controls'].append({'key': _key(*_ctx(rec), tag, name), **context, 'kind': tag,
                'attributes': normalized, 'dataset_key': _key(*_ctx(rec), attrs.get('datSet', '')),
                'reference': f"{domain}/{context['ln']}${functional}${name}" if domain is not None else None,
                'conf_revision': _number(attrs['confRev']) if 'confRev' in attrs else None})
        elif tag in ('GSE', 'SMV'):
            addresses = []
            for child in children[rec['path']]:
                if child['tag'] == 'Address':
                    addresses.extend(c for c in children[child['path']] if c['tag'] == 'P')
            params = {}
            for address in addresses:
                kind, value = address['attributes'].get('type', ''), address['text']
                if kind in params:
                    raise SclError('duplicate Address/P parameter')
                if kind == 'APPID':
                    value = _number(value, 16, 0xffff)
                elif kind == 'VLAN-ID':
                    value = _number(value, 16, 0xfff)
                elif kind == 'VLAN-PRIORITY':
                    value = _number(value, 10, 7)
                elif kind == 'MAC-Address':
                    if not re.fullmatch(r'[0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5}', value):
                        raise SclError('invalid destination MAC address')
                    value = value.replace('-', ':').lower()
                params[kind] = value
            endpoint = {'key': _key(rec.get('network', ''), rec.get('ied', ''), rec.get('ap', ''),
                         tag, attrs.get('ldInst', ''), attrs.get('cbName', '')),
                        'network': rec.get('network', ''), 'ied': rec.get('ied', ''), 'ap': rec.get('ap', ''),
                        'kind': tag, 'ld': attrs.get('ldInst', ''), 'control': attrs.get('cbName', ''),
                        'attributes': attrs, 'address': params}
            model['endpoints'].append(endpoint)
        elif tag == 'ExtRef':
            model['external_references'].append({'key': _key(*_ctx(rec), _json(attrs)),
                                                  **context, 'attributes': attrs})
    for rows in model.values():
        rows.sort(key=_json)
    if len(_json(model)) > MAX_OUTPUT:
        raise SclError('semantic output cap exceeded')
    return model


def _index(rows):
    result = defaultdict(list)
    for row in rows:
        result[row['key']].append(row)
    return result


def _validate(model):
    findings = []
    finding_size = 0

    def issue(code, path, **details):
        nonlocal finding_size
        if len(findings) >= MAX_RECORDS:
            raise SclError('finding count exceeds cap')
        item = {'code': code, 'path': path, 'details': details}
        finding_size += len(_json(item))
        if finding_size > MAX_OUTPUT:
            raise SclError('finding output exceeds cap')
        findings.append(item)

    indices = {section: _index(rows) for section, rows in model.items()}
    control_index = _controls_index(model)
    nodes_by_source = defaultdict(list)
    child_index = {}
    for node in model['logical_nodes']:
        nodes_by_source[(node['ied'], node['ld'], node['ln'])].append(node)
    for row in model['templates']:
        members = defaultdict(list)
        for child in row['children']:
            members[(child['kind'], child['attributes'].get('name'))].append(child)
        child_index[row['key']] = members
    for section, index in indices.items():
        for key, rows in index.items():
            if len(rows) > 1:
                issue('duplicate-identity', key, section=section, count=len(rows))

    def resolve(section, key, code, path):
        rows = indices[section].get(key, [])
        if len(rows) != 1:
            issue('ambiguous-reference' if rows else code, path, target=key, section=section)
            return None
        return rows[0]

    def template(kind, ident, path):
        return resolve('templates', _key(kind, ident), 'unresolved-type', path)

    for node in model['logical_nodes']:
        template('LNodeType', node['attributes'].get('lnType', ''), node['key'])
    for row in model['templates']:
        for child in row['children']:
            attrs, kind = child['attributes'], child['kind']
            target = 'DOType' if kind in ('DO', 'SDO') else ('DAType' if attrs.get('bType') == 'Struct'
                                                       else 'EnumType' if attrs.get('bType') == 'Enum' else None)
            if target:
                template(target, attrs.get('type', ''), row['key'])

    fc_cache, fc_visiting = {}, set()
    fc_budget = [MAX_RECORDS * 8]

    def functional_constraints(current, path, depth=0):
        key = current['key']
        if key in fc_cache:
            return fc_cache[key]
        if key in fc_visiting:
            issue('cyclic-type-reference', path, target=key)
            return set()
        if depth >= vendor.MAX_DEPTH:
            raise SclError('data-object type depth exceeds cap')
        fc_visiting.add(key)
        values = set()
        for child in current['children']:
            fc_budget[0] -= 1
            if fc_budget[0] < 0:
                raise SclError('data-object traversal exceeds cap')
            if child['kind'] == 'DA' and child['attributes'].get('fc'):
                values.add(child['attributes']['fc'])
            elif child['kind'] == 'SDO':
                target = template('DOType', child['attributes'].get('type', ''), path)
                if target is not None:
                    values.update(functional_constraints(target, path, depth + 1))
        fc_visiting.remove(key)
        fc_cache[key] = values
        return values

    def data_ref(member, context, path):
        # Partial FCDA/ExtRef forms describe groups or engineering-time bindings.
        # Do not fabricate a single target or expand an unspecified group.
        if not member.get('lnClass') or not member.get('ldInst') or not member.get('doName'):
            issue('partial-data-reference', path, reference=member)
            return
        ln = member.get('prefix', '') + member['lnClass'] + member.get('lnInst', '')
        node = resolve('logical_nodes', _key(context['ied'], context['ap'], member['ldInst'], ln),
                       'unresolved-logical-node', path)
        if node is None:
            return
        current = template('LNodeType', node['attributes'].get('lnType', ''), path)
        if current is None:
            return
        for part in member['doName'].split('.'):
            members = child_index[current['key']]
            children = members.get(('DO', part), []) + members.get(('SDO', part), [])
            if len(children) != 1:
                issue('ambiguous-reference' if children else 'unresolved-data-object', path, name=part)
                return
            current = template('DOType', children[0]['attributes'].get('type', ''), path)
            if current is None:
                return
        da = member.get('daName', '')
        if not da:  # FCD references the entire data object for the given FC.
            if member.get('fc') and member['fc'] not in functional_constraints(current, path):
                issue('unresolved-functional-constraint', path, fc=member['fc'])
            return
        for i, part in enumerate(da.split('.')):
            members = child_index[current['key']]
            children = members.get(('DA', part), []) + members.get(('BDA', part), [])
            if len(children) != 1:
                issue('ambiguous-reference' if children else 'unresolved-data-attribute', path, name=part)
                return
            child = children[0]['attributes']
            if i == 0 and member.get('fc') and child.get('fc') != member['fc']:
                issue('unresolved-functional-constraint', path, expected=child.get('fc'), actual=member['fc'])
            if i < len(da.split('.')) - 1:
                if child.get('bType') != 'Struct':
                    issue('unresolved-data-attribute', path, name=da)
                    return
                current = template('DAType', child.get('type', ''), path)
                if current is None:
                    return

    for dataset in model['datasets']:
        for i, member in enumerate(dataset['members']):
            data_ref(member, dataset, dataset['key'] + f'/FCDA[{i}]')
    for control in model['controls']:
        if control['attributes'].get('datSet'):
            resolve('datasets', control['dataset_key'], 'unresolved-dataset', control['key'])
    for row in model['external_references']:
        attrs = row['attributes']
        candidates = nodes_by_source.get((attrs.get('iedName'), attrs.get('ldInst'),
                     attrs.get('prefix', '') + attrs.get('lnClass', '') + attrs.get('lnInst', '')), [])
        if not attrs.get('iedName'):
            issue('partial-data-reference', row['key'], reference=attrs)
        elif len(candidates) != 1:
            issue('ambiguous-reference' if candidates else 'unresolved-logical-node', row['key'], reference=attrs)
        else:
            data_ref(attrs, candidates[0], row['key'])
            if attrs.get('srcCBName'):
                kind = {'GOOSE': 'GSEControl', 'SMV': 'SampledValueControl', 'Report': 'ReportControl'}.get(attrs.get('serviceType'))
                if kind:
                    source_ln = attrs.get('srcPrefix', '') + attrs.get('srcLNClass', 'LLN0') + attrs.get('srcLNInst', '')
                    resolve('controls', _key(attrs['iedName'], candidates[0]['ap'],
                            attrs.get('srcLDInst', attrs.get('ldInst', '')), source_ln, kind, attrs['srcCBName']),
                            'unresolved-control', row['key'])
                else:
                    issue('unsupported-source-service', row['key'], service=attrs.get('serviceType'))
    for connected in model['connected_aps']:
        resolve('access_points', _key(connected['ied'], connected['ap']), 'unresolved-access-point', connected['key'])
    for endpoint in model['endpoints']:
        resolve('access_points', _key(endpoint['ied'], endpoint['ap']), 'unresolved-access-point', endpoint['key'])
        controls = _endpoint_controls(control_index, endpoint)
        if len(controls) != 1:
            issue('ambiguous-reference' if controls else 'unresolved-control', endpoint['key'], count=len(controls))
    for parameter, code in (('APPID', 'duplicate-appid'), ('MAC-Address', 'duplicate-mac')):
        groups = defaultdict(list)
        for endpoint in model['endpoints']:
            if parameter in endpoint['address']:
                groups[(endpoint['network'], endpoint['address'][parameter])].append(endpoint['key'])
        for (network, value), keys in groups.items():
            if len(keys) > 1:
                issue(code, _key(network, value), endpoints=sorted(keys), value=value,
                      note='shared multicast destination' if parameter == 'MAC-Address' else 'shared transport APPID')
    return sorted(findings, key=_json)


def _controls_index(model):
    index = defaultdict(list)
    for row in model['controls']:
        if row['ln'] == 'LLN0':
            index[(row['kind'], row['ied'], row['ap'], row['ld'], row['attributes'].get('name'))].append(row)
    return index


def _endpoint_controls(index, endpoint):
    kind = 'GSEControl' if endpoint['kind'] == 'GSE' else 'SampledValueControl'
    return index.get((kind, endpoint['ied'], endpoint['ap'], endpoint['ld'], endpoint['control']), [])


@_guard
def canonicalize_scl(data):
    """Return deterministic semantic entities, preserving ordered FCDA members."""
    return _canonical(data)


@_guard
def analyze_scl(data):
    """Return semantic model, reproducible SHA256, and cross-reference findings."""
    model = _canonical(data)
    return {'canonical': model, 'sha256': hashlib.sha256(_json(model).encode()).hexdigest(),
            'findings': _validate(model)}


@_guard
def diff_scl(before, after):
    """Diff entity sets; members inside each dataset remain ordered."""
    left, right = analyze_scl(before), analyze_scl(after)
    changes = []
    for section in left['canonical']:
        old, new = _index(left['canonical'][section]), _index(right['canonical'][section])
        for key in sorted(old.keys() | new.keys()):
            if old.get(key, []) != new.get(key, []):
                changes.append({'section': section, 'key': key, 'before': old.get(key, []), 'after': new.get(key, [])})
    return {'equal': not changes, 'before_sha256': left['sha256'], 'after_sha256': right['sha256'],
            'changes': changes, 'before_findings': left['findings'], 'after_findings': right['findings']}


def _correlation_state(model):
    control_index = _controls_index(model)
    pairs, by_appid, by_ref = [], defaultdict(list), defaultdict(list)
    for endpoint in model['endpoints']:
        for control in _endpoint_controls(control_index, endpoint):
            if len(pairs) >= MAX_RECORDS:
                raise SclError('ambiguous endpoint expansion exceeds cap')
            number = len(pairs)
            pairs.append((endpoint, control))
            kind = endpoint['kind']
            if 'APPID' in endpoint['address']:
                by_appid[(kind, endpoint['address']['APPID'])].append(number)
            reference = control['reference'] if kind == 'GSE' else control['attributes'].get('smvID')
            if reference is not None:
                by_ref[(kind, reference)].append(number)
    return pairs, by_appid, by_ref, _index(model['datasets'])


def _correlate(state, frame, index):
    parsed = power.parse_frame(frame)
    kind = 'GSE' if parsed['protocol'] == 'iec61850-goose' else 'SMV'
    views = [parsed['fields']] if kind == 'GSE' else parsed['asdus']
    matches, findings, mapped = [], [], []
    pairs, by_appid, by_ref, datasets = state
    output_size = 0

    def add(destination, item):
        nonlocal output_size
        output_size += len(_json(item))
        if output_size > MAX_OUTPUT:
            raise SclError('frame correlation output cap exceeded')
        destination.append(item)

    for asdu_index, view in enumerate(views):
        # All positive selectors contribute candidates; conflicts are exposed,
        # never hidden by matching only the forged field.
        reference = view.get('gocb_ref') if kind == 'GSE' else view.get('sv_id')
        numbers = sorted(set(by_ref.get((kind, reference), [])) | set(by_appid.get((kind, parsed['appid']), [])))
        candidates = [pairs[number] for number in numbers]
        if len(candidates) != 1:
            add(findings, {'code': 'ambiguous-capture-match' if candidates else 'unmatched-capture',
                             'asdu': asdu_index, 'candidates': [x[0]['key'] for x in candidates]})
            continue
        endpoint, control = candidates[0]
        ds = datasets.get(control['dataset_key'], [])
        if len(ds) != 1:
            add(findings, {'code': 'ambiguous-dataset' if ds else 'unresolved-dataset', 'asdu': asdu_index,
                             'target': control['dataset_key']})
            continue
        dataset = ds[0]
        add(matches, {'asdu': asdu_index, 'endpoint': endpoint['key'], 'control': control['key'],
                        'dataset': dataset['key']})

        def compare(field, expected, actual):
            if expected is not None and expected != actual:
                add(findings, {'code': 'capture-field-mismatch', 'asdu': asdu_index, 'field': field,
                                 'expected': expected, 'actual': actual})

        compare('appid', endpoint['address'].get('APPID'), parsed['appid'])
        compare('destination', endpoint['address'].get('MAC-Address'), parsed['ethernet']['destination'])
        vlan = parsed['ethernet']['vlans'][-1] if parsed['ethernet']['vlans'] else {}
        compare('vlan_id', endpoint['address'].get('VLAN-ID'), vlan.get('id', 0))
        compare('vlan_priority', endpoint['address'].get('VLAN-PRIORITY'), vlan.get('priority'))
        compare('conf_revision', control['conf_revision'], view.get('conf_revision'))
        if kind == 'GSE':
            compare('gocb_ref', control['reference'], view.get('gocb_ref'))
            compare('dataset', dataset['reference'], view.get('dataset'))
            if 'go_id' in view:  # Optional wire GoID, distinct from Ethernet APPID.
                compare('go_id', control['attributes'].get('appID'), view['go_id'])
            compare('entry_count', len(dataset['members']), view.get('entry_count'))
            for i, value in enumerate(parsed['all_data']):
                add(mapped, {'asdu': asdu_index, 'index': i, 'dataset': dataset['key'],
                    'member': dataset['members'][i] if i < len(dataset['members']) else None, 'value': value})
        else:
            compare('sv_id', control['attributes'].get('smvID'), view.get('sv_id'))
            compare('asdu_count', control['attributes'].get('nofASDU'), parsed['asdu_count'])
            if 'sample_rate' in view:
                compare('sample_rate', control['attributes'].get('smpRate'), view['sample_rate'])
            if 'sample_mode' in view:
                mode = {'SmpPerPeriod': 0, 'SmpPerSec': 1, 'SecPerSmp': 2}.get(control['attributes'].get('smpMod'))
                compare('sample_mode', mode, view['sample_mode'])
            if 'dataset' in view:
                compare('dataset', dataset['reference'], view['dataset'])
            add(mapped, {'asdu': asdu_index, 'dataset': dataset['key'], 'members': dataset['members'],
                           'data_hex': view['data_hex'], 'encoding': 'opaque-seqData',
                           'note': 'SCL FCDA labels only; byte offsets/scales require an explicit SV layout'})
    return {'index': index, 'protocol': parsed['protocol'], 'matches': matches,
            'findings': findings, 'mapped_fields': mapped}


@_guard
def correlate_frames(scl, frames):
    """Correlate a bounded list of raw Ethernet GOOSE/SV frames with SCL."""
    if not isinstance(frames, (list, tuple)) or len(frames) > MAX_FRAMES:
        raise SclError('frames must be a bounded list/tuple')
    analysis = analyze_scl(scl)
    state = _correlation_state(analysis['canonical'])
    results, size = [], 0
    for i, frame in enumerate(frames):
        result = _correlate(state, frame, i)
        size += len(_json(result))
        if size > MAX_OUTPUT:
            raise SclError('capture output cap exceeded')
        results.append(result)
    return {'frames': results, 'findings': analysis['findings'], 'scl_sha256': analysis['sha256']}


@_guard
def correlate_capture(scl, capture):
    """Read local PCAP/PCAPNG bytes using ics_capture; ignore non-GOOSE/SV traffic."""
    if not isinstance(capture, bytes) or len(capture) > MAX_CAPTURE:
        raise SclError('capture must be bounded bytes')
    analysis = analyze_scl(scl)
    state = _correlation_state(analysis['canonical'])
    results, ignored, size = [], 0, 0
    for count, packet in enumerate(iter_capture(capture), 1):
        if count > MAX_FRAMES:
            raise SclError('capture packet cap exceeded')
        raw = packet['data']
        if packet['linktype'] != 1:
            ignored += 1
            continue
        if len(raw) < 14:
            raise SclError('truncated Ethernet header in capture')
        ethertype, at = int.from_bytes(raw[12:14], 'big'), 14
        while ethertype in (0x8100, 0x88a8, 0x9100):
            if at > 26 or at + 4 > len(raw):
                raise SclError('invalid captured VLAN header')
            ethertype = int.from_bytes(raw[at + 2:at + 4], 'big')
            at += 4
        if ethertype not in (0x88b8, 0x88ba):
            ignored += 1
            continue
        result = _correlate(state, raw, packet['index'])
        result['timestamp'] = packet['timestamp']
        size += len(_json(result))
        if size > MAX_OUTPUT:
            raise SclError('capture output cap exceeded')
        results.append(result)
    return {'frames': results, 'findings': analysis['findings'], 'scl_sha256': analysis['sha256'],
            'ignored_packets': ignored}


def _read(path, limit):
    with Path(path).open('rb') as handle:
        value = handle.read(limit + 1)
    if len(value) > limit:
        raise SclError('file exceeds input cap')
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('analyze', 'canonical'):
        commands.add_parser(name).add_argument('scl')
    diff = commands.add_parser('diff')
    diff.add_argument('before')
    diff.add_argument('after')
    correlation = commands.add_parser('correlate')
    correlation.add_argument('scl')
    correlation.add_argument('capture')
    correlation.add_argument('--frame', action='store_true', help='capture is one raw Ethernet frame')
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        if args.command == 'diff':
            report = diff_scl(_read(args.before, MAX_INPUT), _read(args.after, MAX_INPUT))
        elif args.command == 'correlate':
            scl = _read(args.scl, MAX_INPUT)
            raw = _read(args.capture, power.MAX_FRAME if args.frame else MAX_CAPTURE)
            report = correlate_frames(scl, [raw]) if args.frame else correlate_capture(scl, raw)
        else:
            report = (analyze_scl if args.command == 'analyze' else canonicalize_scl)(_read(args.scl, MAX_INPUT))
        print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True))
        return 0
    except (SclError, OSError, ValueError, TypeError) as exc:
        print(f'ot_scl_integrity: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
