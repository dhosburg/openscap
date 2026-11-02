#!/usr/bin/env python3
#This script was built with extensive help from LLMs
"""Extract failed OpenSCAP rules and map them to NIST 800-53 controls."""
import csv
import sys
import xml.etree.ElementTree as ET


def local(tag):
    """Strip the XML namespace, leaving only local element name."""
    return tag.rpartition('}')[2]


def read_results(path):
    """rule_id -> verdict, from the XCCDF results file."""
    results = {}
    for el in ET.parse(path).iter():
        if local(el.tag) != 'rule-result':
            continue
        idref = el.get('idref')
        if not idref:
            continue
        verdict = ''
        for child in el:
            if local(child.tag) == 'result':
                verdict = (child.text or '').strip()
                break
        results[idref] = verdict
    return results


def read_rule_metadata(path, wanted):
    """rule_id -> {title, severity, controls} for the rules in `wanted`."""
    meta = {}
    for el in ET.parse(path).iter():
        if local(el.tag) != 'Rule':
            continue
        rid = el.get('id')
        if rid not in wanted:
            continue
        title, controls = '', []
        for child in el:
            name = local(child.tag)
            if name == 'title' and not title:
                title = ' '.join(''.join(child.itertext()).split())
            elif name == 'reference' and '800-53' in child.get('href', ''):
                text = ''.join(child.itertext()).strip()
                if text:
                    controls.append(text)
        meta[rid] = {
            'title': title,
            'severity': el.get('severity', ''),
            'controls': sorted(set(controls)),
        }
    return meta


def families(controls):
    """AC-2(1) -> AC. Gives you the control-family grouping."""
    return sorted({c.split('-')[0].strip().upper() for c in controls if '-' in c})


def main():
    if len(sys.argv) != 4:
        sys.exit('usage: map_controls.py <results.xml> <datastream.xml> <out.csv>')
    results_path, ds_path, out_path = sys.argv[1:4]

    results = read_results(results_path)
    failed = {rid for rid, verdict in results.items() if verdict == 'fail'}
    if not failed:
        sys.exit('No failed rules found — check that you passed the results file.')

    meta = read_rule_metadata(ds_path, failed)

    rows = 0
    unmapped = 0
    with open(out_path, 'w', newline='') as fh:
        writer = csv.writer(fh)
        writer.writerow([
            'rule_id', 'severity', 'result',
            'nist_800_53_control', 'control_family', 'title', 'risk_note',
        ])
        for rid in sorted(failed):
            info = meta.get(rid, {'title': '', 'severity': '', 'controls': []})
            controls = info['controls']
            if not controls:
                unmapped += 1
            writer.writerow([
                rid,
                info['severity'],
                'fail',
                '; '.join(controls) if controls else 'unmapped',
                '; '.join(families(controls)),
                info['title'],
                '',
            ])
            rows += 1

    print(f'{rows} failed rules written to {out_path}')
    print(f'{unmapped} had no 800-53 reference in the content (marked "unmapped")')


if __name__ == '__main__':
    main()
