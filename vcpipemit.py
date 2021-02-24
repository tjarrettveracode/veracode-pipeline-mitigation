import sys
import argparse
import logging
import datetime
import os
import json

import mdutils.mdutils as mdu
import anticrlf
from veracode_api_py import VeracodeAPI as vapi, Applications, Findings

log = logging.getLogger(__name__)

def setup_logger():
    handler = logging.FileHandler('vcpipmit.log', encoding='utf8')
    handler.setFormatter(anticrlf.LogFormatter('%(asctime)s - %(levelname)s - %(funcName)s - %(message)s'))
    logger = logging.getLogger(__name__)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

def creds_expire_days_warning():
    creds = vapi().get_creds()
    exp = datetime.datetime.strptime(creds['expiration_ts'], "%Y-%m-%dT%H:%M:%S.%f%z")
    delta = exp - datetime.datetime.now().astimezone() #we get a datetime with timezone...
    if (delta.days < 7):
        print('These API credentials expire ', creds['expiration_ts'])

def get_app_findings(appguid,sandboxguid=None):
    status = "Getting findings for application {}".format(appguid)
    print(status)
    log.info(status)

    request_params = {'scan_type': 'STATIC'}

    all_findings = Findings().get_findings(app=appguid,request_params=request_params, sandbox=sandboxguid)

    log.info('Got {} findings for app guid {} and sandbox guid {}'.format(len(all_findings),appguid,sandboxguid))

    return all_findings

def get_baseline_findings(baseline_file):
    bfindings = []

    with open(baseline_file) as f:
        data = json.load(f)

    bfindings.extend(data.get('findings',[]))

    log.info('The baseline file {} contains {} findings'.format(baseline_file, len(bfindings)))

    return bfindings

def create_match_format_pipeline(pipeline_findings):
    #     thisf['cwe'] = int(bf['cwe_id'])
    #     thisf['source_file'] = bf['files']['source_file']['file']
    #     thisf['function_name'] = bf['files']['source_file']['function_name']
    #     thisf['function_prototype'] = bf['files']['source_file']['function_name']
    #     thisf['line'] = bf['files']['source_file']['line']
    #     thisf['qualified_function_name'] = bf['files']['source_file']['qualified_function_name']
    #     thisf['scope'] = bf['files']['scope']
    return [{'cwe': int(pf['cwe_id']), 'source_file': pf['files']['source_file']['file'], 'line': pf['files']['source_file']['line'] } for pf in pipeline_findings]

def create_match_format_policy(policy_findings):
    return [{'id': pf['issue_id'],
                'cwe': pf['finding_details']['cwe']['id'],
                'source_file': pf['finding_details']['file_path'],
                'line': pf['finding_details']['file_line_number']} for pf in policy_findings]

def get_matched_findings(appguid, baseline_findings, sandboxguid=None):
    candidate_findings = []
    matched_findings = []

    app_findings = get_app_findings(appguid,sandboxguid)

    pipeline_findings = create_match_format_pipeline(baseline_findings)
    policy_findings = create_match_format_policy(app_findings)

    for thisf in pipeline_findings:

        match = next((pf for pf in policy_findings if ((pf['cwe'] == thisf['cwe']) & 
               (pf['source_file'].find(thisf['source_file']) > -1 ) & 
               (pf['line'] == thisf['line']))), None)

        if match != None:
            candidate_findings.append(match)

    matched_findings = candidate_findings
    
    return matched_findings

def process_matched_findings(appguid, matched_findings, baseline_file, sandboxguid=None, dry_run=False):
    issues = [mf['id'] for mf in matched_findings]
    comment = 'This finding was in the Pipeline Scan Baseline File'
    action = 'DESIGN'

    updategram = { 'issue_list': issues, 'comment': comment, 'action': action }

    if not(dry_run):
        # add support for mitigating in sandbox
        Findings().add_annotation(appguid,issues,comment, action,sandboxguid)

    # create markdown file with json payloads
    mdfile = mdu.MdUtils(file_name='vcpipemit.md',title='Veracode Mitigations from Pipeline Scan Baseline')
    mdfile.new_paragraph("This document contains the update statement for the Veracode Annotations API for the findings in the scan baseline file.")
    mdfile.new_paragraph("Application GUID: {}".format(appguid))
    mdfile.new_paragraph("Sandbox GUID: {}".format(sandboxguid))
    mdfile.new_paragraph("Baseline File: {}".format(baseline_file))
    mdfile.insert_code( json.dumps(updategram), language='json')
    mdfile.create_md_file()

def main():
    parser = argparse.ArgumentParser(
        description='This script lists modules in which static findings were identified.')
    parser.add_argument('-a', '--applicationguid', help='Applications guid in which to propose mitigations', required=True)
    parser.add_argument('-bf', '--baseline_file', help='Pipeline scan baseline file from which to draw mitigations', required=True)
    parser.add_argument('-s', '--sandboxguid', help='Sandbox guid in which to propose mitigations')
    parser.add_argument('-d', '--dry_run', action='store_true', help='If set, mitigation proposals are written to a file and not executed' )
    args = parser.parse_args()

    appguid = args.applicationguid
    bf = args.baseline_file
    sandboxguid = args.sandboxguid
    dry_run = args.dry_run

    setup_logger()

    # CHECK FOR CREDENTIALS EXPIRATION
    creds_expire_days_warning()

    status = "Parsing baseline file..."
    log.info(status)
    print(status)
    baseline_findings = get_baseline_findings(bf)

    matched_findings = get_matched_findings(appguid, baseline_findings, sandboxguid)

    process_matched_findings(appguid, matched_findings, bf, sandboxguid, dry_run)

    status = "Processed {} matched findings. See log file for details".format(len(matched_findings))
    print(status)
    log.info(status)
    
if __name__ == '__main__':
    main()