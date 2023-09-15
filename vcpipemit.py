import sys
import argparse
import logging
import datetime
import os
import json
from uuid import UUID

import anticrlf
from veracode_api_py import VeracodeAPI as vapi, Applications, Findings

LINE_NUMBER_SLOP = 3 #adjust to allow for line number movement

log = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = set(['json'])

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

def prompt_for_app(prompt_text):
    appguid = ""
    app_name_search = input(prompt_text)
    app_candidates = vapi().get_app_by_name(app_name_search)
    if len(app_candidates) == 0:
        print("No matches were found!")
    elif len(app_candidates) > 1:
        print("Please choose an application:")
        for idx, appitem in enumerate(app_candidates,start=1):
            print("{}) {}".format(idx, appitem["profile"]["name"]))
        i = input("Enter number: ")
        try:
            if 0 < int(i) <= len(app_candidates):
                appguid = app_candidates[int(i)-1].get('guid')
        except ValueError:
            appguid = ""
    else:
        appguid = app_candidates[0].get('guid')

    return appguid

def allowed_file(filename):
  return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_valid_uuid(uuid_to_test, version=4):
    try:
        uuid_obj = UUID(uuid_to_test, version=version)
    except ValueError:
        return False
    return str(uuid_obj) == uuid_to_test

def get_app_findings(appguid,sandboxguid=None):
    status = "Getting findings for application {}".format(appguid)
    print(status)
    log.info(status)

    request_params = {'scan_type': 'STATIC'}

    all_findings = Findings().get_findings(app=appguid, annot=True, request_params=request_params, sandbox=sandboxguid)

    log.info('Got {} findings for app guid {} and sandbox guid {}'.format(len(all_findings),appguid,sandboxguid))

    return all_findings

def get_mitigated_findings(all_findings):

    return list(filter(lambda finding: finding['finding_status']['resolution_status'] == 'APPROVED', all_findings))

def get_results_findings(results_file):
    rfindings = []

    with open(results_file) as f:
        data = json.load(f)

    rfindings.extend(data.get('findings',[]))

    log.info('The results file {} contains {} findings'.format(results_file, len(rfindings)))

    return rfindings

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
                'resolution': pf['finding_status']['resolution'],
                'cwe': pf['finding_details']['cwe']['id'],
                'source_file': pf['finding_details']['file_path'],
                'line': pf['finding_details']['file_line_number']} for pf in policy_findings]

def get_matched_findings(appguid, mitigated_findings, pipeline_findings, use_no_base_file, sandboxguid=None):
    candidate_findings = []

    mitigated_index = create_match_format_policy(mitigated_findings)

    for thisf in mitigated_index:
        # we allow for some movement of the line number in the pipeline scan findings relative to the mitigated finding as the code may
        # have changed. adjust LINE_NUMBER_SLOP for a more or less precise match, but don't broaden too far or you might match the wrong
        # finding.
        match = next((pf for pf in pipeline_findings if ((thisf['cwe'] == int(pf['cwe_id'])) & 
               (thisf['source_file'].find(pf['files']['source_file']['file']) > -1 ) & 
               ((pf['files']['source_file']['line'] - LINE_NUMBER_SLOP) <= thisf['line'] <= (pf['files']['source_file']['line'] + LINE_NUMBER_SLOP)))), None)

        if match != None:
            match['origin'] = { 'source_app': appguid, 'source_id': thisf['id'], 'resolution': thisf['resolution'],'comment': 'Migrated from mitigated policy or sandbox finding'}
            candidate_findings.append(match)
            log.debug('Matched pipeline finding {} to mitigated finding {}'.format(match['issue_id'],thisf['id']))

    return candidate_findings
    
def process_matched_findings( matched_findings):
    # write matched findings to new baseline file
    baselinefilename = 'baseline.json'

    bfcontent = {'findings': matched_findings}

    with open(baselinefilename, "w", newline='') as f:
        f.write(json.dumps(bfcontent, indent=4))
        f.close()

def get_app_by_name(appname, verbose):
    applications = Applications().get_by_name(appname)
    if (verbose):
        print(applications)
    if applications:
        for index in range(len(applications)):
            if applications[index]["profile"]["name"] == appname:
                return applications[index]["guid"]
    print(f"ERROR: unable to find application named {appname}")
    sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description='This script lists modules in which static findings were identified.')
    parser.add_argument('-a', '--application', help='Applications guid or name from which to retrieve mitigated findings')
    parser.add_argument('-p', '--prompt', action='store_true', help='Prompt for application using partial match search')
    parser.add_argument('-rf', '--results', help='Location of a Pipeline Scan results file from which the baseline file will be created.')
    parser.add_argument('-s', '--sandboxguid', help='Sandbox guid from which to retrieve mitigated findings in the application specified above')
    parser.add_argument('-d', '--debug')
    args = parser.parse_args()

    appguid = args.application
    rf = args.results
    sandboxguid = args.sandboxguid
    prompt = args.prompt
    verbose = args.debug

    setup_logger()

    # CHECK FOR CREDENTIALS EXPIRATION
    creds_expire_days_warning()
 
    if not(allowed_file(rf)):
        print('{} is an invalid filename. --results must point to a json file.')
        return

    if prompt:
        appguid = prompt_for_app('Enter the application name from which to copy mitigations: ')

    if not(is_valid_uuid(appguid)):
        appguid = get_app_by_name(appguid, verbose)

    all_findings = get_app_findings(appguid,sandboxguid)

    mitigated_findings = get_mitigated_findings(all_findings)

    pipeline_findings = get_results_findings(rf)

    matched_findings = get_matched_findings(appguid, mitigated_findings, pipeline_findings, sandboxguid)

    process_matched_findings(matched_findings)

    status = "Processed {} matched findings. See log file for details".format(len(mitigated_findings))
    print(status)
    log.info(status)
    
if __name__ == '__main__':
    main()