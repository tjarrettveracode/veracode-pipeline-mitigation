# Veracode Pipeline Mitigation

Retrieves findings with APPROVED mitigations from an application's policy scan (or sandbox) and creates a baseline file for Pipeline Scan.  Mitigations in a "proposed" state will not be retrieved.

## Setup

Clone this repository:

    git clone https://github.com/tjarrettveracode/veracode-pipeline-mitigation

Install dependencies:

    cd veracode-pipeline-mitigation
    pip install -r requirements.txt

(Optional) Save Veracode API credentials in `~/.veracode/credentials`

    [default]
    veracode_api_key_id = <YOUR_API_KEY_ID>
    veracode_api_key_secret = <YOUR_API_KEY_SECRET>

## Run

If you have saved credentials as above you can run:

    python vcpipemit.py (arguments)

Otherwise you will need to set environment variables:

    export VERACODE_API_KEY_ID=<YOUR_API_KEY_ID>
    export VERACODE_API_KEY_SECRET=<YOUR_API_KEY_SECRET>
    python vcpipemit.py (arguments)

Arguments supported include:

* `--application`, `-a`  (required if `--prompt` not used): Applications guid from which to retrieve mitigated findings.
* `--prompt`, `-p` (optional): Specify to be prompted to search by application name.
* `--results`, `-rf` (required): Location of a Pipeline Scan results file from which the baseline file will be created.
* `--sandbox`, `-s` (optional): Sandbox guid from which to retrieve mitigated findings in the application specified above.

All actions are logged to `vcpipmit.log`. The baseline file is created in the current directory and is named `baseline_<appguid>.json`.

## Notes

We perform a naïve match between the mitigated findings and the pipeline findings based on CWE ID, source file and line number value. There is some
"slop" built into the match (checking a range in the pipeline finding around the original mitigated finding); you can adjust the constant
`LINE_NUMBER_SLOP` to get a more or less precise match.
