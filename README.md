# Veracode Pipeline Mitigation

Parses a Pipeline Scan baseline file, matches flaws to the given application, and identifies which ones have not yet been mitigated. Can be run in "dry run" mode in which JSON files are generated for the mitigations being proposed, or "hands off" mode in which the mitigations are proposed.  

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

* `--application`, `-a`  (required): Applications guid to which to apply mitigations.
* `--baseline_file`, `-bf` (required): Baseline file containing findings that should be mitigated in the application.
* `--sandbox`, `-s` (optional): Sandbox guid to which to apply mitigation in the application specified above.
* `--dry_run`, `-d` (optional): if set, generates mitigation proposals in a JSON script instead of executing the mitigation calls.

When run in `--dry_run` mode, no mitigations are processed, but the JSON payload for the Annotations API is written to `vcpipemit.md`. All actions are logged to `vcpipmit.log`.
