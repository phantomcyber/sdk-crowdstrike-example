# Splunk SOAR SDK example app
## Manages CrowdStrike IOA rules

This is a sample app built with the [Splunk SOAR SDK](https://pypi.python.org/project/splunk-soar-sdk).

To learn more about the SDK, check out our presentation at [.conf25](https://conf.splunk.com/sessions/catalog.html?search=DEV1495#/)!

---
### Requirements
- Mac or Linux development machine
- [uv](https://docs.astral.sh/uv/) with Python 3.9 and 3.13 installed

Visual Studio Code is recommended, to take full advantage of the Run and Debug Configurations we've provided. However, any editor or IDE will work.

Installing the SOAR CLI globally is also helpful: `uv tool install splunk-soar-sdk`.

### Get Started:
1. Clone the repo and open it in your editor.
2. Install dependencies: `uv sync`
3. Copy `test_asset.example.json` to `test_asset.json` and fill in your CrowdStrike API credentials.
4. Activate the virtual environment: `source .venv/bin/activate`

### Running actions from the command line
`python src/app.py action <action_name> -a <asset_filename> -p <parameter_filename>`

We've added run configurations to make this easier in Visual Studio Code. Simply use the `Run and Debug` panel to run an action.

### Building a SOAR app package
`soarapps package build`

You can install this package on any version of Splunk SOAR, 6.2.2 or later.

### Project structure
- `src/app.py`: Entry point of the app, contains all the app metadata, as well as each action.
- `src/params.py`: Data structures for the inputs of each action.
- `src/outputs.py`: Data structures for the outputs of each action.
- `test_params/`: Pre-filled parameters for testing actions from the CLI or VS Code.
- `.vscode/launch.json`: VS Code launch configs for each action.
