# Steam Blocker

A simple tool for blocking Steam connections on Windows 10/11 using the Microsoft Defender Firewall. This tool adds or removes firewall rules for specified Steam executables and IP ranges.

> **Note:** This project was compiled using PyInstaller, which may trigger false positives on VirusTotal. For a clean build, compile the source yourself by installing Python and running `pip install -r requirements.txt`.

## Requirements

- **Operating System:** Windows 10 or Windows 11
- **Firewall:** Microsoft Defender Firewall must be enabled for the tool to work.
- **Administrator Privileges:** It needs to be run as administrator in order for the app to modify firewall entries
- **Python:** Python 3.11 or later (if compiling from source)
- **Dependencies:** Listed in [requirements.txt](requirements.txt)

### Compiled Version

Download the compiled executable from the [Releases](https://github.com/6374686C/steamblocker/releases) section. Note that compiled binaries using PyInstaller may trigger false positives on VirusTotal.

### Building from Source

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/6374686C/steamblocker.git
   cd steam-blocker-gui
   python -m venv venv
   venv\scripts\activate
   pip install pyqt6 pyinstaller
   pyinstaller --onefile --noconsole --icon=icon.ico steam_blocker.py
   ```
