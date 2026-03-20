## Supporting Measurement Data & Software For "Poor Privacy Practices Of The Apple App Store: Cookies, Advertising and Tracking Of Users"

Files:

- `cookies_minimal_17feb2026.txt.zip`
    - The decrypted/decoded network connections for Experiment Part 1 (location off, not logged in)
- `cookies_minimal_17feb2026_locationon.txt.zip`
    - The decrypted/decoded network connections for Experiment Part 2 (location on, logged in)
- `cookies_minimal_17feb2026_locationon_cookiesblocked2.txt.zip`
    - The decrypted/decoded network connections for the Additional Experiment using mitmdump addon `block_cookies2.py` to block cookies and telemetry connections
- `block_cookies2.py`
    - mitmdump addon used to block cookies and telemetry connections
- In folder addon_ios:  
    - `File `ios_decoding_helpers.py` is mitmdump addon used to decode data sent/received in Apple network connections.  Usage: mitmdump -nr <mitm_data_file> -s addon_ios/ios_decoding_helpers.py
- In folder ssl-kill-switch3-DL:  
    - Objective-C tweak used to bypass SSL cert checks by Apple system processes.  This is based on https://github.com/NyaMisty/ssl-kill-switch3, with only file SSLKillSwitch2.plist changed to include extra system processes to hook.


