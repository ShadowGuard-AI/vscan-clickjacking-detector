# vscan-clickjacking-detector
Detects clickjacking vulnerabilities by analyzing HTTP response headers and the presence of frame busting techniques. Scans a URL and reports if the site is susceptible to clickjacking. - Focused on Lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities

## Install
`git clone https://github.com/ShadowStrikeHQ/vscan-clickjacking-detector`

## Usage
`./vscan-clickjacking-detector [params]`

## Parameters
- `-h`: Show help message and exit
- `-v`: No description provided

## Notes
The URL is checked exactly as given, query string included. Frame busting credit is given for the shapes real frame busting code uses: a comparison between top and self, or a top.location assignment or replacement in a script. If the URL is invalid or the request fails, the tool prints a failure line and exits with a non-zero status, with no verdict for a target it did not reach.

## License
Copyright (c) ShadowStrikeHQ
