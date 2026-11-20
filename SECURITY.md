# Security policy

## Reporting a problem

Please do not open a public issue for a security problem.

Write to **support@ardeasecurity.com** with "Security" in the subject. Tell us:

- what you found and where (file, page or setting)
- how to reproduce it
- which version you run (run `git log -1 --oneline` in your Ardea folder)

You will get a reply within 3 working days. We will tell you when a fix is released, and we will credit you
in the release notes if you would like that.

## Supported versions

Security fixes go into the latest release. Please update to it before reporting.

## What Ardea is designed not to do

These are part of the design, so a way around any of them is a security problem worth reporting:

- write to your SIEM or act on your hosts (it uses read-only API keys and fixed queries)
- send alert data to a cloud service (the model runs in your own Ollama; web search is off by default)
- close a credential access or lateral movement alert without a person
- follow instructions hidden in alert data
- show a stored secret in the web console
