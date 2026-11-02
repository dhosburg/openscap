This is a Python project to map an OpenSCAP compliance scan to NIST results 
  with verifications and remediation recommendations.

Installed Rocky Linux 10.2 on vmWARE Fusion

Installed openscap-scanner and scap-securiy-guide

Discovered SCAP datasteam in /usr/share/xml/scap/ssg/content/ssg-rl10-ds.xml
Used oscap info to find profile id for Rocky Linux 10.2
Scanned against a CIS RL10 L2 Server benchmark 
  xccdf_org.ssgproject.content_profile_cis
  #No NIST 800-53 profile available in SCAP security-guide for Rocky Linux 10
  #CIS Rocky Linux Level 2 server benchmark was used as technical baseline
  #failed checks were cross-referenced to NIST SP 800-53r4

Noted the following:
  194 pass counts
  18 notapplicable counts
  211 failed counts:
    21 low severity
    182 medium severity
    4 high severity
Resulting in a score of 66.43%

Verified content carried 800-53 references.

Used LLM assistance to build a Python script that automated extraction of 
  failed OpenSCAP rules and mapped them to NIST 800-53 controls

Prioritized 6 findings to remediate through Ansible located in POAM.md
