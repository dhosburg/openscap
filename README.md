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

Prioritized 6 findings to remediate through Ansible:

1: Disable SSH Access via Empty Passwords
xccdf_org.ssgproject.content_rule_sshd_disable_empty_passwords	
high	
fail	
AC-17(a); 
CM-6(a); 
CM-7(a); 
CM-7(b)	AC; 
CM	

2: Prevent Login to Accounts With Empty Password
xccdf_org.ssgproject.content_rule_no_empty_passwords	
high	
fail	
CM-6(a); 
IA-5(1)(a); 
IA-5(c)	CM; 
IA

3: Disable SSH Root Login
xccdf_org.ssgproject.content_rule_sshd_disable_root_login	
medium	
fail	
AC-17(a); 
AC-6(2); 
CM-6(a); 
CM-7(a); 
CM-7(b); 
IA-2; 
IA-2(5)	AC; 
CM; 
IA

4: Ensure PAM Enforces Password Requirements - Enforce for root User
xccdf_org.ssgproject.content_rule_accounts_password_pam_enforce_root	
medium	
fail	
CM-6(a); 
IA-5(1)(a); 
IA-5(4); 
IA-5(c)	CM; 
IA	

5: Record Events that Modify User/Group Information - /etc/shadow
xccdf_org.ssgproject.content_rule_audit_rules_usergroup_modification_shadowmedium	
fail	
AC-2(4); 
AC-6(9); 
AU-12(c); 
AU-2(d); 
CM-6(a)	
AC; 
AU; 
CM	

6: Set Interactive Session Timeout	
xccdf_org.ssgproject.content_rule_accounts_tmout	
medium	
fail	
AC-12; 
AC-2(5); 
CM-6(a); 
SC-10	
AC; 
CM; 
SC	
