
POAM-01: Disable SSH Access via Empty Passwords
xccdf_org.ssgproject.content_rule_sshd_disable_empty_passwords	
high	
fail	
AC-17(a); 
CM-6(a); 
CM-7(a); 
CM-7(b)	AC; 
CM	

POAM-02: Prevent Login to Accounts With Empty Password
xccdf_org.ssgproject.content_rule_no_empty_passwords	
high	
fail	
CM-6(a); 
IA-5(1)(a); 
IA-5(c)	CM; 
IA

POAM-03: Disable SSH Root Login
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

POAM-04: Ensure PAM Enforces Password Requirements - Enforce for root User
xccdf_org.ssgproject.content_rule_accounts_password_pam_enforce_root	
medium	
fail	
CM-6(a); 
IA-5(1)(a); 
IA-5(4); 
IA-5(c)	CM; 
IA	

POAM-05: Record Events that Modify User/Group Information - /etc/shadow
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

POAM-06: Set Interactive Session Timeout	
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
