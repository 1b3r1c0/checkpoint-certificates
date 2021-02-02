# Create and Install Signed Certs for Checkpoint Firewall's

#### This Perl script uses CPAN modules Net::SSH::Expect, Net::SCP::Expect, Term::ReadKey and IPC::Open2 to add fundamental security controls on the Company's Check Point Firewalls. Specifically, it performs the following:
- Uses 'SSH Expect' to start a remote shell on the firewall
- Uses OpenSSL to create a CSR on the firewall
    - This way the private key is never transported off the box
- Uses 'SCP Expect' to copy the CSR to the Company's Windows AD CA server
    - The CA uses a batch script to create the signed SSL certificate
    - This signed cert is trusted by PCs on the Domain
- Copies the CA signed certificate to the firewall and installs it
- Uses OpenSSL to verify the Subect & Issuer X509 attributes on the newly installed signed certificate 
- Disables HTTP access
- Disables telnet access
- Configures scheduled automated backups 
- Saves the config


-----
### Input file

The input file must be provided as an invocation argument, for example

    <scriptname> deviceInfo.csv 

#### Each line of this file:
- corresponds to a single Checkpoint firewall
- Contains comma-separated-values which correspopnd to x509 attributes. For example

    |               |     DN Section    |            SAN Section
    |---------------|-------------------|-----------------------------------
    | CSV Field #   | 0  1  2  3  4  5  | 6    7    8    9    10    11
    | x509 Attrbute | C  ST L  O  OU CN | IP   URI  DNS  DNS  [DNS] [DNS]	

-----
### These credentials will be prompted for at run time
- The local 'admin' credentials for company's Checkpoint Firewalls
- The script-user's AD credentials
    - in order to SCP files between the local host and the Windows Domain CA
	
-----
### Logs messages to $log_path_and_filename

