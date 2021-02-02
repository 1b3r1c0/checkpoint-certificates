#!/usr/bin/perl 

use Net::SSH::Expect; # http://search.cpan.org/~bnegrao/Net-SSH-Expect-1.09/lib/Net/SSH/Expect.pod
use Net::SCP::Expect;
use Term::ReadKey;
use IPC::Open2;
use FileHandle;

#----------- GLOBAL VARS - START -----------#

# This script requires admin login to the Checkpoint firewalls (admin starts in shell instead of clish; no need to 'sudo su -' to install the cert) 
my $username_cp_admin = "admin";
# this is where the req config files, private keys and public certs will be saved on the remote CP FW's
my $wd_remote_cp      = "/var/tmp/"; 

# Local Working directories
my $wd_local_reqcnf	  = $ENV{"HOME"}."/reqcnf/"; 	# req config files for the 'openssl req' utility
my $wd_local_csr	  = $ENV{"HOME"}."/csr/"; 		# CSR's from the CP FW's
my $wd_local_cer	  = $ENV{"HOME"}."/cer/"; 		# Signed certs for the CP FW's
# If the Local Working directories were created from this script then they'll get overwritten each time
# mkdir( $wd_local_reqcnf );
# mkdir( $wd_local_csr );
# mkdir( $wd_local_cer );

# error log for this script 
my $log_path_and_filename	= $ENV{"HOME"}."/cpFwInstallSignedCert_err.log";  

# hwetsrm01.ad.syniverse.com (172.28.40.134)
my $ip_ad = '172.28.40.134';
my $wd_remote_ad_csr = '/c/rmtcerts/';
my $wd_remote_ad_cer = $wd_remote_ad_csr;
my $hostname_ad = 'hwetsrm01';
my $hostname_ca = 'ad-HW1DC01-CA'; # used for verification of the installed signed cert

#----------- GLOBAL VARS - END -----------#

sub getcreds {
	my $user = shift @_;
	
	unless ($user) {
		# initialize $user
		$user = "";
		
		# loops until something is entered
		while ( $user eq "" ) {
			#dbg#	print "enter username [g703584]\n";
			print "Enter username\n";
			chomp ( $user = <STDIN> );
			#dbg#	$user = "g703584" unless $user;
		}
	}
			
	# prompt the user to enter their password
	# loops until something is entered
	# scope and initialize $password 
	my $password = "";
	while ( $password eq "" ) {
		print "Enter the password for user $user. Characters will not be echoed as the password is typed\n";
		# disable echo on the local system while the password is entered
		# requires Term::ReadKey mod
		ReadMode 'noecho';
		chomp ( $password = ReadLine(0) );
		# re-enable echo on the local system after the password has been entered
		# req's Term::ReadKey
		ReadMode 'normal';
	}
	print "Successfully got the password for $user!\n\n";

	return($user, $password);

}

sub create_req_conf_file {
# INPUT = 1: line from the CSV file with the x509 attributes
# OUTPUT = 3:
	# 1) file location of req cnf file on success, "FAIL" on failure
	# 2) command to create the CSR on success, "FAIL" on failure
	# 3) filename of the req cnf file on success, "FAIL" on failure
	
# OVERVIEW: creates and saves a request file for creating a CSR and creates the open ssl command to create the csr

	my $line = shift @_;

	# the attribute values = the CSV's in $line	
	my @x509values = split(',', $line);
	# get rid of any new lines
	chomp foreach @x509values;
	
	# The output will be saved to a file named CN.req.cnf; the CN is the 5th element
	my $filename_output = $x509values[5].".req.cnf";
	
#============================================
# Create the DN (Distinguished Name) section 
	# • The 0th through 5th elements in @x509values are the DN attributes
	#
	#  Distinguished Name section |  SAN Section
	# 0 1  2 3 4  5               | 6  7   8   9   10  11
	# C ST L O OU CN              | IP URI DNS DNS DNS DNS );
	
	my $dnsect = "\# Use this configuration file with the 'openssl req' utilty 
\#  to create a CSR for the $x509values[5] device
\#
\# • SCP this file ($filename_output) to $x509values[5] 
\# 
\# • Execute the openssl command below from the shell (not the CLI)
\#
\# • Make sure that the openssl command is executed from the same
\#   directory that $filename_output was SCP'd to
\#
\# openssl req -new -config $filename_output -keyout $x509values[5].key -out $x509values[5].csr

[ req ]
default_bits        = 1024
prompt              = no
encrypt_key		    = no
default_md			= md5
distinguished_name	= req_distinguished_name
req_extensions 		= req_ext

[ req_distinguished_name ]
C  = $x509values[0]
ST = $x509values[1]
L  = $x509values[2]
O  = $x509values[3]
OU = $x509values[4]
CN = $x509values[5]\n\n";

#===================================================
# Create the SAN (Subject Alternative Name ) section 
	# • The 6th through 11th elements in @conflines are the SAN attributes
	# • For some lines, the 10th & 11th elements will be empty, ""
	#
	#  Distinguished Name section |  SAN Section
	# 0 1  2 3 4  5               | 6  7   8   9   10  11
	# C ST L O OU CN              | IP URI DNS DNS DNS DNS );
	
	# create the SAN section assuming that elements 10 & 11 = "" 
	my $sansect = "\[ req_ext \]\nsubjectAltName = IP:$x509values[6],URI:$x509values[7],DNS:$x509values[8],DNS:$x509values[9]";
	
	# append elements 10 & 11 to the SAN section if they != ""
	if ( ($x509values[10] ne "") && ($x509values[11] ne "") ) {
		# Win32::MsgBox( "\$x509values[10] = $x509values[10]\n\$x509values[11] = $x509values[11]", 0, "debug line 74" );
		$sansect = $sansect . ",DNS:$x509values[10],DNS:$x509values[11]";
	}
	
	# Save the req.cnf output to the local working directory
	# for windoze: my $tempfilevar2 = "$wd_local_reqcnf\\$filename_output";
	# for unix:
	my $tempfilevar2 = "$wd_local_reqcnf/$filename_output";
	eval { open(TEMPFILEHANDLE2,">$tempfilevar2"); };
	return("FAIL", "FAIL", "FAIL") if ( $@ );
	print TEMPFILEHANDLE2 "$dnsect$sansect";
	close(TEMPFILEHANDLE2);
	
	# Create the openssl req command
	my $command  = "openssl req -new -config $filename_output -keyout $x509values[5].key -out $x509values[5].csr";
	
	# Return the output (see remarks at beginning of sub)
	return($tempfilevar2, $command, $filename_output);

}

sub securecopy {
	# Requires Net::SCP::Expect
	# INPUT = 7:	specify local-to-remote xor remote-to-local with { 'l2r' | r2l } 
	#				remote username
	#				remote password
	#				remote ip      
	#				remote location (directory)
	#				filename; assumes filename will not change after being copied       
	# 				local location (directory) 
	# OUTPUT = 1: 'OK' on success; 'FAIL: <errorMsg>' on failure
	
#DBG#print "debug 1: sub securecopy\n"; print "$_\n" foreach (@_); print "press enter to continue, CTL-C to quit\n"; my $debugpause = <STDIN>; 

	# quick sanity check to verify that all of the arguments were supplied:
	foreach (@_) { 
		unless ($_) {
			return ("FAIL: Not all arguments were defined");
		}
	}

	my ( $scp_direction, $scp_remoteusername, $scp_remotepassword, $scp_remoteip, $scp_remote_location, $scp_filename, $scp_local_location ) = @_;
	
#--- DIRECTION ARGUMENT WASN'T SUPPLIED CORRECTLY
	unless ( $scp_direction eq 'l2r' || $scp_direction eq 'r2l' ) {
			return ( "FAIL: SCP Direction not understood" );
			
#--- LOCAL-TO-REMOTE 
	} elsif ( $scp_direction eq 'l2r' ) {
		# CPAN: Example 2 - uses constructor, shorthand scp:
		# CPAN: my $scpe = Net::SCP::Expect->new( host=>'host', user=>'user', password=>'xxxx');
		# CPAN: $scpe->scp('file','/some/dir'); # 'file' copied to 'host' at '/some/dir'
	
		my $scp_src_argument = "$scp_local_location$scp_filename";
		my $scp_dst_argument = "$scp_remote_location$scp_filename";
		
#DBG# 	print "DEBUG LINE 145\n\$scp_src_argument: $scp_src_argument\n\$scp_dst_argument: $scp_dst_argument\npress enter to continue, CTL-C to quit\n"; my $debugpause = <STDIN>;

		# put this in an eval block so it doesn't kill the script
		my ( $scpe, $scp_result );
		eval {
			$scpe = Net::SCP::Expect->new(
										host     => $scp_remoteip,
										user     => $scp_remoteusername,
										password => $scp_remotepassword,
										timeout  => undef,
										auto_yes => 1,
										recursive => 1,
										option => 'StrictHostKeyChecking=no'
										);
 
			$scp_result = $scpe->scp( $scp_src_argument, $scp_dst_argument, ); 
#DBG# 	print "DEBUG LINE 165\npress enter to continue, CTL-C to quit\n"; my $debugpause = <STDIN>;
		};
		
		# everything goes ok
		if ( $scp_result == 1 ) {
			return ( 'OK' );
		
		# something goes awry
		} else {
			return ( "FAIL: $@" );
		}
#DBG# print "debug line 259: sub securecopy\n$@\npress enter to continue, CTL-C to quit\n"; my $debugpause = <STDIN>;
		
#--- REMOTE-TO-LOCAL ( $scp_direction must be 'r2l' by virtue of the first 2 cases,  )
	} else {
		# CPAN: Example 3 - copying from remote machine to local host
		# CPAN: my $scpe = Net::SCP::Expect->new(user=>'user',password=>'xxxx');
		# CPAN: $scpe->scp('host:/some/dir/filename','newfilename');
	
		my $scp_src_argument = "$scp_remoteip:$scp_remote_location$scp_filename";
		my $scp_dst_argument = "$scp_local_location$scp_filename";

#DBG# print "debug 3: sub securecopy\n"; print "\$scp_dst_argument : $scp_dst_argument\n\$scp_src_argument: $scp_src_argument\npress enter to continue, CTL-C to quit\n"; my $debugpause = <STDIN>; 
		
		my ( $scpe, $scp_result );
		# put this in an eval block so it doesn't kill the script
		eval {
			$scpe = Net::SCP::Expect->new(
										user     => $scp_remoteusername,
										password => $scp_remotepassword,
										timeout  => undef,
										auto_yes => 1,
										recursive => 1,
										option => 'StrictHostKeyChecking=no'
										);

			$scp_result = $scpe->scp( $scp_src_argument, $scp_dst_argument ); 
		};
		
		# everything goes ok
		if ( $scp_result == 1 ) {
			return ( 'OK' );
		
		# something goes awry
		} else {
			return ( "FAIL: $@" );
		}
	}
}

sub ssh_connect {
	# INPUT = 4: username, password, rdh (remote destination host) & timeout in secs
	# RETURNS = 1: login output on success, FAIL on failure
	
	my ($un, $pw, $rdh, $timeout) = @_;
#dbg# print "\ndebug line 93\n"; print "\$un: $un\n\$pw: $pw\n\$rdh: $rdh\npress enter to continue, CTL-C to quit\n"; my $debugpause = <STDIN>;

	#-- set up a new connection
	$ssh = Net::SSH::Expect->new(
	   host => $rdh,
	   user => $un,
	   password => $pw,
	   raw_pty => 1,
	   timeout => $timeout
	);

	# Start the SSH process with Net::SSH::Expect->run_ssh() 
	# eval returns undef if there is a syntax error, a runtime error or a die statement is executed 
	my $login_output = eval{$ssh->run_ssh()};
	# return FAIL if the eval block fails
	# When eval returns undef, an error message is saved into $@
	# $@ will be true iff eval is undef & eval generated an error message
	if ($@) {
		return("FAIL");
	}

	# login to the SSH server with Net::SSH::Expect->login() 
	# when successful, $ssh->login() passes the login banner and prompt to eval
	# see notes on eval and $@ above
	$login_output = eval{$ssh->login()};
	# return FAIL if the eval block fails
	if ($@) {
		return("FAIL");
	}

	return( $login_output );
}

sub ssh_getShellPrompt {
	# INPUT = timeout in secs
	# RETURNS = 1: remote host's prompt on success, FAIL on failure

	# THIS SUB ASSUMES WE ARE ALREADY SSH'D INTO THE REMOTE HOST'S AS ROOT (SHELL, NOT CLISH) 
	
	my $timeout = shift @_;
	my $prompt;
	
	# immediatly send CTL-C 
	# 1) in case we're at the "Terminal type [vt100]" prompt
	# 2) to terminate a botched login attempt (e.g. bad password)
	$ssh->send("\cC", 1);
	
	eval {
		# send ' ' and get the current prompt
		$ssh->read_all(1); # Clear the output from the input stream
		$prompt = $ssh->exec(" ", 1); # send ' ' & CR
	};
	
	# In case something went awry in the eval block
	return ( 'FAIL' ) if ( $@ );
		

	# cleanup output
	$prompt =~ s/\n//g; # 'g'lobally 's'ubstitute new line chars
	#remove leading spaces & trailing spaces
	$prompt =~ s/^\s+//; 
	$prompt =~ s/\s+$//; 
	# replace special characters that are common in prompt strings with '.'
	# special chars throw off Regex when trying to match on the prompt string
	$prompt =~ s/[\[\]@ ~\$:#>]/./g;
	
#1111111111# 	print "\n#1111111111#\n"; print "\$prompt: $prompt\npress enter to continue, CTL-C to quit\n"; my $debugpause = <STDIN>;
	
	if ( $prompt !~ /Nokia/ ) {
	
#2222222222222 		print "\n#222\n"; print "\$prompt: $prompt\npress enter to continue, CTL-C to quit\n"; my $debugpause = <STDIN>;
		return( $prompt );
	} else {

#FFFFFFFFFFF		print "\nFFF\n"; print "\$prompt: $prompt\npress enter to continue, CTL-C to quit\n"; my $debugpause = <STDIN>;
		return("FAIL");
	}
	
# $ssh->send("stty raw -echo"); # Disable terminal translations and echo on the remote SSH server # doesn't work on checkpoint shell
		# Undo "stty raw -echo"
		# doesn't work on Nokia's
		# $ssh->send( "reset" );
# From CPAN: exec($cmd [,$timeout]) - executes a command in the remote machine returning its output
}

sub ssh_changeShellToClish {
	# INPUT = 1: timeout in secs
	# RETURNS = 1: "Nokia" success, "FAIL" on failure
	#
	# THIS SUB ASSUMES WE ARE ALREADY SSH'D INTO THE REMOTE HOST AND WE ARE AT THE SHELL PROMPT
	
	my $timeout = shift @_;
	
	# immediatly send CTL-C in case we're at the "Terminal type [vt100]" prompt
	# if that wasn't the prompt, no biggie, it's just CTL-C
	# $ssh->send("\cC", 1);
	
	# $ssh->send("stty raw -echo"); # Disable terminal translations and echo on remote device; doesn't work on checkpoint shell

	# From CPAN: exec($cmd [,$timeout]) - executes a command in the remote machine returning its output
	
	# This assumes we're starting at the shell prompt
#-- send 'clish' and get the output & the prompt
	$ssh->read_all(1); # Clear the output from the input stream
	my $prompt = $ssh->exec("clish", 1); # send the 'clish' command and capture the output
	
#11111111111#	print "\n#111111111111#\n"; print "\$prompt: $prompt\npress enter to continue, CTL-C to quit\n"; my $debugpause = <STDIN>;
	
	# Cleanup the output
	$prompt =~ s/\n//g; # 'g'lobally 's'ubstitute '\n'ew line chars
	$prompt =~ s/^\s+//;  # remove leading spaces...
	$prompt =~ s/\s+$//;  # ... & trailing spaces
	# replace special characters that are common in prompt strings with '.'
	# special chars throw off Regex when trying to match on the prompt string
	$prompt =~ s/[\[\]@ ~\$:#>]/./g;
		
#22222222222#	print "\n#22222222222#\n"; print "\$prompt: $prompt\npress enter to continue, CTL-C to quit\n"; my $debugpause = <STDIN>;

#-- case: prompt = "Could not acquire the config lock"
	# SPACES WERE REPLACED WITH PERIODS!
	if ( $prompt =~ /config.lock/i ) {
	
#3333333333333# 		print "\n#3333333333333#\n"; print "\$prompt: $prompt\npress enter to continue, CTL-C to quit\n"; my $debugpause = <STDIN>;
		
		# override the config lock
		$ssh->send("set config-lock on override", 1);
			
		# send ' ' and get the current output & the prompt
		$ssh->read_all(1); # Clear the output from the input stream
		$prompt = $ssh->exec(" ", 1); # send ' ' & CR and get the output
		
		# Cleanup the output
		$prompt =~ s/\n//g; # 'g'lobally 's'ubstitute '\n'ew line chars
		$prompt =~ s/^\s+//;  #remove leading spaces...
		$prompt =~ s/\s+$//;  # ... & trailing spaces
		# replace special characters that are common in prompt strings with '.'
		# special chars throw off Regex when trying to match on the prompt string
		$prompt =~ s/[\[\]@ ~\$:#>]/./g;
	}	
	
#444444444444 	print "\n444\n"; print "\$prompt: $prompt\npress enter to continue, CTL-C to quit\n"; my $debugpause = <STDIN>;	
	
#-- case: prompt contains "Nokia"
	if ( $prompt =~ /Nokia/ ) {
	
#5555555555555 		print "\n555\n"; print "\$prompt: $prompt\npress enter to continue, CTL-C to quit\n"; my $debugpause = <STDIN>;			

		# Undo "stty raw -echo"
		$ssh->send( "reset" );
		return( "Nokia" );
	} 
	
#6666666666 	print "\n666\n"; print "\$prompt: $prompt\npress enter to continue, CTL-C to quit\n"; my $debugpause = <STDIN>;
	
#-- case: prompt does not contain "Nokia"
	# Undo "stty raw -echo"
	$ssh->send( "reset" );
	return("FAIL");
	
}

sub ssh_send_cmd {
	# INPUT = 3:
	#	1) command to be sent to the remote host,
	#	2) the string to wait for ($wfs) &
	#	3) the timeout in seconds
	
	# RETURNS = 1: 'OK' on success, "FAIL" on failure
	
	# THIS SUB ASSUMES WE ARE ALREADY SSH'D INTO THE REMOTE HOST
	
	my ($cmd, $wfs, $timeout) = @_;
	
	# immediatly send CTL-C in case we're at the "Terminal type [vt100]" prompt
	$ssh->send("\cC");

	# $vtyoutput is used to hold the output from the SSH session after a command has been executed
	my $vtyoutput;
	
	# send the command
	$ssh->read_all(1); # Clear the existing output from the input stream
	$vtyoutput = $ssh->exec($cmd, $timeout);
	
	if ( $vtyoutput =~ /$wfs/ ) {
		return( "OK");
	} else { 
		# return FAIL if the $wfs was not in the output
		return ("FAIL");
	}
	
#dbg# 	print "\ndebug line 440\n"; print "\$cmd:\n$cmd\n\$wfs:\n$wfs\n!!!!PRESS ENTER TO CONTINUE, CTL-C TO QUIT!!!!!\n"; my $debugpause = <STDIN>;
# Doesn't work on checkpoint
# Disable terminal translations and echo on the remote SSH server
# $ssh->send("stty raw -echo");
# From CPAN: exec($cmd [,$timeout]) - executes a command in the remote machine returning its output
}

sub verifyandlog {
	# INPUT = 4 required, 2 optional 
	#		1) path & filename for the error log,
	#		2) result, with any error message, to be verified,
	#		3) string to match result to for failure, or "" 
	#		4) string to match result to for sucess, or "",
	#		5) OPTIONAL: [ message to be logged on failure ]
	#		6) OPTIONAL: [ message to be logged on success ]

	# OUTPUT= 'OK' or 'FAIL'
	
# If the failure string is not supplied, then the success string must be supplied 
# If the success string is not supplied, then the failure string must be supplied 
		
# e.g. &verifyandlog($log_path_and_filename, $result, 'FAIL', "") 
# or
# e.g. &verifyandlog($log_path_and_filename, $result, "", 'OK') 

	# This sub attempts to open a file for logging errors. This sub will kill the script if it cannot open the file
	
	# If $success_string = ""
		# If $result matches the failure string
		# 	• Prints $mssg_failure to STDOUT
		# 	• Appends a message to the error log
		# 	• Returns 'FAIL'
		#
		# If $result does not match the failure string
		# 	• Prints $mssg_sucess to STDOUT
		# 	• Returns 'OK'
		
	# If $failure_string = ""
		# If $result matches $success_string 
		# 	• Prints $mssg_sucess to STDOUT
		# 	• Returns 'OK'
		# If $result does not match $success_string 
		# 	• Prints $mssg_failure to STDOUT
		# 	• Appends a message to the error log
		# 	• Returns 'FAIL'
		
	my ( $log_path_and_filename, $result, $failure_string, $success_string, $mssg_failure, $mssg_sucess ) = @_;
	
	$mssg_failure = "FAILED." unless $mssg_failure;
	$mssg_sucess = "Completed successfully!" unless $mssg_sucess;
	
#debugprint "debug line 579: \n\$mssg_failure: $mssg_failure\npress enter to continue, CTL-C to quit\n"; my $debugpause = <STDIN>;	
	
	# Open the error file for appending (>>)
	open(ERRFILE, ">> $log_path_and_filename") || die("Cannot Open Error Log at $log_path_and_filename. Reason: $!");
	
	if ( $success_string eq "" && $failure_string eq "" ) {
		close(ERRFILE);
		return 'UNKNOWN';
	} elsif ( $success_string eq "" ) {
		if ($result =~ /^$failure_string/ ) {
			print ("$mssg_failure - Reason: $result\n\n");
			print ERRFILE "$mssg_failure - Reason: $result\n";
			close(ERRFILE);
			return 'FAIL';
		} else {
			print ("$mssg_sucess\n\n");
			close(ERRFILE);
			return 'OK';
		}
	} elsif ( $failure_string eq "" ) {
		if ($result =~ /^$success_string/ ) {
			print ("$mssg_sucess\n\n");
			close(ERRFILE);
			return 'OK';
		} else {
			print ("$mssg_failure - Reason: $result\n\n");
			print ERRFILE "$mssg_failure - Reason: $result\n";
			return 'FAIL';
		}
	} else {
		close(ERRFILE);
		return 'UNKNOWN';
	}
}

sub verify_installed_cert {
# INPUT: 3 = 1) command to be run outside of the script (i.e. from the shell)
#			 2) first regex to match on. Each line of the the output from the command will be compared to this regex -  case insensitive
# 			 3) second regex to match on. Each line of the the output from the command will be compared to this regex as well -  case insensitive

# OUTPUT: 1 = 'OK' on success, 'FAIL' on failure

	my ( $command, $regex1, $regex2 ) = @_;
	
#DBG#  	print "DEBUG LINE 561.\n\$command, \$regex1, \$regex2\n$command, $regex1, $regex2\npress enter to continue, CTL-C to quit\n"; my $debugpause = <STDIN>;

	# create $filehandle_read to read output from a command sent with open2
	# create $filehandle_write to write output to a command sent with open2
# NOTE: Data in $filehandle_read cannot be accessed until $filehandle_write has been closed (?!)
	my ($filehandle_read, $filehandle_write) = (IO::Handle->new(), IO::Handle->new());

	# Use open2 to send the command to the shell.
	open2($filehandle_read, $filehandle_write, $command);

	# $filehandle_write is only created so that it can be closed. Nothing gets into $filehandle_read until $filehandle_write gets an end-of-file signal. I know, kinda kludgey
	$filehandle_write->close();

	# put the output of $command_openssl_test into an array 
	my @output_command = <$filehandle_read>;
	$filehandle_read->close(); # close the filehandle

	# initialize match vars
	my ( $matchvar1, $matchvar2 ) = ( 'fail', 'fail'); 

	# iterate through each line of output from $command
	foreach ( @output_command ) {

		# Set $matchvar1 to 'MATCH' if 1 or more lines of the command output = regex1; case insensitive
		$matchvar1 = 'MATCH' if ( /$regex1/i );

		# Set $matchvar2 to 'MATCH' if 1 or more lines of the command output = regex2; case insensitive
		$matchvar2 = 'MATCH' if ( /$regex2/i );
	}

	# there must be at least 1 match for each regex in order to return 'OK'
	if ( $matchvar1 eq 'MATCH' && $matchvar2 eq 'MATCH') {
		return 'OK';
	} else { 
		return 'FAIL';
	}
}

###################=====--- MAIN ---=====########################
# this script uses a single invocation argument: deviceInfo.csv 

# PRINT SCRIPT-BANNER
print ("\n\n\n\n---------------------------------------------------------\n" );
print ("Create and Install Signed Certs for Checkpoint Firewall's\n" );
print ("---------------------------------------------------------\n\n\n\n" );

# GET THE LOCAL CREDS FOR THE CHECKPOINT FIREWALLS
print ("\n\n\n\n\nThis script requires the local 'admin' credentials for Syniverse's Checkpoint Firewalls\n" );
my ($username_cp, $password_cp) = &getcreds($username_cp_admin);

# GET THE USER'S ADSYNIVERSE CREDENTIALS
print ("This script also requires your ADSYNIVERSE credentials - in order to SCP files between the local host and $hostname_ad\n" );
my ($username_ad, $password_ad) = &getcreds();

# go through each line of the .csv file specified in the invocation argument ($ARGV[0])
while ( <> ) {
	chomp;
	
	# Each line from the input file corresponds to a single Checkpoint firewall
	# each line from the input file has these comma separated values in it
	# C ST L O OU CN              | IP URI DNS DNS [DNS] [DNS]	
	# 0 1  2 3 4  5               | 6  7   8   9   10    11
	#  Distinguished Name section |  SAN Section
	
	# Each line of the .csv file gets put into $_
	# Within a single line, each comma-separated-value correspopnds to an x509 attribute value
	# E.G. 
	#	• the hostname, or CN (Common Name), is the 5th element
	# 	• IP address is in the 6th element
	
	# split up each line from the input file
	my @tempArray = split(',');
	
	# put the hostname of the Checkpoint FW into $hostname_cp
	my $hostname_cp = $tempArray[5];
	chomp $hostname_cp;
	
	# put the IP of the Checkpoint FW into $ip_cp
	my $ip_cp = $tempArray[6];
	chomp($ip_cp);
	
#---- PRINT LOOP-BANNER
	print ("\n\n####====---- $hostname_cp ----====####\n\n" );
	
#---- CREATE THE REQ_CNF FILE ON THE LOCAL SERVER
	#  the sub create_req_conf_file will do 3 things:
	# 1) Supply the location of the req cnf file,
	# 2) Create the the 'openssl req' command that will generate the CSR on the remote device and
	# 3) Create the req config file for 'openssl req'
	print ("\nCreating request config file for $hostname_cp that will be used by the 'openssl req' utility...\n");
	my ($req_cnf_file_location, $openssl_req_cmd, $req_cnf_filename) = &create_req_conf_file( $_ );
	
	# verify results of req config file creation
	if ( $req_cnf_file_location eq "" ) {
			print ("Couldn't create the request config file for the openssl req utility\nThis script will now end\n\n");
			# Open the error file for appending (>>)
			open(ERRFILE, ">> $log_path_and_filename") || die("Cannot Open Error Log at $log_path_and_filename. Reason: $!");
			print ERRFILE "For $hostname_cp, could not create req config file.\n";
			close (ERRFILE);
			die;
	} else {
		print "Completed successfully!\n\n";
	}
	
#---- SCP THE REQ CONFIG FILE FROM LOCAL HOST TO THE REMOTE CP FW;
	print ("Attempting to SCP the req config file from the local host to $hostname_cp...\n");
	my $result = &securecopy(
		'l2r', 					# direction: local-to-remote ('l2r') xor remote-to-local ('r2l'): REQUIRED 
		$username_cp, 		# remote username: REQUIRED
		$password_cp, 		# remotepassword: REQUIRED
		$ip_cp,  				# remoteip: REQUIRED
		$wd_remote_cp, 			# remote location: REQUIRED
		"$hostname_cp.req.cnf",	# filename: REQUIRED
		$wd_local_reqcnf 		# local location: REQUIRED
		);	
		
	# verify and log any failures, go to next line of input file on 'FAIL'	
	next if ( &verifyandlog($log_path_and_filename, $result, 'FAIL', "", "SCP FAILED on $hostname_cp",) =~ /fail/i);
	
#---- SSH TO THE REMOTE CP FW SHELL AS ADMIN
	print ("Attempting to SSH to $hostname_cp...\n");
	my $result = &ssh_connect($username_cp, $password_cp, $ip_cp, 5);
	
	# verify and log any failures, go to next line of input file on 'FAIL'	
	next if ( &verifyandlog($log_path_and_filename, $result, 'FAIL', "", "SSH failed for $hostname_cp.", "Connected via SSH to $hostname_cp. If $hostname_cp accepts the supplied password for the admin account, we'll get its prompt string..." ) =~ /fail/i);

#---- GET THE SHELL PROMPT STRING OF THE CP FW 
	print ("Attempting to get the prompt string for $hostname_cp...\n");
	my $shellprompt = &ssh_getShellPrompt(2);
 
	# verify and log any failures, go to next line of input file on 'FAIL'	
	next if ( &verifyandlog($log_path_and_filename, $shellprompt, 'FAIL', "", "For $hostname_cp, could not get the remote host's prompt string.", "SUCCESSFULLY got the prompt string for $hostname_cp: $shellprompt" ) =~ /fail/i);

#---- CHANGE DIRECTORY ON THE CP FW TO $wd_remote_cp
	print ("Attempting to change directory to $wd_remote_cp on $hostname_cp...\n");
	$command = "cd ".$wd_remote_cp;
	my $waitforstring = $shellprompt;
	my $result = &ssh_send_cmd($command, $waitforstring, 2);
	
	# verify the command was successful on the remote host
	next if ( &verifyandlog($log_path_and_filename, $result, 'FAIL', "", "On $hostname_cp, this command failed: $command, with this wait for string: $waitforstring") =~ /fail/i);
	
#---- GENERATE THE CSR ON THE CP FW
	print ("Attempting to generate the CSR on $hostname_cp...\n");
	$command = $openssl_req_cmd;
	$waitforstring = "writing new private key";
	$result = &ssh_send_cmd($command, $waitforstring, 5);
	
	# verify the command was successful on the remote host
	next if ( &verifyandlog($log_path_and_filename, $result, 'FAIL', "", "On $hostname_cp, this command failed: $command, with this wait for string: $waitforstring") =~ /fail/i);
	
#---- VERIFY THAT THE CSR WAS CREATED ON THE CP FW
	print ("Verifying that the CSR exists on $hostname_cp...\n");
	$command = "ls -l";
	$waitforstring = $hostname_cp.".csr";
	$result = &ssh_send_cmd($command, $waitforstring, 2);
	
	# verify the command was successful on the remote host
	next if ( &verifyandlog($log_path_and_filename, $result, 'FAIL', "", "On $hostname_cp, this command failed: $command, with this wait for string: $waitforstring") =~ /fail/i);
	
#---- VERIFY THAT THE SSL PRIVATE KEY WAS CREATED ON THE CP FW
	print ("Verifying that the newly created private SSL key exists on $hostname_cp...\n");
	$command = "ls -l";
	$waitforstring = $hostname_cp.".key";
	$result = &ssh_send_cmd($command, $waitforstring, 2);
	
	# verify the command was successful on the remote host
	next if ( &verifyandlog($log_path_and_filename, $result, 'FAIL', "", "On $hostname_cp, this command failed: $command, with this wait for string: $waitforstring") =~ /fail/i);
	
#---- SCP THE CSR FROM THE REMOTE CP FW TO THE LOCAL HOST
	print ("Attempting to SCP the CSR from $hostname_cp to the local host...\n");
	my $result = &securecopy(
		'r2l', 				# direction: local-to-remote ('l2r') xor remote-to-local ('r2l'): REQUIRED 
		$username_cp, 	# remote username: REQUIRED
		$password_cp, 	# remotepassword: REQUIRED
		$ip_cp,  			# remoteip: REQUIRED
		$wd_remote_cp, 		# remote location: REQUIRED
		"$hostname_cp.csr",	# filename: REQUIRED
		$wd_local_csr 		# local location: REQUIRED
		);
		
	# verify and log any failures, go to next line of input file on 'FAIL'	
	next if ( &verifyandlog($log_path_and_filename, $result, 'FAIL', "", "SCP FAILED for $hostname_cp.") =~ /fail/i);
	
#---- SCP THE CSR FROM THE LOCAL HOST TO THE REMOTE AD SIGNING SERVER
	print ("Attempting to SCP the CSR from the local host to the remote AD signing server ($hostname_ad)...\n");
	my $result = &securecopy(
		'l2r', 				# direction: local-to-remote ('l2r') xor remote-to-local ('r2l'): REQUIRED 
		$username_ad, 		# remote username: REQUIRED
		$password_ad, 		# remotepassword: REQUIRED
		$ip_ad,  			# remoteip: REQUIRED
		$wd_remote_ad_csr,	# remote location: REQUIRED
		"$hostname_cp.csr",	# filename: REQUIRED
		$wd_local_csr 		# local location: REQUIRED
		);
	
	# verify and log any failures, go to next line of input file on 'FAIL'	
	next if ( &verifyandlog($log_path_and_filename, $result, 'FAIL', "", "SCP FAILED for $hostname_ad.") =~ /fail/i);
	
#---- WAIT WHILE THE REMOTE AD SIGNING SERVER CREATES THE SIGNED CERT
	# I hate this....
	# Special domain credentials are required to create a cert signed by the Widoze AD server.
	# Of course, the user of this script does not have these credentials nor knows when they will acquire them :-)
	# so instead, a batch script was created to automatically look in $wd_remote_ad_csr and sign any file ending in '.csr'. this script runs at the required permission level.
	# the resulting signed certs have the same filename except they end in '.cer', instead of '.csr'
	# The batch script automatically runs every 5 seconds (or so)
	# so that's why we are going to sleep for 6 seconds right now.... what a kludge....
	my $shleepytime = 6;
	print ("Waiting $shleepytime seconds while $hostname_ad creates the signed certificate...\n\n");
	sleep( $shleepytime );
	
#---- SCP THE SIGNED CERT FROM THE REMOTE AD SIGNING SERVER TO THE LOCAL HOST
	print ("Attempting to SCP the signed cert from the remote AD signing server ($hostname_ad) to the local host...\n");
	my $result = &securecopy(
		'r2l', 				# direction: local-to-remote ('l2r') xor remote-to-local ('r2l'): REQUIRED 
		$username_ad, 		# remote username: REQUIRED
		$password_ad, 		# remotepassword: REQUIRED
		$ip_ad,  			# remoteip: REQUIRED
		$wd_remote_ad_cer,	# remote location: REQUIRED
		"$hostname_cp.cer",	# filename: REQUIRED
		$wd_local_cer 		# local location: REQUIRED
		);
	
	# verify and log any failures, go to next line of input file on 'FAIL'	
	next if ( &verifyandlog($log_path_and_filename, $result, 'FAIL', "", "SCP FAILED for $hostname_ad." ) =~ /fail/i );
	
#---- SCP THE SIGNED CERT FROM THE THE LOCAL HOST TO THE CP FW
	print ("Attempting to SCP the signed cert from the the local host to $hostname_cp...\n");
	my $result = &securecopy(
		'l2r', 				# direction: local-to-remote ('l2r') xor remote-to-local ('r2l'): REQUIRED 
		$username_cp, 	# remote username: REQUIRED
		$password_cp, 	# remotepassword: REQUIRED
		$ip_cp,  			# remoteip: REQUIRED
		$wd_remote_cp, 		# remote location: REQUIRED
		"$hostname_cp.cer",	# filename: REQUIRED
		$wd_local_cer 		# local location: REQUIRED
		);
		
	# verify and log any failures, go to next line of input file on 'FAIL'	
	next if ( &verifyandlog($log_path_and_filename, $result, 'FAIL', "", "SCP FAILED for $hostname_cp" ) =~ /fail/i );
	
#---- SWITCH TO CLISH ON REMOTE CP FW
	print ("Attempting to switch to clish on $hostname_cp...\n");
	my $shellprompt = &ssh_changeShellToClish(2);

 	# verify the command was successful on the remote host
	 next if ( &verifyandlog($log_path_and_filename, $shellprompt, 'FAIL', "", "On $hostname_cp, could not switch from shell to CLISH") =~ /fail/i);
	
#---- INSTALL SIGNED CERT ON REMOTE CP FW
	# Must be at the clish prompt; must have config lock
	print ("Attempting to install the signed certificate on $hostname_cp...\n");
	$command = "set voyager ssl-certificate cert-file $wd_remote_cp$hostname_cp.cer key-file $wd_remote_cp$hostname_cp.key";
	$waitforstring = $shellprompt;
	
	$result = &ssh_send_cmd($command, $waitforstring, 5);
	
	# verify the command was successful on the remote host
	next if ( &verifyandlog($log_path_and_filename, $result, 'FAIL', "", "On $hostname_cp, this command failed: $command, with this wait for string: $waitforstring" ) =~ /fail/i );
	
#---- DISABLE HTTP ON REMOTE CP FW
	# Must be at the clish prompt; must have config lock
	print ("Attempting to disable HTTP on $hostname_cp...\n");
	$command = "set voyager ssl-level 40";
	$waitforstring = $shellprompt;
	
	$result = &ssh_send_cmd($command, $waitforstring, 5);
	
	# verify the command was successful on the remote host
	next if ( &verifyandlog($log_path_and_filename, $result, 'FAIL', "", "On $hostname_cp, this command failed: $command, with this wait for string: $waitforstring" ) =~ /fail/i );
	
#---- DISABLE TELNET ON REMOTE CP FW
	# Must be at the clish prompt; must have config lock
	print ("Attempting to disable telnet on $hostname_cp...\n");
	$command = "set net-access telnet no";
	$waitforstring = $shellprompt;
	
	$result = &ssh_send_cmd($command, $waitforstring, 5);
	
	# verify the command was successful on the remote host
	next if ( &verifyandlog($log_path_and_filename, $result, 'FAIL', "", "On $hostname_cp, this command failed: $command, with this wait for string: $waitforstring" ) =~ /fail/i );
	
#---- CONFIGURE SCHEDULED/AUTOMATED BACKUPS ON REMOTE CP FW - PART 1
	# Must be at the clish prompt; must have config lock
	print ("Attempting to configure scheduled/automated backups (part 1) on $hostname_cp...\n");
	my $backupfilename = $hostname_cp . "_daily";
	$command = "set backup scheduled filename $backupfilename hour 8 minute 0";
	$waitforstring = $shellprompt;
	$result = &ssh_send_cmd($command, $waitforstring, 5);
	
	# verify the command was successful on the remote host
	next if ( &verifyandlog($log_path_and_filename, $result, 'FAIL', "", "On $hostname_cp, this command failed: $command, with this wait for string: $waitforstring" ) =~ /fail/i );
	
#---- CONFIGURE SCHEDULED/AUTOMATED BACKUPS ON REMOTE CP FW - PART 2
	# Must be at the clish prompt; must have config lock
	print ("Attempting to configure scheduled/automated backups (part 2) on $hostname_cp...\n");
	$command = "set backup auto-transfer ipaddr 172.28.207.196";
	$waitforstring = $shellprompt;
	$result = &ssh_send_cmd($command, $waitforstring, 5);
	
	# verify the command was successful on the remote host
	next if ( &verifyandlog($log_path_and_filename, $result, 'FAIL', "", "On $hostname_cp, this command failed: $command, with this wait for string: $waitforstring" ) =~ /fail/i );
	
		
#---- CONFIGURE SCHEDULED/AUTOMATED BACKUPS ON REMOTE CP FW - PART 3
	# Must be at the clish prompt; must have config lock
	print ("Attempting to configure scheduled/automated backups (part 3) on $hostname_cp...\n");
	$command = "set backup auto-transfer protocol ftp ftp-dir /incoming";
	$waitforstring = $shellprompt;
	$result = &ssh_send_cmd($command, $waitforstring, 5);
	
	# verify the command was successful on the remote host
	next if ( &verifyandlog($log_path_and_filename, $result, 'FAIL', "", "On $hostname_cp, this command failed: $command, with this wait for string: $waitforstring" ) =~ /fail/i );
	
#---- SAVE CONFIG ON REMOTE CP FW
	# Must be at the clish prompt; must have config lock
	print ("Attempting to save the config on $hostname_cp...\n");
	$command = "save config";
	$waitforstring = $shellprompt;
	$result = &ssh_send_cmd($command, $waitforstring, 5);
	
	# verify the command was successful on the remote host
	next if ( &verifyandlog($log_path_and_filename, $result, 'FAIL', "", "On $hostname_cp, this command failed: $command, with this wait for string: $waitforstring") =~ /fail/i );
	
#---- CLOSE THE SSH CONNECTION WITH THE REMOTE CP FW
	print ("CLOSING the SSH connection to $hostname_cp...\n");
	$ssh->close();
	print ("SSH connection was successfully closed.\n\n");
	
#---- VERIFY THE NEWLY INSTALLED CERT ON THE REMOTE CP FW
	print ("Verifying the newly installed signed certificate on $hostname_cp...\n\n");
	my $command_openssl_test = "openssl s_client -connect $ip_cp:443";
	my $match_subject_cn = "subject.*$hostname_cp";
	my $match_issuer_cn = "issuer.*$hostname_ca";

	my $result = &verify_installed_cert( $command_openssl_test, $match_subject_cn, $match_issuer_cn );

	# Verify and log the output from the sub
	&verifyandlog($log_path_and_filename, $result, 'FAIL', "", "\n\nOn $hostname_cp, there is a problem with the newly installed certificate", "\n\nCompleted successfully!");

#DBG#	print "End of main loop.\npress enter to continue, CTL-C to quit\n"; my $debugpause = <STDIN>;
}

# PRINT SCRIPT-BANNER
print ("\n\n\n\n------------------------------------------\n" );
print ("             END OF SCRIPT\n" );
print ("------------------------------------------\n\n\n\n" );

#DBG# print "debug line 848\n\$command: $command\npress enter to continue, CTL-C to quit\n"; my $debugpause = <STDIN>;

#DBG# print "DEBUG LINE 827.\n\$result: $result\npress enter to continue, CTL-C to quit\n"; my $debugpause = <STDIN>; $result = &verifyandlog($log_path_and_filename, $result, 'FAIL', "", "On $hostname_cp, this command failed: $command, with this wait for string: $waitforstring");  print "DEBUG LINE 829.\n\$result: $result\npress enter to continue, CTL-C to quit\n"; my $debugpause = <STDIN>;

#############################################
#############################################
#############################################
#############################################
#############################################
#############################################
#############################################
#############################################
#############################################