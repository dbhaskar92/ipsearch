#! /usr/bin/perl -w

#=ipsearch==========
# PURPOSE: Given a list of IP addresses, hostnames and log files, determines if these IP addresses / hostnames
# appear in any of the log files.
# AUTHOR   :	Dhananjay Bhaskar
# LICENSE   :	GPL V2.0
# Revision  : 	2011/09/23 by dbhaskar 
#===================

use strict;

use File::Basename;
use Getopt::Long;
use Socket;

##Constants
use constant{
FALSE =>0,
TRUE => 1,
};

##Global variables
my @log_files_list; 	#list of log file locations
my %str_lookup_files;	#hash of strings and associated log files
my @complete_ip_addr;	#complete ip addresses
my @ip_addr_8;			#ip addresses of the form 255.255.255.
my @ip_addr_16;			#ip addresses of the form 255.255.
my @ip_addr_24;			#ip addresses of the form 255.
my $ip_addr_32;			#ip address of the form .
my $summary = FALSE;	#flag for summary mode
my $host_lookup = TRUE;	#flag indicating whether hostname lookup will be performed
my %IP_Host_hash;	#hash of ip addresses and corresponding host names
my %FileCounter;	#counter for number of matches per file
my %IpCounter;		#counter for number of matches found per ip
my $SCRIPT_DIR = dirname($0);
my $output_flag = FALSE;		#flag for output mode
my $print_handle;				#stores the handler for output

##Global variables for formats:
my $FILE_COUNT_file;
my $FILE_COUNT_number;
my $REPORT_file;
my $REPORT_line;
my $REPORT_content;
my $IP_COUNT_ip;
my $IP_COUNT_number;
my $IP_COUNT_hostname;

##Main routine
parseCommandLineArguements();
if ($output_flag){
	my $output_file = $SCRIPT_DIR."/output";
	open(PRINT_HANDLE, ">$output_file");
	$print_handle = *PRINT_HANDLE;
}else{
	$print_handle = *STDOUT;
}
search_ip_host_hash();
if (!defined($ip_addr_32)){
	search_ip(@ip_addr_24);
	search_ip(@ip_addr_16);
	search_ip(@ip_addr_8);
	search_ip(@complete_ip_addr);

}else{
	search_ip($ip_addr_32);
}
if ($summary){
	printSummary();
}
if($output_flag){
	close(PRINT_HANDLE);
}
#test();	#use this routine to test the parsing of command line arguments

##Subroutines

#=parseCommandLineArguments===============
# Purpose: Sets up parsing of command line options.
# Output: Fills in global variables.
#=========================================
sub parseCommandLineArguements{
	my @ipString;
	my @hostString;
	my @logString;
	my $addr_file;
	my $config_file;
	my $no_host_flag;
	my $summary_flag;
	my $help_flag;
	my $output;

	GetOptions('ip=s' => \@ipString,
		   'hostname=s' => \@hostString,
		   'file=s' => \@logString,
		   'address-file=s' => \$addr_file,
		   'config-file=s' => \$config_file,
		   'no-host-lookup' => \$no_host_flag,
		   's|summary' => \$summary_flag,
		   'h|help' => \$help_flag,
		   'o|output' => \$output);
	if($help_flag){
		die(usage());
	}
	if($output){
		my $output_file = $SCRIPT_DIR."/output";
		if (-f $output_file){
			print "File 'output' already exists in the script directory. Overwrite (y/n)";
			chomp(my $usr_input = <STDIN>);
			if($usr_input =~ /^y/i){
				$output_flag = TRUE;	
			}else{
				die;
			}
		}else{
			$output_flag = TRUE;
		}		
	}
	if($summary_flag){
		$summary = TRUE;
	}
	if($no_host_flag){
		$host_lookup = FALSE;
	}
	 @logString = split(/,/,join(',',@logString));	#separate out the CSV values
        foreach my $log_file (@logString){
                parseFileArguement($log_file);
        }
	if($config_file){
		parseConfigFile($config_file);	
	}else{
		$config_file = "$SCRIPT_DIR/config";
		if (-f $config_file){
			parseConfigFile($config_file);
		}
	}
	if($addr_file){
		parseAddressFile($addr_file);
	}
	if($#ipString<0 and $#hostString<0 and (!defined($addr_file) or $addr_file eq '')){
		print STDERR "Error: Must specify atleast one IP address or hostname \n";
		die(usage());
	}
	@hostString = split(/,/,join(',',@hostString));
	foreach my $host (@hostString){
		parseHostArguement($host);	
	} 
	@ipString = split(/,/,join(',',@ipString));
	foreach my $ip (@ipString){
		parseIpArguement($ip);
	}
}

#=parseConfigFile============================
# Purpose: Parses out config file for any configuration parameters.
# Input:   $config_file The path/name of the config file to parse.
# Output:  Fills in some of the global variables with information from the config file.
#          This includes @log_files_list, giving a list of all log files.
#============================================
sub parseConfigFile{
	my $config_file = shift;
 	open(CONFIGFILE, $config_file) or die("Could not open file $config_file \n");
	for my $line (<CONFIGFILE>)
    	{
        	my $validLine = $line;
        	if ($line =~ m/(.*?)\#/){ # extract up to first #
            		$validLine = $1;
        	}
        	if ($validLine =~ m/^logFile\s*=\s*(.*)$/){
            		my $path = $1;
            		my $file;
			while(defined($file = glob($path))){
				if (-f $file){
					my $is_file_present = FALSE;	# check if this file has to be searched for some string
					foreach my $asso_file (values(%str_lookup_files)){
						if ($asso_file eq $file){
							$is_file_present = TRUE;
							last;
						}
					}
					unless($is_file_present){
						push(@log_files_list,$file);
					}
				}
			}
           	}		 
   	}
	close(CONFIGFILE);
}

#=parseAddressFile===================
# Purpose:  Parses the address file for any addresses to read
# Input:    $addr_file  The name of the address file to parse.
# Output:   Calls appropriate functions to parse ips and hostnames.
#====================================
sub parseAddressFile{
	my $addr_file = shift;
	if (defined($addr_file) and $addr_file ne ''){
 		if(open(ADDRESS_FILE, $addr_file)){
        		for my $line (<ADDRESS_FILE>){
                		my ($validLine) = ($line =~ m/^\s*(.*?)\s*$/); # strip whitespace
                		if ($validLine =~ m/(.*?)\#/){ # extract up to first #
                    			$validLine = $1;
                		}
                		# if ip address
                		if ($validLine =~ m/^(\d){1,3}(\.)(\d+){0,3}(\.)?(\d+){0,3}(\.)?(\d+){0,3}$/){
                    			parseIpArguement($validLine);
                		}elsif ($validLine ne '') { # else treat as hostname
                    			parseHostArguement($validLine); 
                		}
            		}
            		close ADDRESS_FILE;
        	}else{
			warn "Could not open address file $addr_file, skipping... \n";
    		}
	}
}

#=parseFileArguement===================
# Purpose:  Parses the argument to the --file option.
# Input:    $log_file  Log files in CSV format with optional associated strings
# Output:   Add each log file to the appropiate global variable.
#====================================
sub parseFileArguement{
	my $log_file = shift;
	if ($log_file =~ m/^(.*):([a-z\.\/A-Z_0-9]+)$/){		# if an additional string has been specified 
		if(-f $2){
			my $is_key_present = FALSE;
			foreach my $key (keys(%str_lookup_files)){	# check if this string is associated with another file
				if ($key eq $1){
					$is_key_present = TRUE;
					last;
				}
			}
			if($is_key_present == FALSE){
				$str_lookup_files{$1}=$2;
			}else{
				warn "Invalid argument for files: $1 associated multiple times. \n";
				push(@log_files_list, $2);
			}
		}else{
			warn "Invalid argument for files: $log_file ... skipping\n";
		}
	}else{
		if(-f $log_file){
			my $is_file_present = FALSE;
			foreach my $file (@log_files_list){
				if ($file eq $log_file){
					$is_file_present = TRUE;
				}
			}
			if ($is_file_present == FALSE){
				push(@log_files_list,$log_file);
			}
		}else{
			warn "Invalid argument for files: $log_file ... skipping\n";
		}
	}
}

#=parseHostArguement==================
# Purpose: Checks validity of hostname 
# Input:  $host The hostname to check
#========================================
sub parseHostArguement{
	my $host = shift;
	unless(defined(my $ip = getIpFrom($host))){
		warn "Could not find IP address for host: $host \n";
	}
}

#=parseIpArguement===============
# Purpose: Parses out the ip address from the ip argument.
# Input: $ip  Ip address
# Output: Adds the ip to appropiate global variables
#=========================================
sub parseIpArguement{
	my $ip = shift;
	my $ip_fragment;
	if($ip =~ m/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/){
        	if (0 <= $1 and $1 <= 255 
		and 0 <= $2 and $2 <= 255
		and 0 <= $3 and $3 <= 255
		and 0 <= $4 and $4 <= 255){
            		my $ip_addr = "$1.$2.$3.$4";
			my $new_ip_addr = "$1\\.$2\\.$3\\.$4";
                	if ($host_lookup){
                    		if(defined(my $hostname = getHostFrom($ip_addr))){
					$IP_Host_hash{$new_ip_addr}=$hostname;
				}else{	
					push(@complete_ip_addr, $new_ip_addr);
				}
                	}
            	}else{
            		warn "\"$ip\" is an invalid ip address";
        	}
	}
	elsif ($ip =~ m/^(\d+)\.(\d+)\.(\d+)\.$/){
        	if (0 <= $1 and $1 <= 255 and
        	    0 <= $2 and $2 <= 255 and
                    0 <= $3 and $3 <= 255){
            		$ip_fragment = "$1\\.$2\\.$3\\.";
			$ip_fragment .= '[0-9]{1,3}'; 
            		push(@ip_addr_8, $ip_fragment);
        	}else{
            		warn "\"$ip\" invalid for option \"--ip\"";
        	}
    	}
	elsif ($ip =~ m/^(\d+)\.(\d+)\.$/){
        	if (0 <= $1 and $1 <= 255 and
            	    0 <= $2 and $2 <= 255){
            		$ip_fragment = "$1\\.$2\\.";
			$ip_fragment .= '[0-9]{1,3}\.[0-9]{1,3}';
            		push(@ip_addr_16, $ip_fragment);
        	}else{
            		warn "\"$ip\" invalid for option \"--ip\"";
        	}
    	}
	elsif ($ip =~ m/^(\d+)\.$/){
        	if (0 <= $1 and $1 <= 255){
            		$ip_fragment = "$1\\.";
			$ip_fragment .= '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}';
            		push(@ip_addr_24, $ip_fragment);
        	}else{
            		warn "\"$ip\" invalid for option \"--ip\"";
        	}
    	}
	elsif ($ip =~ m/^\.$/){
		$ip_fragment = '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}';
        	$ip_addr_32=$ip_fragment;
    	}
    	else{
        	warn "\"$ip\" invalid for option \"--ip\"";
    	}
}

#=getIpFrom===============
# Purpose:  Looks up an ip address from the passed hostname.
# Input:    $hostname  The hostname to lookup
# Output:   Returns the ip address, or undef if no ip address.
#=========================
sub getIpFrom{
    my $hostname = shift;
    my $packed_ip = gethostbyname($hostname);
    my $ip_address = undef;
    if (defined $packed_ip){
        $ip_address = inet_ntoa($packed_ip);
	my @ip_components = unpack("C4",$packed_ip);
	my $new_ip = join("\\.",@ip_components);
        $IP_Host_hash{$new_ip} = $hostname;
    }
    return $ip_address;
}

#=getHostFrom==============
# Purpose: Returns the hostname from the table (or looks it up if no hostname)
# Input:   $ip The ip to find the hostname for
# Output:  The hostname of this ip (or '' if no such hostname)
#==============================
sub getHostFrom{
    my $ip = shift;
    my $hostname = $IP_Host_hash{$ip};
    unless(defined($hostname)){
	my $iaddr = inet_aton($ip);
        $hostname = gethostbyaddr($iaddr, AF_INET);
    }
    return $hostname;
}


sub usage{
    print "Usage: ".basename($0)."  [Options]\n";
    print "\n";
    print "\tOptions:\n";
    print "\t\t--ip=[ip address(es) to search in CSV format]\n";
    print "\t\t--hostname=[hostnames to search in CSV format]\n";
    print "\t\t--address-file=[file]\n";
    print "\t\t\tWhere [file] is the name of a file containing addresses to search for, one per line.\n";
    print "\t\t--config-file=[file]\n";
    print "\t\t\tWhere [file] is the configuration file to use.\n";
    print "\t\t-s|--summary:  Prints out a summary of the addresses found.\n";
    print "\t\t--no-host-lookup: Do not perform lookups on hostnames\n";
    print "\t\t--file=[extrastring:]filename  Where filename is the name of another log file to search\n";
    print "\t\t\t And where [extrastring:] is another string that must be found for any matches for this file.\n";
    print "\t\t\t Multiple files can be specified in CSV format. A string can only be associated with one file.\n";
    print "\t\t-h|--help: Prints this help screen\n";
    print "\t\t-o|--output: Prints the output in a output file in the script directory.\n";
}

sub test{
	print "Log files list:\n @log_files_list \n \n";
	my @str_look_for = keys(%str_lookup_files);
	print "Strings to look for:\n @str_look_for \n";
	my @ip_asso_str = values(%str_lookup_files);
	print "Log files associated with strings:\n @ip_asso_str \n \n";
	print "Complete IP addresses: \n @complete_ip_addr ";
	my @complete_ip_hash = keys(%IP_Host_hash);
	print "@complete_ip_hash \n \n";
	my @hostnames = values(%IP_Host_hash);
	print "Hostnames: \n @hostnames \n \n";
	print "IP_ADDR_8: \n @ip_addr_8 \n \n";
        print "IP_ADDR_16: \n @ip_addr_16 \n \n";
	print "IP_ADDR_24: \n @ip_addr_24 \n \n";
	if (defined($ip_addr_32)){
		print "IP_ADDR_32: \n $ip_addr_32 \n \n";
	}
}

#=search_ip_host_hash===========
# Purpose: Parse through all log files for the ip addresses and hostnames stored in the IP_Host_hash 
# Output:  Prints the matching lines
#==============================
sub search_ip_host_hash{
	my $grep_prog = 'egrep';
	foreach my $ip (keys(%IP_Host_hash)){
		foreach my $file (@log_files_list){
			if ($file =~ /\.gz$/){			#if the file is compressed
				$grep_prog = 'zegrep';
			}
			my $lines = `$grep_prog -Hn '$ip|$IP_Host_hash{$ip}' $file | uniq`;
			if($lines!~/^\s*$/){
				printLine($lines);
			}
		}
		foreach my $string (keys(%str_lookup_files)){
			my $asso_file = $str_lookup_files{$string};
			if ($asso_file =~ /\.gz$/){
                        	$grep_prog = 'zegrep';
                	}
                	my $text = `$grep_prog -Hn '$ip|$IP_Host_hash{$ip}' $asso_file | grep '$string'  | uniq`;
			if($text!~/^\s*$/){
                		printLine($text);
			}
                }
	}
}

#=search_ip====================
# Purpose: Parse through all log files for incomplete ip addresses 
# Output:  Prints the matching lines
#==============================
sub search_ip{
	my $grep_prog = 'egrep';
	foreach my $ip (@_){
		foreach my $file (@log_files_list){
                        if ($file =~ /\.gz$/){
                                $grep_prog = 'zegrep';
                        }
                        my $lines = `$grep_prog -Hn '$ip' $file | uniq`;
			if($lines!~/^\s*$/){
                        	printLine($lines);
			}
                }
                foreach my $string (keys(%str_lookup_files)){
                        my $asso_file = $str_lookup_files{$string};
                        if ($asso_file =~ /\.gz$/){
                                $grep_prog = 'zegrep';
                        }
                        my $text = `$grep_prog -Hn '$ip' $asso_file | grep '$string'  | uniq`;
			if($text!~/^\s*$/){
                        	printLine($text);
			}
                }
	}
}

#=printSummary=================
# Purpose: Prints a summary of the search using hashs
#==============================
sub printSummary{
	foreach my $file (sort(keys(%FileCounter))){
		select($print_handle);
		$~ = "FILE_COUNT";
		$^ = "FILE_COUNT_TOP";
		$FILE_COUNT_file = $file;
		$FILE_COUNT_number = $FileCounter{$FILE_COUNT_file};
		write;
	}
	$- = 0;						# force new header
	foreach my $ip (sort(keys(%IpCounter))){
		$IP_COUNT_hostname = getHostFrom($ip);
		$IP_COUNT_ip = $ip;
		$IP_COUNT_number = $IpCounter{$ip};
		unless(defined($IP_COUNT_hostname)){
			$IP_COUNT_hostname = "N/A";
		}
		select($print_handle);
		$~ = "IP_COUNT";
		$^ = "IP_COUNT_TOP";
		write;
	}
}

#=printLine====================
# Purpose: Prints out the parsed lines and extracts some useful information
#==============================
sub printLine{
	my $input = shift;
	chomp($input);	
	my @results = split(/\n/,$input);
	foreach my $result (@results){
		my ($file,$line,@data)=split(":",$result);
		my $data = join(":",@data);
		if ($summary){
			$FileCounter{$file}+=1;
			my @ip_matches = $data =~ /([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/g;
			foreach my $ip_match (@ip_matches){
				$IpCounter{$ip_match}+=1;
			}
		}else{
			select($print_handle);
			$~ = "REPORT";
			$^ = "REPORT_TOP";
			$REPORT_file = $file;
			$REPORT_line = $line;
			$REPORT_content = $data;
			write;
		}
	} 
}

## Formats:
format FILE_COUNT=
@<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<	@<<<<<<<<<<<<<
$FILE_COUNT_file,$FILE_COUNT_number
.

format FILE_COUNT_TOP=
FILE								NUMBER OF MATCHES
.

format IP_COUNT=
@<<<<<<<<<<<<<<<<	@<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<	@<<<<<<<<<<<<<
$IP_COUNT_ip,$IP_COUNT_hostname,$IP_COUNT_number
.

format IP_COUNT_TOP=
IP ADDRESS		HOSTNAME				NUMBER OF MATCHES
.

format REPORT=
FILE @<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
$REPORT_file
LINE @########################	
$REPORT_line
CONTENT: ^<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
$REPORT_content
~~^<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
$REPORT_content

.

format REPORT_TOP=
-------------------------------------------------------------------
Results of parsing log files			Page:	@<<<<<<< 
$%
-------------------------------------------------------------------
.


