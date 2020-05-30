#!/usr/bin/perl -w

####
# Anti-hacking fail2ban-esque script for asterisk-based voip phone systems. So Asterisk, Bicom, FreePBX, etc.
# Checks log files for specific signature and adds IP to iptables
#
# This version has rules designed for older asterisk versions.
#### 

#### HOW TO USE: ####
#### Make script executable with: chmod +x /script/asterisk-security.pl
#### Add to cronjob with:  */5 * * * * perl /script/asterisk-security.pl >/dev/null 2>&1

use warnings;
my (@failhost);
my %currblocked;
my %addblocked;
my $action;
#my (@badip);

open (MYINPUTFILE, "/opt/pbxware/pw/var/log/asterisk/messages") or die "\n", $!, "Does log file file exist\?\n\n";

while (<MYINPUTFILE>) {
    my ($line) = $_;
    chomp($line);

    if ($line =~ m/Sending fake auth rejection for device .*?<(.*?)\>;tag=.*? \(INVITE: (.*?)\)/) {
        my @badip = "";
        @badip = split(':', $2);
        push(@failhost,$badip[0]);
    }
    if ($line =~ m/manager\.c: (.*?) tried to authenticate with/) {
        my @badip = "";
        @badip = split(':', $1);
        push(@failhost,$badip[0]);
    }
    if ($line =~ m/manager\.c: (.*?) failed to authenticate as/) {
        my @badip = "";
        @badip = split(':', $1);
        push(@failhost,$badip[0]);
    }
    if ($line =~ m/\' failed for \'(.*?)\' - No matching peer found/) {
        my @badip = "";
        @badip = split(':', $1);
        push(@failhost,$badip[0]);
    }
    if ($line =~ m/\' failed for \'(.*?)\' ▒^▒^▒ Wrong password/) {
        my @badip = "";
        @badip = split(':', $1);
        push(@failhost,$badip[0]);
    }
}

my $blockedhosts = `/sbin/iptables -n -L INPUT`;

while ($blockedhosts =~ /(.*)/g) {
    my ($line2) = $1;
    chomp($line2);
    if ($line2 =~ m/(\d+\.\d+\.\d+\.\d+)(\s+)/) {
        $currblocked{ $1 } = 'blocked';
    }
}

while (my ($key, $value) = each(%currblocked)){
    print $key . "\n";
}

if (@failhost) {
    &count_unique(@failhost);
    while (my ($ip, $count) = each(%addblocked)) {
        if (exists $currblocked{ $ip }) {
            print "$ip already blocked\n";
        } else {
            $action = `/sbin/iptables -A INPUT -s $ip -j DROP`;
            print "$ip blocked. $count attempts.\n";
        }
    }
} else {
    print "no failed registrations.\n";
}

sub count_unique {
    my @array = @_;
    my %count;
    map { $count{$_}++ } @array;
    map {($addblocked{ $_ } = ${count{$_}})} sort keys(%count);
}
