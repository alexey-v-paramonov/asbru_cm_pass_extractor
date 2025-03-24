#!/usr/bin/perl
use strict;
use warnings;
use YAML qw(LoadFile);
use Crypt::CBC;

# Password, salt are hardcoded in Asbru CM source code (security by obscurity)
my $CIPHER = Crypt::CBC -> new( -key => 'PAC Manager (David Torrejon Vaquerizas, david.tv@gmail.com)', -cipher => 'Blowfish', -salt => '12345678' ) or die "ERROR: $!";

# Open and read the YAML file
use Getopt::Long;

# Define default file path and variable for YAML data
my $file = '~/.config/asbru/asbru.yml';
my $yaml;

# Process command line options
GetOptions(
    'file=s' => \$file,
    'help'   => sub { print_help() }
) or print_help();

# Expand tilde in file path if present
$file =~ s/^~/$ENV{HOME}/;

sub print_help {
    print "Usage: $0 [options]\n";
    print "Options:\n";
    print "  --file=PATH   Path to asbru YAML file (default: ~/.config/asbru/asbru.yml)\n";
    print "  --help        Show this help message\n";
    exit 1;
}

eval {
    $yaml = LoadFile($file);
};

if ($@) {
    die "Error loading YAML file $file: $@";
}

# Variables to store extracted credentials
my @connections;

# Recursively process the YAML structure
extract_connections($yaml, \@connections);

# Print extracted connection information
print "Extracted connection information:\n";
foreach my $conn (@connections) {
    print "Name: $conn->{name}\n";
    print "IP: $conn->{ip}\n" if defined $conn->{ip};
    print "User: $conn->{user}\n" if defined $conn->{user};
    print "Password: $conn->{pass}\n" if defined $conn->{pass};
    print "-------------------\n";
}

# Function to recursively extract connection information
sub extract_connections {
    my ($data, $connections_ref) = @_;
    
    if (ref($data) eq 'HASH') {
        # Check if this hash has connection information
        my %connection;
        $connection{name} = $data->{name} if defined $data->{name};
        $connection{ip} = $data->{host} || $data->{ip} if defined($data->{host}) || defined($data->{ip});
        $connection{user} = $data->{user} || $data->{username} if defined($data->{user}) || defined($data->{username});
        $connection{pass} = $data->{pass} || $data->{password} if defined($data->{pass}) || defined($data->{password});
        # Decrypt
        $connection{pass} = $CIPHER -> decrypt_hex( $connection{pass} ) if defined $connection{pass};
        
        # If we found any connection info, add it to our results
        if (defined $connection{name} || defined $connection{ip}) {
            push @$connections_ref, \%connection;
        }
        
        # Continue searching in nested structures
        foreach my $key (keys %$data) {
            extract_connections($data->{$key}, $connections_ref) if ref($data->{$key});
        }
    }
    elsif (ref($data) eq 'ARRAY') {
        # Search through array elements
        foreach my $item (@$data) {
            extract_connections($item, $connections_ref) if ref($item);
        }
    }
}
