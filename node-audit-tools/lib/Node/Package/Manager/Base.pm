package Node::Package::Manager::Base;

# Copyright 2025 Koha Development Team
#
# This file is part of Koha.
#
# Koha is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# Koha is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Koha; if not, see <https://www.gnu.org/licenses/>.

use Modern::Perl;
use Carp qw(croak);

use Node::Utils qw(
    log_message
    run_command
    safe_json_decode
    map_dependency_info
);

our $VERSION = '1.0.0';

sub new {
    my ($class) = @_;
    return bless {}, $class;
}

sub run_outdated_check {
    my ( $self, $tool_config, $direct_deps, $verbose ) = @_;
    croak 'Must implement run_outdated_check method';
}

sub run_audit_check {
    my ( $self, $tool_config, $direct_deps, $verbose ) = @_;
    croak 'Must implement run_audit_check method';
}

sub build_resolved_dependency_data {
    my ( $self, $tool_config, $direct_deps, $project_root, $verbose ) = @_;
    croak 'Must implement build_resolved_dependency_data method';
}

1;

__END__

=head1 NAME

Node::Package::Manager::Base - Abstract base class for package manager strategies

=head1 SYNOPSIS

    # This is an abstract base class
    # Use concrete implementations like Node::Package::Manager::Yarn or Npm

    my $manager = Node::Package::Manager::Yarn->new();
    my ($outdated, $summary) = $manager->run_outdated_check($config, $deps, $verbose);

=head1 DESCRIPTION

This module provides an abstract base class implementing the Strategy pattern for
different Node.js package managers (yarn, npm). It defines the interface
that all package manager strategies must implement.

=head1 METHODS

=head2 new()

Creates a new instance of the package manager strategy.

    my $manager = Node::Package::Manager::Yarn->new();

=head2 run_outdated_check($tool_config, $direct_deps, $verbose)

Abstract method that must be implemented by concrete classes.
Runs outdated dependency check for the specific package manager.

=over 4

=item * $tool_config - Hashref of configuration for this package manager

=item * $direct_deps - Hashref of direct dependencies from package.json

=item * $verbose - Boolean flag for verbose output

=back

Returns: ($outdated_packages, $summary)

=head2 run_audit_check($tool_config, $direct_deps, $verbose)

Abstract method that must be implemented by concrete classes.
Runs security audit check for the specific package manager.

=over 4

=item * $tool_config - Hashref of configuration for this package manager

=item * $direct_deps - Hashref of direct dependencies from package.json

=item * $verbose - Boolean flag for verbose output

=back

Returns: ($vulnerabilities, $summary)

=head2 build_resolved_dependency_data($tool_config, $direct_deps, $project_root, $verbose)

Abstract method that must be implemented by concrete classes.
Builds complete resolved dependency tree for the package manager.

=over 4

=item * $tool_config - Hashref of configuration for this package manager

=item * $direct_deps - Hashref of direct dependencies from package.json

=item * $project_root - Path to project root directory

=item * $verbose - Boolean flag for verbose output

=back

Returns: Hashref containing resolved dependency data

=head1 AUTHOR

Koha Development Team

=head1 COPYRIGHT

Copyright 2025 Koha

=cut
