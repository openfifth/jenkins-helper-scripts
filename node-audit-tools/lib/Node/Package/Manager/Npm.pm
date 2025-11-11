package Node::Package::Manager::Npm;

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
use Carp qw(carp croak);
use JSON qw(decode_json);

use Node::Utils qw(
    log_message
    run_command
    safe_json_decode
    map_dependency_info
);

use parent 'Node::Package::Manager::Base';

our $VERSION = '1.0.0';

sub run_outdated_check {
    my ( $self, $tool_config, $direct_deps, $verbose ) = @_;

    my $cmd = $tool_config->{'commands'}{'outdated'};
    if ( !$cmd ) {
        log_message( 'warn', $verbose, 'Outdated command not configured for npm' );
        return ( {}, {} );
    }

    log_message( 'debug', $verbose, "Running outdated command: $cmd" );
    my @cmd_parts = split /\s+/smx, $cmd;
    my @args      = @cmd_parts[ 1 .. $#cmd_parts ];
    my ( $output, $exit ) = run_command( $cmd_parts[0], \@args );
    log_message( 'debug', $verbose, "Outdated command exit code: $exit" );

    if ( !$output ) {
        return ( {}, {} );
    }

    my $payload = safe_json_decode($output);
    if ( !$payload ) {
        log_message( 'warn', $verbose, 'Failed to decode npm outdated output' );
        return ( {}, {} );
    }

    my $packages = {};

    if ( ref $payload eq 'HASH' ) {
        for my $name ( keys %{$payload} ) {
            my $entry = $payload->{$name};
            if ( ref $entry ne 'HASH' ) {
                next;
            }

            my $current = $entry->{'current'};
            my $latest  = $entry->{'latest'};
            my $wanted  = $entry->{'wanted'};
            my $update  = $self->_determine_update_type( $current, $latest );

            $packages->{$name} = {
                'current' => $current,
                'wanted'  => $wanted,
                'latest'  => $latest,
                'update'  => $update,
            };

            map_dependency_info( $packages, $name, $direct_deps );
        }
    }

    my $counts = {};
    for my $info ( values %{$packages} ) {
        if ( ref $info ne 'HASH' ) {
            next;
        }
        my $update = $info->{'update'} // 'unknown';
        $counts->{$update}++;
    }

    my $summary = {
        'total'  => scalar keys %{$packages},
        'counts' => $counts,
    };

    return ( $packages, $summary );
}

sub run_audit_check {
    my ( $self, $tool_config, $direct_deps, $verbose ) = @_;

    my $cmd = $tool_config->{'commands'}{'audit'};
    if ( !$cmd ) {
        log_message( 'warn', $verbose, 'Audit command not configured for npm' );
        return ( [], {} );
    }

    log_message( 'debug', $verbose, "Running audit command: $cmd" );
    my @cmd_parts = split /\s+/smx, $cmd;
    my @args      = @cmd_parts[ 1 .. $#cmd_parts ];
    my ( $output, $exit ) = run_command( $cmd_parts[0], \@args );
    log_message( 'debug', $verbose, "Audit command exit code: $exit" );

    if ( !$output ) {
        return ( [], {} );
    }

    my $payload = safe_json_decode($output);
    if ( !$payload ) {
        log_message( 'warn', $verbose, 'Failed to decode npm audit output' );
        return ( [], {} );
    }

    my $vulnerabilities      = [];
    my $vulnerabilities_data = $payload->{'vulnerabilities'} || {};
    for my $module ( keys %{$vulnerabilities_data} ) {
        my $entry = $vulnerabilities_data->{$module};
        if ( ref $entry ne 'HASH' ) {
            next;
        }

        my $severity = lc( $entry->{'severity'} // 'unknown' );

        my $fix = $entry->{'fixAvailable'};
        my $fixed_in;
        if ( !defined $fix ) {
            $fixed_in = undef;
        } elsif ( ref $fix eq 'HASH' && $fix->{'version'} ) {
            $fixed_in = $fix->{'version'};
        } elsif ($fix) {
            $fixed_in = 'latest';
        }

        my $nodes = [ @{ $entry->{'nodes'} || [] } ];
        my $paths =
            [ map { $self->_npm_node_to_path($_) } @{$nodes} ];
        my $direct = $self->_analyze_dependency_paths( $paths, $direct_deps );

        push @{$vulnerabilities},
            {
            'package'         => $module,
            'severity'        => $severity,
            'current_version' => $entry->{'version'} // $entry->{'range'} // 'unknown',
            'fixed_in'        => $fixed_in,
            'url'             => $self->_find_first_url( $entry->{'via'} ),
            'recommendation'  => $entry->{'via'} && ref $entry->{'via'}[0] eq 'HASH'
            ? $entry->{'via'}[0]{'recommendation'}
            : q{},
            'dependency_paths'    => $paths,
            'direct_dependencies' => $direct,
            };
    }

    my $severity_counts = {};
    for my $entry ( @{$vulnerabilities} ) {
        my $severity = lc( $entry->{'severity'} // 'unknown' );
        $severity_counts->{$severity}++;
    }

    my $summary = {
        'total'           => scalar @{$vulnerabilities},
        'severity_counts' => $severity_counts,
    };

    return ( $vulnerabilities, $summary );
}

sub build_resolved_dependency_data {
    my ( $self, $tool_config, $direct_deps, $project_root, $verbose ) = @_;

    my $list_cmd = $tool_config->{'commands'}{'list'};
    if ( !$list_cmd ) {
        log_message( 'warn', $verbose, 'npm list command not configured, skipping resolved map' );
        return;
    }

    my @cmd_parts = split /\s+/smx, $list_cmd;
    my @args      = @cmd_parts[ 1 .. $#cmd_parts ];
    my ( $output, $exit ) = run_command( $cmd_parts[0], \@args );
    if ( $exit != 0 ) {
        log_message( 'warn', $verbose, "npm list command failed ($exit), skipping resolved map" );
        return;
    }

    my $payload = safe_json_decode($output);
    if ( !$payload ) {
        log_message( 'warn', $verbose, 'Failed to decode npm list output' );
        return;
    }

    my $direct_resolved = {
        dependencies    => {},
        devDependencies => {},
    };
    my $packages = {};
    $self->_traverse_npm_tree(
        $payload->{'dependencies'} || {},
        $packages,
        $direct_resolved,
        $direct_deps
    );

    my $package_list  = [];
    my $package_index = {};
    for my $name ( sort keys %{$packages} ) {
        for my $version ( sort keys %{ $packages->{$name} } ) {
            my $type = $packages->{$name}{$version};
            $package_index->{$name}{$version} = $type;
            push @{$package_list},
                {
                name    => $name,
                version => $version,
                type    => $type,
                };
        }
    }

    my $metadata = {
        source        => 'npm list --json',
        tool          => 'npm',
        package_count => scalar @{$package_list},
    };

    return {
        metadata => $metadata,
        direct   => $direct_resolved,
        packages => $package_list,
        index    => $package_index,
    };
}

sub _determine_update_type {
    my ( $self, $current, $latest ) = @_;

    if ( !defined $current || !defined $latest ) {
        return 'unknown';
    }

    my $current_parts = $self->_version_parts($current);
    my $latest_parts  = $self->_version_parts($latest);

    if ( !@{$current_parts} || !@{$latest_parts} ) {
        return 'unknown';
    }

    if ( $latest_parts->[0] > $current_parts->[0] ) {
        return 'major';
    }
    if ( $latest_parts->[1] > $current_parts->[1] ) {
        return 'minor';
    }
    if ( $latest_parts->[2] > $current_parts->[2] ) {
        return 'patch';
    }

    return 'up-to-date';
}

sub _version_parts {
    my ( $self, $version ) = @_;
    if ( !defined $version ) {
        return;
    }

    my $clean = $version;
    $clean =~ s/^[\^~><=v\s]+//smx;

    my $parts   = [ split /[.]/smx, $clean ];
    my $numeric = [];
    for my $part ( @{$parts} ) {
        my $match = $part;
        push @{$numeric}, ( $match =~ /(\d+)/xms ? $1 : 0 );
    }

    while ( @{$numeric} < 3 ) {
        push @{$numeric}, 0;
    }

    return [ @{$numeric}[ 0 .. 2 ] ];
}

sub _analyze_dependency_paths {
    my ( $self, $paths, $direct_deps ) = @_;

    my $direct = {};

    for my $path ( @{$paths} ) {
        if ( !defined $path ) {
            next;
        }
        my $segments = [ split /\s*>\s*/smx, $path ];
        for my $segment ( @{$segments} ) {
            my $pkg = $self->_normalize_dependency_segment($segment);
            if ( !$pkg ) {
                next;
            }
            if ( exists $direct_deps->{$pkg} ) {
                $direct->{$pkg} = $direct_deps->{$pkg};
            }
        }
    }

    my $result = [];
    for my $key ( sort keys %{$direct} ) {
        my $entry = $direct->{$key};
        push @{$result},
            {
            'name'             => $key,
            'type'             => $entry->{'type'},
            'version_spec'     => $entry->{'version'},
            'resolved_version' => $entry->{'resolved_version'},
            };
    }
    return $result;
}

sub _normalize_dependency_segment {
    my ( $self, $segment ) = @_;
    if ( !defined $segment ) {
        return q{};
    }

    $segment =~ s/^\s+|\s+$//smxg;
    if ( !length $segment ) {
        return q{};
    }

    # Remove trailing version portion (but keep scoped package prefix)
    $segment =~ s/\@(?=[^\/]+$)[^\/]+$//smx;

    return $segment;
}

sub _npm_node_to_path {
    my ( $self, $node ) = @_;
    if ( !defined $node ) {
        return q{};
    }

    # node_modules/foo/node_modules/bar -> foo>bar
    my $segments = [
        grep { $_ ne 'node_modules' && $_ ne q{} }
            split m{/}smx, $node
    ];

    my $packages = [];
    for my $segment ( @{$segments} ) {
        push @{$packages},
            $self->_normalize_dependency_segment($segment);
    }

    return join '>', @{$packages};
}

sub _find_first_url {
    my ( $self, $via ) = @_;

    if ( ref $via ne 'ARRAY' ) {
        return q{};
    }
    for my $item ( @{$via} ) {
        if ( ref $item ne 'HASH' ) {
            next;
        }
        if ( $item->{'url'} ) {
            return $item->{'url'};
        }
    }
    return q{};
}

sub _traverse_npm_tree {
    my ( $self, $node, $packages, $direct_resolved, $direct_deps, $path ) = @_;

    $path ||= [];

    my $precedence = {
        transitive      => 0,
        devDependencies => 1,
        dependencies    => 2,
    };

    for my $name ( keys %{$node} ) {
        my $info = $node->{$name} || {};
        my $version =
               $info->{'version'}
            || $info->{'resolved'}
            || $info->{'from'}
            || 'unknown';

        my $type = 'transitive';
        if (   $direct_deps->{$name}
            && $direct_deps->{$name}{'type'} eq 'dependencies' )
        {
            $type = 'dependencies';
            $direct_resolved->{'dependencies'}{$name} = $version;
        } elsif ( $direct_deps->{$name}
            && $direct_deps->{$name}{'type'} eq 'devDependencies' )
        {
            $type = 'devDependencies';
            $direct_resolved->{'devDependencies'}{$name} = $version;
        }

        my $existing = $packages->{$name}{$version};
        if ( !defined $existing
            || ( $precedence->{$type} // 0 ) > ( $precedence->{$existing} // 0 ) )
        {
            $packages->{$name}{$version} = $type;
        }

        $self->_traverse_npm_tree(
            $info->{'dependencies'} || {},
            $packages,
            $direct_resolved,
            $direct_deps,
            [ @{$path}, $name ]
        );
    }

    return;
}

1;

__END__

=head1 NAME

Node::Package::Manager::Npm - NPM package manager strategy implementation

=head1 SYNOPSIS

    use Node::Package::Manager::Npm;

    my $npm = Node::Package::Manager::Npm->new();
    my ($outdated, $summary) = $npm->run_outdated_check($config, $deps, $verbose);

=head1 DESCRIPTION

This module provides a concrete implementation of the package manager strategy
pattern for NPM. It implements the abstract methods defined in
Node::Package::Manager::Base to handle NPM-specific operations
including outdated checks, security audits, and dependency resolution.

=head1 METHODS

This class inherits from Node::Package::Manager::Base and implements
the following abstract methods:

=head2 run_outdated_check($tool_config, $direct_deps, $verbose)

Implements outdated dependency check for NPM using 'npm outdated --json' command.

=head2 run_audit_check($tool_config, $direct_deps, $verbose)

Implements security audit for NPM using 'npm audit --json' command.

=head2 build_resolved_dependency_data($tool_config, $direct_deps, $project_root, $verbose)

Builds complete dependency tree using 'npm list --json' command.

=head1 PRIVATE METHODS

The following methods are internal to the implementation:

=over 4

=item * _determine_update_type($current, $latest)

=item * _version_parts($version)

=item * _analyze_dependency_paths($paths, $direct_deps)

=item * _normalize_dependency_segment($segment)

=item * _npm_node_to_path($node)

=item * _find_first_url($via)

=item * _traverse_npm_tree($node, $packages, $direct_resolved, $direct_deps, $path)

=back

=head1 AUTHOR

Koha Development Team

=head1 COPYRIGHT

Copyright 2025 Koha

=cut
