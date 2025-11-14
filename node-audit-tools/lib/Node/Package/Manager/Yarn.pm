package Node::Package::Manager::Yarn;

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
    normalize_semver_spec
);

use parent 'Node::Package::Manager::Base';

our $VERSION = '1.0.0';

sub run_outdated_check {
    my ( $self, $tool_config, $direct_deps, $verbose ) = @_;

    my $cmd = $tool_config->{'commands'}{'outdated'};
    if ( !$cmd ) {
        log_message( 'warn', $verbose, 'Outdated command not configured for yarn' );
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

    my $packages = {};

    for my $line ( split /\n/smx, $output ) {
        if ( $line !~ /\S/smx ) {
            next;
        }
        if ( $line !~ /^\s*[{]/smx ) {
            next;
        }
        my $payload = safe_json_decode($line);
        if ( !$payload ) {
            log_message( 'warn', $verbose, "Failed to decode yarn outdated line: $line" );
            next;
        }

        if ( !$payload->{'type'} || $payload->{'type'} ne 'table' ) {
            next;
        }
        my $body = $payload->{'data'}{'body'} || [];
        for my $row ( @{$body} ) {
            if ( ref $row ne 'ARRAY' || @{$row} < 4 ) {
                next;
            }
            my ( $name, $current, $wanted, $latest ) =
                @{$row}[ 0 .. 3 ];
            my $update_type = $self->_determine_update_type( $current, $latest );

            $packages->{$name} = {
                'current' => $current,
                'wanted'  => $wanted,
                'latest'  => $latest,
                'update'  => $update_type,
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
        log_message( 'warn', $verbose, 'Audit command not configured for yarn' );
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

    my $vulnerabilities = [];
    my $seen            = {};
    for my $line ( split /\n/smx, $output ) {
        if ( $line !~ /\S/smx ) {
            next;
        }
        if ( $line !~ /^\s*[{]/smx ) {
            next;
        }
        my $payload = safe_json_decode($line);
        if ( !$payload ) {
            log_message( 'warn', $verbose, "Failed to decode yarn audit line: $line" );
            next;
        }

        if ( !$payload->{'type'} || $payload->{'type'} ne 'auditAdvisory' ) {
            next;
        }

        my $advisory   = $payload->{'data'}{'advisory'}   || {};
        my $resolution = $payload->{'data'}{'resolution'} || {};

        my $findings =
            [ @{ $advisory->{'findings'} || [] } ];
        my $paths_seen = {};
        for my $finding ( @{$findings} ) {
            if ( ref $finding ne 'HASH' ) {
                next;
            }
            for my $path ( @{ $finding->{'paths'} || [] } ) {
                if ( !defined $path ) {
                    next;
                }
                $paths_seen->{$path} = 1;
            }
        }

        my $paths = [ sort keys %{$paths_seen} ];

        my $severity = lc( $advisory->{'severity'} // 'unknown' );

        my $module = $advisory->{'module_name'} // 'unknown';
        my $current_version =
              $advisory->{'findings'} && @{ $advisory->{'findings'} } && $advisory->{'findings'}[0]{'version'}
            ? $advisory->{'findings'}[0]{'version'}
            : $resolution->{'currentVersion'} // 'unknown';

        my $patched = $advisory->{'patched_versions'} // q{};
        if ($patched) {
            $patched =~ s/^[\^~><=\s]+//smx;
        }

        my $recommendation = $advisory->{'recommendation'} // q{};

        my $key = join q{:}, $module, $current_version, @{$paths};
        if ( $seen->{$key} ) {
            next;
        }
        $seen->{$key} = 1;

        push @{$vulnerabilities},
            {
            'package'             => $module,
            'severity'            => $severity,
            'current_version'     => $current_version,
            'fixed_in'            => $patched || undef,
            'patched_versions'    => $patched || undef,
            'vulnerable_versions' => $advisory->{'vulnerable_versions'} // undef,
            'title'               => $advisory->{'title'} // undef,
            'cves'                => $advisory->{'cves'} // [],
            'url'                 => $advisory->{'url'} // q{},
            'recommendation'      => $recommendation,
            'dependency_paths'    => $paths,
            'direct_dependencies' => $self->_analyze_dependency_paths( $paths, $direct_deps ),
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
        log_message( 'warn', $verbose, 'yarn list command not configured, skipping resolved map' );
        return;
    }

    log_message( 'debug', $verbose, "Running yarn list command: $list_cmd" );
    my @cmd_parts = split /\s+/smx, $list_cmd;
    my @args      = @cmd_parts[ 1 .. $#cmd_parts ];
    my ( $output, $exit ) = run_command( $cmd_parts[0], \@args );
    log_message( 'debug', $verbose, "yarn list command exit code: $exit" );

    if ( $exit != 0 ) {
        log_message( 'warn', $verbose, "yarn list command failed ($exit), skipping resolved map" );
        return;
    }

    my $nodes = [];
    for my $line ( split /\n/smx, $output ) {
        if ( $line !~ /\S/smx ) {
            next;
        }
        my $payload = safe_json_decode($line);
        if ( !$payload ) {
            log_message( 'warn', $verbose, "Failed to decode yarn list line: $line" );
            next;
        }

        my $type = $payload->{'type'} // q{};
        if ( $type eq 'warning' || $type eq 'info' ) {
            next;
        }

        if ( $type eq 'tree' ) {
            my $trees = $payload->{'data'}{'trees'} || [];
            push @{$nodes}, @{$trees};
        }
    }

    if ( !@{$nodes} ) {
        log_message( 'warn', $verbose, 'yarn list produced no dependency data' );
        return;
    }

    return $self->_process_yarn_nodes( $nodes, $direct_deps, $verbose );
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

sub _process_yarn_nodes {
    my ( $self, $nodes, $direct_deps, $verbose ) = @_;

    my $packages        = {};
    my $package_index   = {};
    my $direct_resolved = {
        dependencies    => {},
        devDependencies => {},
    };

    my $precedence = {
        transitive      => 0,
        devDependencies => 1,
        dependencies    => 2,
    };

    my $visit;
    $visit = sub {
        my ($node) = @_;
        if ( ref $node ne 'HASH' ) {
            return;
        }

        for my $child ( @{ $node->{'children'} || [] } ) {
            $visit->($child);
        }

        if ( $node->{'shadow'} ) {
            return;
        }

        my $raw = $node->{'name'};
        if ( !defined $raw ) {
            return;
        }

        my ( $pkg, $descriptor ) = $self->_parse_yarn_identifier($raw);
        if ( !$pkg || !defined $descriptor ) {
            return;
        }

        my $version = $self->_extract_yarn_version($descriptor);
        if ( !defined $version || $version eq q{} ) {
            return;
        }

        my $type = 'transitive';
        if ( my $direct = $direct_deps->{$pkg} ) {
            my $bucket =
                $direct->{'type'} eq 'devDependencies'
                ? 'devDependencies'
                : 'dependencies';
            $type = $bucket;
            $direct_resolved->{$bucket}{$pkg} //= $version;
        }

        my $existing = $packages->{$pkg}{$version};
        if ( !defined $existing
            || ( $precedence->{$type} // 0 ) > ( $precedence->{$existing} // 0 ) )
        {
            $packages->{$pkg}{$version} = $type;
        }
    };

    $visit->($_) for @{$nodes};

    if ( !keys %{$packages} ) {
        log_message( 'warn', $verbose, 'yarn list traversal yielded no packages' );
        return;
    }

    my $package_list = [];
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

    my $spec_map = {};
    for my $name ( keys %{$direct_deps} ) {
        my $spec = $direct_deps->{$name}{'version'};
        if ( !defined $spec || $spec eq q{} ) {
            next;
        }

        my $bucket =
            $direct_deps->{$name}{'type'} eq 'devDependencies'
            ? 'devDependencies'
            : 'dependencies';
        my $resolved = $direct_resolved->{$bucket}{$name};

        if ( !defined $resolved || $resolved eq q{} ) {
            next;
        }

        $spec_map->{"$name\@$spec"} = $resolved;

        if ( my $normalized = normalize_semver_spec($spec) ) {
            $spec_map->{"$name\@$normalized"} //= $resolved;
        }
    }

    my $metadata = {
        source        => 'yarn list --json',
        tool          => 'yarn',
        package_count => scalar @{$package_list},
    };

    return {
        metadata => $metadata,
        direct   => $direct_resolved,
        packages => $package_list,
        spec_map => $spec_map,
        index    => $package_index,
    };
}

sub _parse_yarn_identifier {
    my ( $self, $identifier ) = @_;
    if ( !defined $identifier ) {
        return;
    }

    $identifier =~ s/^\s+//smx;
    $identifier =~ s/\s+$//smx;

    if ( $identifier =~ /^(@[^\/]+\/[^@]+)@(.+)$/smx ) {
        return ( $1, $2 );
    } elsif ( $identifier =~ /^([^@]+)@(.+)$/smx ) {
        return ( $1, $2 );
    }

    return;
}

sub _extract_yarn_version {
    my ( $self, $descriptor ) = @_;
    if ( !defined $descriptor ) {
        return;
    }

    my $value = $descriptor;
    $value =~ s/^\s+|\s+$//smxg;

    if ( $value =~ /^([^:]+):(.+)$/smx ) {
        my ( $prefix, $rest ) = ( $1, $2 );
        if ( $prefix eq 'npm' ) {
            return $rest;
        }
        return "$prefix:$rest";
    }

    $value =~ s/^[\^~=\s]+//smx;

    return length $value ? $value : undef;
}

1;

__END__

=head1 NAME

Node::Package::Manager::Yarn - Yarn package manager strategy implementation

=head1 SYNOPSIS

    use Node::Package::Manager::Yarn;

    my $yarn = Node::Package::Manager::Yarn->new();
    my ($outdated, $summary) = $yarn->run_outdated_check($config, $deps, $verbose);

=head1 DESCRIPTION

This module provides a concrete implementation of the package manager strategy
pattern for Yarn. It implements the abstract methods defined in
Node::Package::Manager::Base to handle Yarn-specific operations
including outdated checks, security audits, and dependency resolution.

=head1 METHODS

This class inherits from Node::Package::Manager::Base and implements
the following abstract methods:

=head2 run_outdated_check($tool_config, $direct_deps, $verbose)

Implements outdated dependency check for Yarn using 'yarn outdated --json' command.

=head2 run_audit_check($tool_config, $direct_deps, $verbose)

Implements security audit for Yarn using 'yarn audit --json' command.

=head2 build_resolved_dependency_data($tool_config, $direct_deps, $project_root, $verbose)

Builds complete dependency tree using 'yarn list --json' command.

=head1 PRIVATE METHODS

The following methods are internal to the implementation:

=over 4

=item * _determine_update_type($current, $latest)

=item * _version_parts($version)

=item * _analyze_dependency_paths($paths, $direct_deps)

=item * _normalize_dependency_segment($segment)

=item * _process_yarn_nodes($nodes, $direct_deps, $verbose)

=item * _parse_yarn_identifier($identifier)

=item * _extract_yarn_version($descriptor)

=back

=head1 AUTHOR

Koha Development Team

=head1 COPYRIGHT

Copyright 2025 Koha

=cut
