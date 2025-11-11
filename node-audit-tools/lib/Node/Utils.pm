package Node::Utils;

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
# along with Koha; if not, see <https://www.gnu.org/licenses>.

use strict;
use warnings;
use Carp qw(carp croak);
use parent 'Exporter';
use Cwd                   qw(abs_path cwd);
use File::Basename        qw(dirname);
use File::Spec::Functions qw(catfile catdir updir);
use English               qw(-no_match_vars);
use JSON                  qw(decode_json encode_json);
use POSIX                 qw(strftime);

our $VERSION   = '1.0.0';
our @EXPORT_OK = qw(
    log_message
    load_config
    find_project_root
    detect_package_manager
    run_command
    safe_json_decode
    change_to_project_root
    map_dependency_info
    determine_update_type
    version_parts
    xml_escape
    generate_purl
    generate_uuid
    normalize_semver_spec
    load_package_json
    build_direct_dependency_map
    write_json_results
    parse_compromise_line
    run_compromise_check
    build_resolved_index
    determine_exit_code
    build_bugzilla_report_data
    build_sbom_data
    detect_koha_version
);

sub log_message {
    my ( $level, $verbosity, $message ) = @_;

    if ( defined $verbosity && !$verbosity && ( $level eq 'debug' || $level eq 'info' ) ) {
        return;
    }

    my $timestamp = strftime( '%Y-%m-%d %H:%M:%S', localtime );
    print {*STDERR} "[$timestamp] [$level] $message\n";
    return;
}

sub load_config {
    my ($config_file) = @_;
    if ( !-f $config_file ) {
        return;
    }

    eval { require YAML; YAML->import('LoadFile'); 1; } or do {
        log_message( 'warn', 1, 'YAML module not available, config loading disabled' );
        return {};
    };

    my $config;
    eval { $config = LoadFile($config_file); 1; } or do {
        log_message( 'error', 1, "Failed to load config file '$config_file': $EVAL_ERROR" );
        return {};
    };
    return $config;
}

sub find_project_root {
    my $current_dir = cwd();

    while ( $current_dir ne q{/} ) {
        return $current_dir if -f catfile( $current_dir, 'package.json' );
        $current_dir = dirname($current_dir);
    }

    croak "Could not find project root (package.json)\n";
}

sub detect_package_manager {
    my $project_root = find_project_root();

    return 'yarn' if -f catfile( $project_root, 'yarn.lock' );
    return 'npm'  if -f catfile( $project_root, 'package-lock.json' );

    log_message( 'warn', 1, 'No lock file found, defaulting to npm' );
    return 'npm';
}

sub run_command {
    my ( $command, $args_ref ) = @_;
    $args_ref //= [];

    log_message( 'debug', 0, "Running command: $command " . join q{ }, @{$args_ref} );

    my $output    = _run_command_and_capture( $command, $args_ref );
    my $exit_code = $CHILD_ERROR >> 8;
    log_message( 'debug', 0, "Command exit code: $exit_code" );

    return ( $output, $exit_code );
}

sub _run_command_and_capture {
    my ( $command, $args_ref ) = @_;

    my $pid = open my $pipe, q{-|};
    if ( !defined $pid ) {
        log_message( 'error', 1, "Cannot fork: $OS_ERROR" );
        return ( "Cannot fork: $OS_ERROR", -1 );
    }

    if ( $pid == 0 ) {

        # Use system calls for reliable STDIN redirection
        require POSIX;
        POSIX::dup2( POSIX::open( '/dev/null', POSIX::O_RDONLY() ), 0 ) or exit 127;
        open STDERR, '>', '/dev/null' or exit 127;
        exec {$command} $command, @{$args_ref} or exit 127;
    }

    my $output = do { local $INPUT_RECORD_SEPARATOR = undef; <$pipe> };
    close $pipe;

    return $output;
}

sub safe_json_decode {
    my ($json_string) = @_;
    if ( !defined $json_string || !length $json_string ) {
        return;
    }

    my $result;
    eval { $result = decode_json($json_string); 1; } or do {
        log_message( 'warn', 1, "Failed to parse JSON: $EVAL_ERROR" );
        return;
    };
    return $result;
}

sub change_to_project_root {
    my $project_root = find_project_root();
    chdir $project_root or log_message( 'error', 1, "Cannot change to project root: $OS_ERROR" ) and return;
    log_message( 'debug', 0, "Changed to project root: $project_root" );
    return $project_root;
}

sub map_dependency_info {
    my ( $packages, $name, $direct_deps ) = @_;

    if ( ref $packages ne 'HASH' || !defined $name ) {
        return;
    }

    my $entry = $packages->{$name} ||= {};
    my $direct =
        ( $direct_deps && ref $direct_deps eq 'HASH' )
        ? $direct_deps->{$name}
        : undef;

    if ($direct) {
        $entry->{'type'}             = $direct->{'type'}             || $entry->{'type'} || 'dependencies';
        $entry->{'version_spec'}     = $direct->{'version'}          || $entry->{'version_spec'};
        $entry->{'resolved_version'} = $direct->{'resolved_version'} || $entry->{'resolved_version'};
    } else {
        $entry->{'type'} ||= 'transitive';
    }

    return $entry;
}

sub load_package_json {
    my ($root) = @_;
    my $path = catfile( $root, 'package.json' );

    open my $fh, '<', $path or croak "Cannot open $path: $OS_ERROR";
    local $INPUT_RECORD_SEPARATOR = undef;
    my $json_text = <$fh>;
    close $fh or croak;

    my $data = decode_json($json_text);
    if ( ref $data ne 'HASH' ) {
        croak 'package.json did not parse into a hash';
    }

    return $data;
}

sub build_direct_dependency_map {
    my ($package_json) = @_;

    my $map = {};

    for my $name ( keys %{ $package_json->{'dependencies'} || {} } ) {
        my $version = $package_json->{'dependencies'}{$name};
        $map->{$name} = {
            'type'    => 'dependencies',
            'version' => $version,
        };
    }

    for my $name ( keys %{ $package_json->{'devDependencies'} || {} } ) {
        my $version = $package_json->{'devDependencies'}{$name};
        $map->{$name} = {
            'type'    => 'devDependencies',
            'version' => $version,
        };
    }

    return $map;
}

sub write_json_results {
    my ( $output, $data, $verbose ) = @_;

    open my $fh, '>', $output
        or croak "Cannot open $output for writing: $OS_ERROR";
    print {$fh} encode_json($data) or croak;
    close $fh                      or croak;

    log_message( 'info', $verbose, "JSON results written to $output" );

    return;
}

sub parse_compromise_line {
    my ($line) = @_;

    if ( !defined $line || !length $line ) {
        return { error => 'empty' };
    }

    my $scoped = qr{
        @[^\/\s]+\/[\w._-]+
    }smx;
    my $unscoped = qr{
        [[:alnum:]][[:alnum:]._-]*
    }smx;
    my $version = qr/[\S]+/smx;

    if ( $line =~ /^($scoped)@($version)$/smx ) {
        return { name => $1, version => $2 };
    }
    if ( $line =~ /^($scoped)[:=]($version)$/smx ) {
        return { name => $1, version => $2 };
    }
    if ( $line =~ /^($scoped)\s+($version)$/smx ) {
        return { name => $1, version => $2 };
    }
    if ( $line =~ /^($unscoped)@($version)$/smx ) {
        return { name => $1, version => $2 };
    }
    if ( $line =~ /^($unscoped)[:=]($version)$/smx ) {
        return { name => $1, version => $2 };
    }
    if ( $line =~ /^($unscoped)\s+($version)$/smx ) {
        return { name => $1, version => $2 };
    }
    if ( $line =~ /^($scoped)$/smx ) {
        return { name => $1 };
    }
    if ( $line =~ /^($unscoped)$/smx ) {
        return { name => $1 };
    }

    return { error => 'unrecognized format' };
}

sub run_compromise_check {
    my ( $queries, $resolved_data, $verbose ) = @_;

    my $queries_list = [ @{ $queries || [] } ];
    my $summary      = {
        total   => scalar @{$queries_list},
        matches => 0,
        missing => 0,
        invalid => 0,
    };

    my $results = [];

    if ( !@{$queries_list} ) {
        $summary->{'note'} = 'No package identifiers provided';
        return { 'summary' => $summary, 'queries' => [] };
    }

    if ( !$resolved_data || !@{ $resolved_data->{'packages'} || [] } ) {
        my $error = 'Resolved dependency data unavailable; cannot evaluate package list';
        log_message( 'warn', $verbose, $error );
        $summary->{'error'} = $error;
        return { 'summary' => $summary, 'queries' => [] };
    }

    my $index = $resolved_data->{'index'};
    $index ||= build_resolved_index( $resolved_data->{'packages'} );

    for my $query ( @{$queries_list} ) {
        if ( $query->{'error'} ) {
            $summary->{'invalid'}++;
            push @{$results},
                {
                'input'  => $query->{'input'},
                'status' => 'invalid',
                'error'  => $query->{'error'},
                };
            next;
        }

        my $name = $query->{'name'};
        my $spec = $query->{'version'};

        my $available = $index->{$name} || {};
        my $versions  = [ sort keys %{$available} ];

        my $matched = [];
        if ( defined $spec && length $spec ) {
            my $normalized = normalize_semver_spec($spec);
            for my $version ( @{$versions} ) {
                if ( $version eq $spec
                    || ( defined $normalized && $version eq $normalized ) )
                {
                    push @{$matched},
                        {
                        version => $version,
                        scope   => $available->{$version},
                        };
                }
            }
        } else {
            @{$matched} = map {
                {
                    version => $_,
                    scope   => $available->{$_},
                }
            } @{$versions};
        }

        my $result = {
            'input'        => $query->{'input'},
            'package'      => $name,
            'version_spec' => $spec,
            'matches'      => $matched,
        };

        if ( @{$matched} ) {
            $result->{'status'} = 'match';
            $summary->{'matches'}++;
        } else {
            $result->{'status'} = 'no-match';
            $summary->{'missing'}++;
        }

        push @{$results}, $result;
    }

    return { summary => $summary, queries => $results };
}

sub build_resolved_index {
    my ($packages) = @_;
    my $index = {};
    for my $entry ( @{ $packages || [] } ) {
        if ( !$entry->{'name'} || !$entry->{'version'} ) {
            next;
        }
        $index->{ $entry->{'name'} }{ $entry->{'version'} } = $entry->{'type'} // 'transitive';
    }
    return $index;
}

sub determine_exit_code {
    my ( $results, $thresholds ) = @_;

    $thresholds //= {};

    my $vuln_fail = $thresholds->{'vulnerable_fail'};
    if ( !defined $vuln_fail ) {
        $vuln_fail = 0;
    }
    my $major_fail      = $thresholds->{'major_version_fail'} // 0;
    my $audit_level     = lc( $thresholds->{'audit_fail_level'} // 'moderate' );
    my $compromise_fail = $thresholds->{'compromise_fail_on_match'};
    if ( !defined $compromise_fail ) {
        $compromise_fail = 1;
    }

    my $severity_rank = {
        info     => 0,
        low      => 1,
        moderate => 2,
        high     => 3,
        critical => 4,
        unknown  => 5,
    };

    my $vulnerabilities = $results->{'vulnerabilities'} || [];

    if ( $vuln_fail && @{$vulnerabilities} ) {
        return 1;
    }

    if ( @{$vulnerabilities} ) {
        my $threshold_rank = $severity_rank->{$audit_level} // $severity_rank->{'moderate'};

        for my $vuln ( @{$vulnerabilities} ) {
            my $rank = $severity_rank->{ lc( $vuln->{'severity'} || q{} ) } // $severity_rank->{'unknown'};
            if ( $rank >= $threshold_rank ) {
                return 1;
            }
        }
    }

    if ($major_fail) {
        for my $pkg ( keys %{ $results->{'outdated'} || {} } ) {
            my $info = $results->{'outdated'}{$pkg};
            if ( !$info->{'update'} || $info->{'update'} ne 'major' ) {
                next;
            }
            return 1;
        }
    }

    if ( my $comp = $results->{'compromise_check'} ) {
        if ( $comp->{'summary'}{'error'} ) {
            return 1;
        }
        if ( $compromise_fail && ( $comp->{'summary'}{'matches'} || 0 ) > 0 ) {
            return 1;
        }
    }

    return 0;
}

sub determine_update_type {
    my ( $current, $latest ) = @_;

    if ( !defined $current || !defined $latest ) {
        return 'unknown';
    }

    my $current_parts = version_parts($current);
    my $latest_parts  = version_parts($latest);

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

sub version_parts {
    my ($version) = @_;
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

sub xml_escape {
    my ($text) = @_;
    if ( !defined $text ) {
        return q{};
    }
    my $escaped = $text;
    $escaped =~ s/&/&amp;/smxg;
    $escaped =~ s/</&lt;/smxg;
    $escaped =~ s/>/&gt;/smxg;
    $escaped =~ s/"/&quot;/smxg;
    $escaped =~ s/'/&apos;/smxg;
    return $escaped;
}

sub generate_purl {
    my ( $name, $version ) = @_;

    my $component = $name;
    $component =~ s/\@/%40/smx;

    return "pkg:npm/$component\@$version";
}

sub generate_uuid {
    my $hex  = [ 0 .. 9, 'a' .. 'f' ];
    my $rand = sub { $hex->[ int rand @{$hex} ] };

    return join q{},
        map { $_ } (
        map { $rand->() } 1 .. 8,
        q{-},
        map { $rand->() } 1 .. 4,
        q{-},
        map { $rand->() } 1 .. 4,
        q{-},
        map { $rand->() } 1 .. 4,
        q{-},
        map { $rand->() } 1 .. 12
        );
}

sub normalize_semver_spec {
    my ($spec) = @_;
    if ( !defined $spec ) {
        return;
    }

    my $normalized = $spec;
    $normalized =~ s/^\s+|\s+$//smxg;
    $normalized =~ s/^[\^~=\s]+//smx;

    return length $normalized ? $normalized : undef;
}

sub build_sbom_data {
    my ( $results, $sbom_cfg, $package_json, $tool_version, $koha_version ) = @_;

    $results      ||= {};
    $sbom_cfg     ||= {};
    $package_json ||= {};
    $tool_version ||= '1.0.0';
    $koha_version ||= q{};

    my $template_name = $sbom_cfg->{'template'} || 'dependency_sbom.xml.tt';

    my $include_dev = $sbom_cfg->{'include_dev_dependencies'} // 0;

    my $resolved = $results->{'resolved_dependencies'};

    my $scope_map = {
        'dependencies'    => 'required',
        'devDependencies' => 'development',
        'transitive'      => 'transitive',
    };

    my $seen       = {};
    my $components = [];

    if ( $resolved && @{ $resolved->{'packages'} || [] } ) {
        for my $entry ( @{ $resolved->{'packages'} } ) {
            my $name    = $entry->{'name'};
            my $version = $entry->{'version'};
            my $type    = $entry->{'type'} || 'transitive';

            if ( $type eq 'devDependencies' && !$include_dev ) {
                next;
            }

            my $scope = $scope_map->{$type} || 'unknown';
            my $key   = join q{|}, $name, $version, $scope;
            if ( $seen->{$key}++ ) {
                next;
            }

            push @{$components},
                _sbom_component( $name, $version, $scope );
        }
    } else {
        for my $name ( sort keys %{ $package_json->{'dependencies'} || {} } ) {
            my $version = $package_json->{'dependencies'}{$name};
            push @{$components},
                _sbom_component( $name, $version, $scope_map->{'dependencies'} );
        }

        if ($include_dev) {
            for my $name ( sort keys %{ $package_json->{'devDependencies'} || {} } ) {
                my $version = $package_json->{'devDependencies'}{$name};
                push @{$components},
                    _sbom_component( $name, $version, $scope_map->{'devDependencies'} );
            }
        }
    }

    my $timestamp   = strftime '%Y-%m-%dT%H:%M:%SZ', gmtime;
    my $serial      = generate_uuid();
    my $app_version = $koha_version || $package_json->{'version'} || 'unknown';

    my $data = {
        timestamp    => $timestamp,
        serial       => $serial,
        app_version  => $app_version,
        tool_name    => 'node_audit_dependencies.pl',
        tool_version => $tool_version,
        components   => $components,
    };

    return ( $template_name, $data );
}

sub _sbom_component {
    my ( $name, $version, $scope ) = @_;

    my $clean_version = $version // 'unknown';
    $clean_version =~ s/^[\^~><=v\s]+//smx;

    return {
        name    => $name,
        version => $clean_version || 'unknown',
        scope   => $scope,
        purl    => generate_purl( $name, $clean_version || 'unknown' ),
    };
}

sub detect_koha_version {
    my $project_root = eval { find_project_root() };
    if ( !$project_root ) {
        return;
    }

    my $path = catfile( $project_root, 'Koha.pm' );
    if ( !-f $path ) {
        return;
    }

    open my $fh, '<', $path or do {
        log_message( 'warn', 1, "Unable to open Koha.pm: $OS_ERROR" );
        return;
    };
    local $INPUT_RECORD_SEPARATOR = undef;
    my $content = <$fh>;
    close $fh;

    if ( $content && $content =~ /\$VERSION\s*=\s*["']([^"']+)["']/smx ) {
        return $1;
    }

    return;
}

sub build_bugzilla_report_data {
    my ( $results, $bugzilla_cfg ) = @_;

    $results      ||= {};
    $bugzilla_cfg ||= {};

    my $template_name = $bugzilla_cfg->{'template'} || 'dependency_bugzilla_report.md.tt';

    my $show_vulns =
        exists $bugzilla_cfg->{'show_vulnerabilities'}
        ? $bugzilla_cfg->{'show_vulnerabilities'}
        : 1;
    my $show_outdated =
        exists $bugzilla_cfg->{'show_outdated'}
        ? $bugzilla_cfg->{'show_outdated'}
        : 1;
    my $show_next_steps =
        exists $bugzilla_cfg->{'show_next_steps'}
        ? $bugzilla_cfg->{'show_next_steps'}
        : 1;
    my $include_summary =
        exists $bugzilla_cfg->{'summary'}
        ? $bugzilla_cfg->{'summary'}
        : 1;

    my $dependency_path_limit = $bugzilla_cfg->{'dependency_path_limit'} // 0;
    my $severity_order_cfg    = $bugzilla_cfg->{'severity_order'};
    my $metadata_static       = $bugzilla_cfg->{'metadata'};
    my $metadata_env          = $bugzilla_cfg->{'metadata_env'};

    my $default_severity_order = [qw(critical high moderate low info unknown)];
    my $severity_order = [ @{ ref $severity_order_cfg eq 'ARRAY' ? $severity_order_cfg : $default_severity_order } ];

    my $severity_rank = {};
    for my $idx ( 0 .. $#{$severity_order} ) {
        my $key = lc $severity_order->[$idx];
        $severity_rank->{$key} = $idx;
    }
    my $fallback_rank = scalar @{$severity_order};

    my $vuln_source     = $results->{'vulnerabilities'} || [];
    my $outdated_source = $results->{'outdated'}        || {};

    my $severity_counts    = {};
    my $vulnerability_rows = [];

    my $ordered_severities = [];

    if ($show_vulns) {
        for my $vuln ( @{$vuln_source} ) {
            my $severity = lc( $vuln->{'severity'} // 'unknown' );
            my $rank     = exists $severity_rank->{$severity} ? $severity_rank->{$severity} : $fallback_rank;
            $severity_counts->{$severity}++;

            my $paths   = [ @{ $vuln->{'dependency_paths'} || [] } ];
            my $omitted = 0;
            if ( $dependency_path_limit && $dependency_path_limit > 0 && @{$paths} > $dependency_path_limit ) {
                $omitted = @{$paths} - $dependency_path_limit;
                @{$paths} = @{$paths}[ 0 .. $dependency_path_limit - 1 ];
            }

            my $direct_list = [];
            for my $dep ( @{ $vuln->{'direct_dependencies'} || [] } ) {
                my $scope =
                      ( $dep->{'type'} && $dep->{'type'} eq 'devDependencies' ) ? 'dev'
                    : ( $dep->{'type'} && $dep->{'type'} eq 'dependencies' )    ? 'prod'
                    :                                                             'unknown';
                my @pieces = ( sprintf '%s (%s)', $dep->{'name'} // q{}, $scope );
                if ( my $spec = $dep->{'version_spec'} ) {
                    push @pieces, sprintf 'spec %s', $spec;
                }
                if ( my $resolved = $dep->{'resolved_version'} ) {
                    push @pieces, sprintf 'resolved %s', $resolved;
                }
                push @{$direct_list},
                    {
                    info => join '; ', @pieces,
                    };
            }

            push @{$vulnerability_rows},
                {
                package                  => $vuln->{'package'} // q{},
                severity                 => $severity,
                severity_label           => uc $severity,
                _severity_rank           => $rank,
                current_version          => $vuln->{'current_version'} // 'unknown',
                fixed_in                 => $vuln->{'fixed_in'},
                recommendation           => $vuln->{'recommendation'},
                url                      => $vuln->{'url'},
                dependency_paths         => $paths,
                dependency_paths_omitted => $omitted,
                direct_dependencies      => $direct_list,
                };
        }

        @{$vulnerability_rows} = sort {
                   ( $a->{_severity_rank} <=> $b->{_severity_rank} )
                || ( lc( $a->{package} ) cmp lc( $b->{package} ) )
                || ( ( $a->{current_version} // q{} ) cmp( $b->{current_version} // q{} ) )
        } @{$vulnerability_rows};

        for my $entry ( @{$vulnerability_rows} ) {
            delete $entry->{_severity_rank};
        }

        my $seen = {};
        for my $sev ( @{$severity_order} ) {
            if ( !$severity_counts->{$sev} ) {
                next;
            }
            push @{$ordered_severities}, $sev;
            $seen->{$sev} = 1;
        }
        for my $sev ( sort keys %{$severity_counts} ) {
            if ( $seen->{$sev} ) {
                next;
            }
            push @{$ordered_severities}, $sev;
        }
    }

    my $outdated_rows        = [];
    my $update_counts        = {};
    my $default_update_order = [qw(major minor patch up-to-date unknown)];
    my $update_seen          = {};
    my $ordered_updates      = [];

    if ($show_outdated) {
        for my $pkg ( sort keys %{$outdated_source} ) {
            my $info   = $outdated_source->{$pkg} || {};
            my $update = lc( $info->{'update'} // 'unknown' );
            $update_counts->{$update}++;

            push @{$outdated_rows},
                {
                name     => $pkg,
                current  => $info->{'current'} // 'unknown',
                wanted   => $info->{'wanted'}  // 'unknown',
                latest   => $info->{'latest'}  // 'unknown',
                resolved => $info->{'resolved'},
                scope    => $info->{'scope'},
                update   => $info->{'update'} // 'unknown',
                };
        }

        for my $type ( @{$default_update_order} ) {
            if ( !$update_counts->{$type} ) {
                next;
            }
            push @{$ordered_updates}, $type;
            $update_seen->{$type} = 1;
        }
        for my $type ( sort keys %{$update_counts} ) {
            if ( $update_seen->{$type} ) {
                next;
            }
            push @{$ordered_updates}, $type;
        }
    }

    my $summary = {
        vulnerabilities => {
            total           => $show_vulns ? scalar @{$vulnerability_rows} : 0,
            severity_counts => $show_vulns ? $severity_counts              : {},
            hidden          => $show_vulns ? 0                             : scalar @{$vuln_source},
            severity_order  => $show_vulns ? $ordered_severities           : [],
        },
        outdated => {
            total         => $show_outdated ? scalar @{$outdated_rows} : 0,
            update_counts => $show_outdated ? $update_counts           : {},
            hidden        => $show_outdated ? 0                        : scalar keys %{$outdated_source},
            update_order  => $show_outdated ? $ordered_updates         : [],
        },
    };

    my $metadata = {};
    if ( ref $metadata_static eq 'HASH' && keys %{$metadata_static} ) {
        $metadata = { %{$metadata_static} };
    }

    if ( ref $metadata_env eq 'ARRAY' ) {
        for my $entry ( @{$metadata_env} ) {
            if ( !defined $entry ) {
                next;
            }
            my ( $label, $env_key );
            if ( ref $entry eq 'HASH' ) {
                ( $label, $env_key ) = each %{$entry};
            } elsif ( $entry =~ /\A(.+?)=(.+)\z/smx ) {
                ( $label, $env_key ) = ( $1, $2 );
            } else {
                $label   = $entry;
                $env_key = $entry;
            }
            if ( !defined $env_key || $env_key eq q{} ) {
                next;
            }
            my $value = $ENV{$env_key};
            if ( !defined $value || $value eq q{} ) {
                next;
            }
            $metadata->{$label} = $value;
        }
    }

    my $metadata_payload = ( keys %{$metadata} ) ? $metadata : undef;

    my $payload = {
        generated_at    => $results->{'generated_at'},
        tool            => $results->{'tool'},
        vulnerabilities => $vulnerability_rows,
        outdated        => $outdated_rows,
        summary         => $include_summary ? $summary : undef,
        metadata        => $metadata_payload,
        config          => {
            show_vulnerabilities  => $show_vulns      ? 1 : 0,
            show_outdated         => $show_outdated   ? 1 : 0,
            show_next_steps       => $show_next_steps ? 1 : 0,
            include_summary       => $include_summary ? 1 : 0,
            dependency_path_limit => $dependency_path_limit,
            severity_order        => $severity_order,
        },
    };

    return ( $template_name, $payload );
}

1;

__END__

=head1 NAME

Node::Utils - Utility functions for Node.js dependency management

=head1 SYNOPSIS

    use Node::Utils qw(log_message safe_json_decode);

    log_message('info', 1, 'Processing dependencies');
    my $data = safe_json_decode($json_string);

=head1 DESCRIPTION

This module provides reusable utility functions for Node.js dependency
management operations including logging, configuration loading, JSON parsing,
and command execution.

=head1 FUNCTIONS

=head2 log_message($level, $verbose, $message)

Outputs a timestamped log message to STDERR. Debug and info messages are only
emitted when C<$verbose> is truthy; warnings and errors are always printed.

=head2 load_config($config_file)

Loads and parses a YAML configuration file.

=head2 find_project_root()

Finds the project root directory by looking for package.json.

=head2 detect_package_manager()

Detects which package manager is being used (yarn or npm).

=head2 run_command($command, $args_ref)

Executes a command with proper error handling.

=head2 safe_json_decode($json_string)

Safely decodes JSON with error handling.

=head2 change_to_project_root()

Changes to the project root directory.

=head2 map_dependency_info($packages, $name, $direct_deps)

Augments C<$packages->{$name}> with direct dependency metadata.

=head2 load_package_json($root)

Loads and decodes F<package.json> from the provided project root.

=head2 build_direct_dependency_map($package_json)

Builds a lookup hash describing each direct dependency, including its type and
version specification.

=head2 write_json_results($output, $data, $verbose)

Writes combined JSON results to disk and emits an informational log message
when verbosity permits.

=head2 parse_compromise_line($line)

Parses a single package identifier used by the compromise helper, supporting
scoped packages and explicit version specifiers.

=head2 run_compromise_check($queries, $resolved_data, $verbose)

Evaluates compromise queries against the resolved dependency graph and returns
match summaries.

=head2 build_resolved_index($packages)

Builds a hash index of resolved packages keyed by name and version.

=head2 determine_exit_code($results, $thresholds)

Computes the dependency-check exit code based on configured thresholds and the
aggregated results structure.

=head2 determine_update_type($current, $latest)

Determines type of update needed (major, minor, patch, up-to-date).

=head2 version_parts($version)

Extracts numeric version parts from version string.

=head2 xml_escape($text)

Escapes text for XML output.

=head2 generate_purl($name, $version)

Generates package URL (purl) for npm package.

=head2 generate_uuid()

Generates a random UUID v4.

=head2 normalize_semver_spec($spec)

Normalizes a semver specification by trimming whitespace and stripping leading
range operators (for example C<^>, C<~>, or C<=>). Returns the cleaned version
string, or C<undef> if nothing meaningful remains.

=head2 build_sbom_data($results, $sbom_cfg, $package_json, $tool_version, $koha_version)

Builds the data structure and selects the template required to generate the
CycloneDX SBOM report. The returned list contains the template filename and a
hashref with timestamps, tool metadata, and the component list filtered by the
supplied configuration.

=head2 build_bugzilla_report_data($results, $bugzilla_cfg)

Assembles vulnerability and outdated dependency data for the Bugzilla Markdown
report. Configuration flags control which sections are included, severity
ordering, and any metadata overrides merged into the rendered output.

=head2 detect_koha_version()

Attempts to read C<$VERSION> from F<Koha.pm> located at the project root and
returns it when available. Returns C<undef> if the version cannot be found.

=head1 AUTHOR

Koha Development Team

=head1 COPYRIGHT

Copyright 2025 Koha Development Team

=cut
