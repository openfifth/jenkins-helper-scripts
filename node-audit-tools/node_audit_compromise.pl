#!/usr/bin/perl

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

use Carp                  qw(croak);
use Cwd                   qw(abs_path);
use English               qw(-no_match_vars);
use File::Spec::Functions qw(catfile);
use Getopt::Long          qw(GetOptions);
use POSIX                 qw(strftime isatty);
use Pod::Usage            qw(pod2usage);

use FindBin;
use lib $FindBin::Bin;

use Node::Utils qw(
    log_message
    load_config
    find_project_root
    detect_package_manager
    change_to_project_root
    load_package_json
    build_direct_dependency_map
    parse_compromise_line
    run_compromise_check
    write_json_results
    determine_exit_code
);

use Node::Package::Manager::Base;
use Node::Package::Manager::Yarn;
use Node::Package::Manager::Npm;

sub main {
    my $opt_config_file = q{};
    my $opt_json_output = q{};
    my $opt_input_file  = q{};
    my $opt_inline      = q{};
    my $opt_stdin       = 0;
    my $opt_verbose     = 0;
    my $opt_help        = 0;

    GetOptions(
        'config-file=s' => \$opt_config_file,
        'json=s'        => \$opt_json_output,
        'input-file=s'  => \$opt_input_file,
        'inline=s'      => \$opt_inline,
        'stdin'         => \$opt_stdin,
        'verbose'       => \$opt_verbose,
        'help'          => \$opt_help,
    ) or pod2usage(2);

    if ($opt_help) {
        pod2usage(0);
    }

    my $queries = build_queries(
        {
            input_file => $opt_input_file,
            inline     => $opt_inline,
            stdin      => $opt_stdin,
        }
    );

    my $script_dir  = $FindBin::Bin;
    my $default_cfg = catfile( $script_dir, 'node_audit_config.yml' );
    my $config_path = $opt_config_file ? abs_path($opt_config_file) : $default_cfg;
    if ($opt_config_file) {
        $config_path //= $opt_config_file;
    }

    my $config       = load_config($config_path);
    my $project_root = find_project_root();
    my $package_json = load_package_json($project_root);
    my $direct_deps  = build_direct_dependency_map($package_json);
    my $tool         = detect_package_manager();

    my $tool_cfg = {};
    if ( $config && ref $config eq 'HASH' && $config->{'tools'} && $config->{'tools'}{$tool} ) {
        $tool_cfg = $config->{'tools'}{$tool};
    }

    my $strategy = create_package_manager_strategy($tool);
    my $resolved_data =
        $strategy->build_resolved_dependency_data( $tool_cfg, $direct_deps, $project_root, $opt_verbose );

    if ( $resolved_data && $resolved_data->{'direct'} ) {
        for my $section (qw(dependencies devDependencies)) {
            my $resolved_section = $resolved_data->{'direct'}{$section} || {};
            for my $name ( keys %{$resolved_section} ) {
                next if !$direct_deps->{$name};
                next if $direct_deps->{$name}{'type'} ne $section;
                $direct_deps->{$name}{'resolved_version'} = $resolved_section->{$name};
            }
        }
    }

    change_to_project_root($project_root);

    log_message( 'info', $opt_verbose, "Using package manager: $tool" );

    my $results = {
        'tool'         => $tool,
        'generated_at' => strftime( '%Y-%m-%dT%H:%M:%SZ', gmtime ),
        'metadata'     => {
            'project_root' => $project_root,
            'config_file'  => $config_path,
        },
        'direct_dependencies'   => $direct_deps,
        'resolved_dependencies' => $resolved_data,
    };

    my $compromise = run_compromise_check( $queries, $resolved_data, $opt_verbose );
    $results->{'compromise_check'} = $compromise;

    my $json_output;
    if ( defined $opt_json_output && length $opt_json_output ) {
        $json_output = $opt_json_output;
    } else {
        $json_output = catfile( $project_root, 'dependency_check_results.json' );
    }

    write_json_results( $json_output, $results, $opt_verbose );

    my $thresholds = {};
    if ( $config && ref $config eq 'HASH' && $config->{'thresholds'} ) {
        $thresholds = $config->{'thresholds'};
    }

    my $exit_code = determine_exit_code( $results, $thresholds );
    log_message( 'info', $opt_verbose, "Exit code: $exit_code" );
    return $exit_code;
}

sub build_queries {
    my ($args) = @_;

    my $lines = [];

    if ( my $file = $args->{input_file} ) {
        if ( !-e $file ) {
            croak "Input file '$file' not found";
        }
        open my $fh, '<', $file or croak "Cannot open $file: $OS_ERROR";
        push @{$lines}, <$fh>;
        close $fh or croak;
    }

    if ( defined $args->{inline} && length $args->{inline} ) {
        push @{$lines}, map { "$_\n" } split /\n/smx, $args->{inline};
    }

    my $should_read_stdin = $args->{stdin};
    if ( !$should_read_stdin && !@{$lines} ) {
        my $stdin_fd = fileno STDIN;
        if ( !defined $stdin_fd || !isatty($stdin_fd) ) {
            $should_read_stdin = 1;
        }
    }

    if ($should_read_stdin) {
        push @{$lines}, <STDIN>;
    }

    my $queries = [];
    for my $raw_line ( @{$lines} ) {
        my $line = $raw_line;
        $line =~ s/\r?\n$//smx;
        my $trimmed = $line;
        $trimmed =~ s/^\s+|\s+$//smxg;

        if ( $trimmed eq q{} ) {
            next;
        }
        if ( index( $trimmed, q{#} ) == 0 ) {
            next;
        }
        if ( $trimmed =~ /^\s*\/\//smx ) {
            next;
        }

        my $parsed = parse_compromise_line($trimmed);
        if ( $parsed->{'error'} ) {
            push @{$queries},
                {
                'input' => $trimmed,
                'error' => $parsed->{'error'},
                };
        } else {
            $parsed->{'input'} = $trimmed;
            push @{$queries}, $parsed;
        }
    }

    return $queries;
}

sub create_package_manager_strategy {
    my ($tool) = @_;

    if ( $tool eq 'yarn' ) {
        return Node::Package::Manager::Yarn->new;
    } elsif ( $tool eq 'npm' ) {
        return Node::Package::Manager::Npm->new;
    }

    croak "Unsupported package manager: $tool";
}

exit main();

__END__

=head1 NAME

node_audit_compromise.pl - Standalone Node.js compromise detection helper

=head1 SYNOPSIS

    node_audit_compromise.pl [options]

=head1 DESCRIPTION

Reads a list of package identifiers, resolves the current dependency graph, and
reports matches. Output is emitted as JSON for downstream automation, and exit
codes honour the thresholds defined in C<misc/devel/node_audit_config.yml>.

=head1 OPTIONS

=over 4

=item B<--input-file FILE>

Read package identifiers from FILE (one per line).

=item B<--inline STRING>

Provide newline-separated package identifiers directly on the command line.

=item B<--stdin>

Force reading package identifiers from STDIN. When neither C<--input-file> nor
C<--inline> is provided, the script automatically reads STDIN when it is not a
TTY.

=item B<--config-file FILE>

Use an alternate configuration file. Defaults to
C<misc/devel/node_audit_config.yml>.

=item B<--json FILE>

Write combined JSON results to FILE. Defaults to
C<dependency_check_results.json> in the project root.

=item B<--verbose>

Emit debug logging.

=item B<--help>

Show usage information.

=back

=head1 OUTPUT

The JSON payload mirrors the structure produced by
C<node_audit_dependencies.pl> and adds a C<compromise_check> section with:

=over 4

=item * C<summary> - totals for matches, missing packages, and invalid inputs.

=item * C<queries> - per-identifier results containing C<status> (C<match>,
C<no-match>, or C<invalid>), the normalised package name, and resolved versions.

=back

Helpful C<jq> snippets when reviewing the output:

=over 4

=item * C<jq '.compromise_check.summary' dependency_check_results.json> - quick
totals for compromise queries.

=item * C<jq '.compromise_check.queries[] | select(.status==\"match\")' dependency_check_results.json>
- list only matching packages.

=back

Exit codes follow the threshold settings defined in
C<misc/devel/node_audit_config.yml>; the helper exits non-zero when a match is
found and C<compromise_fail_on_match> is enabled.

=head1 AUTHOR

Koha Development Team

=head1 COPYRIGHT

Copyright 2025 Koha

=cut
