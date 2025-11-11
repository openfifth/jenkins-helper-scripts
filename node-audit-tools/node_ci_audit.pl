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
use File::Basename        qw(dirname);
use File::Spec::Functions qw(catdir catfile updir);
use FindBin               qw($Bin);
my $script_dir   = abs_path($Bin);
my $project_root = abs_path( catdir( $script_dir, updir(), updir() ) );

use Node::Utils qw(
    load_config
    change_to_project_root
    detect_package_manager
    run_command
);

sub main {
    my $check_script = catfile( $project_root, 'misc', 'devel', 'node_audit_dependencies.pl' );
    my $config_file  = catfile( $project_root, 'misc', 'devel', 'node_audit_config.yml' );

    if ( !-f $check_script ) {
        croak "node_audit_dependencies.pl not found at $check_script\n";
    }
    if ( !-f $config_file ) {
        croak "Configuration file not found at $config_file\n";
    }

    my $config = load_config($config_file);

    my $tool = detect_package_manager();

    say 'Koha Node.js dependency check'   or croak;
    say "Detected package manager: $tool" or croak;

    my $tool_conf   = $config->{'tools'}{$tool} || {};
    my $install_cmd = $tool_conf->{'install'}   || q{};
    my $config_path = $config_file;    # used later

    if ( !$install_cmd ) {
        croak "Install command not configured for $tool\n";
    }

    say "Install command: $install_cmd" or croak;

    change_to_project_root($project_root);

    say 'Installing dependencies with frozen lockfile...' or croak;
    my @cmd_parts = split /\s+/smx, $install_cmd;
    my @args      = @cmd_parts[ 1 .. $#cmd_parts ];
    my ( $output, $exit_code ) = run_command( $cmd_parts[0], \@args );
    if ( $exit_code != 0 ) {
        croak 'Installing dependencies failed';
    }

    my $env = {%ENV};

    my ( $cmd_ref, $stdin_path, $stdin_label ) = build_dependency_command(
        {
            'config_file'  => $config_path,
            'check_script' => $check_script,
            'env'          => $env,
        }
    );

    my $system_exit_code;
    if ($stdin_path) {
        open my $stdin_fh, '<', $stdin_path
            or croak "Unable to open stdin file $stdin_path: $OS_ERROR";
        {
            local *STDIN = $stdin_fh;
            $system_exit_code = system { $cmd_ref->[0] } @{$cmd_ref};
        }
        close $stdin_fh;
    } else {
        $system_exit_code = system { $cmd_ref->[0] } @{$cmd_ref};
    }

    my $rc = $system_exit_code >> 8;

    say "Dependency check completed with exit code: $rc" or croak;

    if ( defined $stdin_label && length $stdin_label ) {
        say "  - Compromise check input: $stdin_label" or croak;
    }

    if ( $stdin_path && ( $env->{NODE_DEP_CHECK_INPUT_FILE} // q{} ) eq q{} ) {
        unlink $stdin_path;
    }

    return $rc;
}

# Call main function and exit with its return code
exit main();

sub build_dependency_command {
    my ($args) = @_;

    my $config_file  = $args->{config_file};
    my $check_script = $args->{check_script};
    my $env          = $args->{env} || {};

    my $modes_raw =
        exists $env->{NODE_DEP_CHECK_MODES} && length $env->{NODE_DEP_CHECK_MODES}
        ? $env->{NODE_DEP_CHECK_MODES}
        : 'outdated,audit,sbom,bugzilla';

    my $mode_tokens = [ grep { length } map { lc s/\s+//smxgr } split /,/smx, $modes_raw ];

    my $mode_flags = {
        outdated         => '--outdated',
        audit            => '--audit',
        sbom             => '--sbom',
        bugzilla         => '--bugzilla',
        compromise       => '--check-packages',
        'check-packages' => '--check-packages',
    };

    my $selected;
    for my $token ( @{$mode_tokens} ) {
        next if !exists $mode_flags->{$token};
        $selected->{ $mode_flags->{$token} } = 1;
    }

    if ( !%{$selected} ) {
        $mode_tokens = [qw(outdated audit sbom bugzilla)];
        $selected    = { map { $mode_flags->{$_} => 1 } @{$mode_tokens} };
    }

    my $compromise = delete $selected->{'--check-packages'};
    if ($compromise) {
        if ( %{$selected} ) {
            croak 'Compromise mode cannot be combined with other dependency-check modes';
        }

        my $comp_script = catfile( $project_root, 'misc', 'devel', 'node_audit_compromise.pl' );
        my $cmd         = [ 'perl', $comp_script, '--config-file', $config_file ];

        if ( !exists $env->{NODE_DEP_CHECK_VERBOSE} || $env->{NODE_DEP_CHECK_VERBOSE} ne '0' ) {
            push @{$cmd}, '--verbose';
        }

        my $json_output = $env->{NODE_DEP_CHECK_JSON} // catfile( $project_root, 'dependency_check_results.json' );
        if ( length $json_output ) {
            push @{$cmd}, '--json', $json_output;
        }

        my $stdin_label;
        if ( my $input_file = $env->{NODE_DEP_CHECK_INPUT_FILE} ) {
            if ( !-e $input_file ) {
                croak "Compromise input file '$input_file' not found\n";
            }
            push @{$cmd}, '--input-file', $input_file;
            $stdin_label = $input_file;
        } elsif ( defined $env->{NODE_DEP_CHECK_INPUT} && length $env->{NODE_DEP_CHECK_INPUT} ) {
            push @{$cmd}, '--inline', $env->{NODE_DEP_CHECK_INPUT};
            $stdin_label = 'NODE_DEP_CHECK_INPUT';
        } else {
            croak "Compromise mode requested but NODE_DEP_CHECK_INPUT_FILE or NODE_DEP_CHECK_INPUT not provided\n";
        }

        return ( $cmd, undef, $stdin_label );
    }

    my $cmd = [ 'perl', $check_script, '--config-file', $config_file ];

    if ( !exists $env->{NODE_DEP_CHECK_VERBOSE} || $env->{NODE_DEP_CHECK_VERBOSE} ne '0' ) {
        push @{$cmd}, '--verbose';
    }

    my $json_output = $env->{NODE_DEP_CHECK_JSON} // catfile( $project_root, 'dependency_check_results.json' );
    if ( length $json_output ) {
        push @{$cmd}, '--json', $json_output;
    }

    push @{$cmd}, sort keys %{$selected};

    return ( $cmd, undef, undef );
}

__END__

=head1 NAME

node_ci_audit.pl - CI-oriented wrapper for node_audit_dependencies.pl

=head1 DESCRIPTION

Installs Node.js dependencies using the configured package manager and then
invokes L<misc/devel/node_audit_dependencies.pl> (or the compromise helper) with
the appropriate flags for continuous integration jobs.

=head1 ENVIRONMENT

The following environment variables alter the behaviour of the script:

=over 4

=item * C<NODE_DEP_CHECK_MODES> - comma-separated list of modes to run. Defaults
to C<outdated,audit,sbom,bugzilla>. Include C<compromise> to run
C<node_audit_compromise.pl> instead.

=item * C<NODE_DEP_CHECK_JSON> - path for the combined JSON output
(defaults to F<dependency_check_results.json> in the project root).

=item * C<NODE_DEP_CHECK_VERBOSE> - set to C<0> to disable the C<--verbose> flag.

=item * C<NODE_DEP_CHECK_INPUT_FILE>, C<NODE_DEP_CHECK_INPUT> - sources for
compromise queries when C<compromise> mode is selected.

=back

=head1 OUTPUT

When the JSON output is enabled, refer to the structure documented in
L<misc/devel/node_audit_dependencies.pl>. Typical CI checks include:

=over 4

=item * C<jq '.vulnerability_summary' dependency_check_results.json> - severity
counts for audit findings.

=item * C<jq '.outdated_summary' dependency_check_results.json> - upgrade counts
per update cadence.

=back

=head1 EXIT STATUS

The wrapper returns the exit code from the underlying audit script so that CI
systems can fail the job when thresholds are exceeded.

=head1 AUTHOR

Koha Development Team

=head1 COPYRIGHT

Copyright 2025 Koha

=cut
