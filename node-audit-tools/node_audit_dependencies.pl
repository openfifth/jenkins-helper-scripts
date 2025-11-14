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

our $VERSION = '1.0.0';

use Carp                  qw(croak);
use Cwd                   qw(abs_path getcwd);
use English               qw(-no_match_vars);
use File::Basename        qw(dirname);
use File::Spec::Functions qw(catfile catdir updir);
use Getopt::Long          qw(GetOptions);
use JSON                  qw(decode_json encode_json);
use POSIX                 qw(strftime);
use Pod::Usage            qw(pod2usage);
use YAML                  qw(LoadFile);
use Template;

use Node::Utils qw(
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
    generate_purl
    generate_uuid
    normalize_semver_spec
    load_package_json
    build_direct_dependency_map
    write_json_results
    determine_exit_code
    build_bugzilla_report_data
    build_sbom_data
    detect_koha_version
);

use Node::Package::Manager::Base;
use Node::Package::Manager::Yarn;
use Node::Package::Manager::Npm;

sub get_context {
    state $context = {};
    return $context;
}

sub set_context {
    my ( $key, $value ) = @_;
    get_context()->{$key} = $value;
    return;
}

sub get_verbose {
    return get_context()->{'verbose'} // 0;
}

sub get_config {
    return get_context()->{'config'} // {};
}

sub get_project_root {
    return get_context()->{'project_root'};
}

sub get_tool {
    return get_context()->{'tool'};
}

sub get_tool_config {
    return get_context()->{'tool_config'} // {};
}

sub get_template_dir {
    return get_context()->{'template_dir'};
}

sub get_direct_deps {
    return get_context()->{'direct_deps'} // {};
}

sub get_resolved_data {
    return get_context()->{'resolved_data'};
}

sub get_package_json {
    return get_context()->{'package_json'} // {};
}

sub initialize_context {
    my ($args) = @_;

    set_context( 'verbose',       $args->{'verbose'} // 0 );
    set_context( 'config',        $args->{'config'}  // {} );
    set_context( 'project_root',  $args->{'project_root'} );
    set_context( 'tool',          $args->{'tool'} );
    set_context( 'tool_config',   $args->{'tool_config'} // {} );
    set_context( 'direct_deps',   $args->{'direct_deps'} // {} );
    set_context( 'resolved_data', $args->{'resolved_data'} );
    set_context( 'package_json',  $args->{'package_json'} // {} );
    set_context( 'template_dir',  $args->{'template_dir'} );

    return;
}

sub create_package_manager_strategy {
    my ($tool) = @_;

    if ( $tool eq 'yarn' ) {
        return Node::Package::Manager::Yarn->new;
    } elsif ( $tool eq 'npm' ) {
        return Node::Package::Manager::Npm->new;
    } else {
        croak "Unsupported package manager: $tool";
    }
}

sub main {
    my $opt_outdated     = 0;
    my $opt_audit        = 0;
    my $opt_sbom         = 0;
    my $opt_bugzilla     = 0;
    my $opt_junit        = 0;
    my $opt_verbose      = 0;
    my $opt_config_file  = q{};
    my $opt_template_dir = q{};
    my $opt_json_output  = q{};
    my $opt_help         = 0;

    GetOptions(
        'outdated'       => \$opt_outdated,
        'audit'          => \$opt_audit,
        'sbom'           => \$opt_sbom,
        'bugzilla'       => \$opt_bugzilla,
        'junit'          => \$opt_junit,
        'verbose'        => \$opt_verbose,
        'config-file=s'  => \$opt_config_file,
        'template-dir=s' => \$opt_template_dir,
        'json=s'         => \$opt_json_output,
        'help'           => \$opt_help,
    ) or pod2usage(2);

    if ($opt_help) {
        pod2usage(0);
    }

    if ( !$opt_outdated && !$opt_audit && !$opt_sbom && !$opt_bugzilla && !$opt_junit ) {
        $opt_outdated = 1;
        $opt_audit    = 1;
        $opt_sbom     = 1;
        $opt_bugzilla = 1;
        $opt_junit    = 1;
    }

    my $script_dir   = dirname( abs_path($PROGRAM_NAME) );
    my $template_dir = $opt_template_dir
        ? abs_path($opt_template_dir)
        : catdir( $script_dir, q{..}, q{..}, 'Koha', 'Devel', 'Node', 'templates' );
    my $default_cfg  = catfile( $script_dir, 'node_audit_config.yml' );
    my $config_path  = $opt_config_file ? abs_path($opt_config_file) : $default_cfg;
    if ($opt_config_file) {
        $config_path //= $opt_config_file;
    }
    my $config       = load_config($config_path);
    my $project_root = find_project_root();
    my $package_json = load_package_json($project_root);
    my $direct_deps  = build_direct_dependency_map($package_json);
    my $tool         = detect_package_manager();
    my $tool_cfg     = {};
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
                if ( !$direct_deps->{$name} ) {
                    next;
                }
                if ( $direct_deps->{$name}{'type'} ne $section ) {
                    next;
                }
                $direct_deps->{$name}{'resolved_version'} = $resolved_section->{$name};
            }
        }
    }

    initialize_context(
        {
            'verbose'       => $opt_verbose,
            'config'        => $config,
            'project_root'  => $project_root,
            'tool'          => $tool,
            'tool_config'   => $tool_cfg,
            'direct_deps'   => $direct_deps,
            'resolved_data' => $resolved_data,
            'package_json'  => $package_json,
            'template_dir'  => $template_dir,
        }
    );

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

    if ($opt_outdated) {
        my ( $outdated, $summary ) =
            $strategy->run_outdated_check( get_tool_config(), get_direct_deps(), get_verbose() );
        $results->{'outdated'}         = $outdated;
        $results->{'outdated_summary'} = $summary;
    }

    if ($opt_audit) {
        my ( $vulns, $summary ) = $strategy->run_audit_check( get_tool_config(), get_direct_deps(), get_verbose() );
        $results->{'vulnerabilities'}       = $vulns;
        $results->{'vulnerability_summary'} = $summary;
    }

    if ($opt_sbom) {
        my $sbom_config = get_config()->{'sbom'} // {};
        generate_sbom_output( $results, $sbom_config );
    }

    if ($opt_bugzilla) {
        my $bugzilla_config = get_config()->{'bugzilla'} // {};
        generate_bugzilla_report( $results, $bugzilla_config );
    }

    if ($opt_junit) {
        my $junit_config = get_config()->{'junit'} // {};
        generate_junit_output( $results, $junit_config );
    }

    if ($opt_json_output) {
        write_json_results( $opt_json_output, $results, get_verbose() );
    }

    my $thresholds = {};
    if ( $config && ref $config eq 'HASH' && $config->{'thresholds'} ) {
        $thresholds = $config->{'thresholds'};
    }
    my $exit_code = determine_exit_code( $results, $thresholds );
    log_message( 'info', $opt_verbose, "Exit code: $exit_code" );
    return $exit_code;
}

exit main();

sub generate_sbom_output {
    my ( $results, $sbom_cfg ) = @_;

    my $output_file = $sbom_cfg->{'output_file'}
        || 'node_modules_sbom.xml';
    my $koha_version = detect_koha_version();
    my ( $template_name, $data ) =
        build_sbom_data( $results, $sbom_cfg, get_package_json(), $VERSION, $koha_version );

    process_template( $template_name, $data, $output_file );

    log_message( 'info', get_verbose(), "SBOM generated at $output_file" );
    return;
}

sub generate_bugzilla_report {
    my ( $results, $bugzilla_cfg ) = @_;

    my $output_file = $bugzilla_cfg->{'output_file'}
        || 'dependency_bugzilla_report.md';
    my ( $template_name, $data ) = build_bugzilla_report_data( $results, $bugzilla_cfg );

    process_template( $template_name, $data, $output_file );

    log_message( 'info', get_verbose(), "Bugzilla report generated at $output_file" );

    return;
}

sub generate_junit_output {
    my ( $results, $junit_cfg ) = @_;

    my $output_file = $junit_cfg->{'output_file'}
        || 'junit_npm_audit.xml';

    my $vuln_summary = $results->{'vulnerability_summary'} // {};
    my $vulnerabilities = $results->{'vulnerabilities'} // [];

    # Count totals
    my $total_tests = 0;
    my $failures = 0;
    my $errors = 0;

    # Count vulnerability test cases
    my $sev_counts = $vuln_summary->{'severity_counts'} // {};
    my $critical   = $sev_counts->{'critical'}          // 0;
    my $high       = $sev_counts->{'high'}              // 0;
    my $moderate   = $sev_counts->{'moderate'}          // 0;
    my $low        = $sev_counts->{'low'}               // 0;

    $total_tests += $critical + $high + $moderate + $low;
    $failures += $critical + $high;      # Critical and high are failures
    $errors += $moderate;                # Moderate are errors

    # If no vulnerabilities, add one passing test
    if ($total_tests == 0) {
        $total_tests = 1;
    }

    my $timestamp = $results->{'generated_at'} // strftime( '%Y-%m-%dT%H:%M:%SZ', gmtime );

    # Prepare vulnerability data for template
    my @template_vulns = map {
        my $cves = $_->{'cves'} // [];
        my $cve_str = @{$cves} ? join(', ', @{$cves}) : 'No CVE';
        {
            'package'             => $_->{'package'} // 'unknown',
            'severity'            => $_->{'severity'} // 'unknown',
            'title'               => $_->{'title'} // 'Security vulnerability',
            'cve_str'             => $cve_str,
            'vulnerable_versions' => $_->{'vulnerable_versions'} // 'unknown',
            'patched_versions'    => $_->{'patched_versions'} // 'none',
        };
    } @{$vulnerabilities};

    my $data = {
        'total_tests'     => $total_tests,
        'failures'        => $failures,
        'errors'          => $errors,
        'timestamp'       => $timestamp,
        'vulnerabilities' => \@template_vulns,
    };

    my $template_name = catfile( get_template_dir(), 'junit_audit.xml.tt' );
    process_template( $template_name, $data, $output_file );

    log_message( 'info', get_verbose(), "JUnit XML generated at $output_file" );

    return;
}

sub process_template {
    my ( $template_name, $vars, $output_file ) = @_;

    my $template_dir = get_template_dir();
    my $include_path = [ grep { defined && length } ($template_dir) ];

    my $cache_key = join q{|}, @{$include_path} ? @{$include_path} : ('__none__');
    state $template_cache;

    my $tt = $template_cache->{$cache_key};
    if ( !$tt ) {
        my $config = {
            ABSOLUTE => 1,
            ENCODING => 'utf8',
        };
        if ( @{$include_path} ) {
            $config->{INCLUDE_PATH} = $include_path;
        }

        $tt = Template->new($config)
            or croak Template->error;
        $template_cache->{$cache_key} = $tt;
    }

    my $options = { binmode => ':utf8' };
    $tt->process( $template_name, $vars, $output_file, $options )
        or croak $tt->error;

    return;
}

__END__

=head1 NAME

node_audit_dependencies.pl - Node.js dependency management and security audit tool

=head1 SYNOPSIS

    node_audit_dependencies.pl [options]

=head1 DESCRIPTION

This script provides comprehensive Node.js dependency management including
outdated package detection, security vulnerability auditing, and SBOM/markdown
report generation. It supports both npm and yarn package managers using a
strategy pattern implementation.

=head1 OPTIONS

=over 4

=item B<--outdated>

Run the outdated dependency check.

=item B<--audit>

Run the security audit check.

=item B<--sbom>

Generate a CycloneDX SBOM based on package.json.

=item B<--bugzilla>

Generate a Bugzilla-ready markdown summary.

=item B<--junit>

Generate JUnit XML test results for CI integration.

=item B<--config-file FILE>

Use an alternate configuration file.

=item B<--json FILE>

Write combined JSON results to FILE.

=item B<--verbose>

Emit debug information.

=item B<--help>

Print this help message.

=back

=head1 OUTPUT

The tool can emit both human-readable and machine-readable artefacts.

=over 4

=item * C<--json FILE> writes a consolidated JSON report (the CI wrapper defaults to C<dependency_check_results.json>).

=item * C<--bugzilla> renders a markdown summary (default C<dependency_bugzilla_report.md>).

=item * C<--sbom> produces a CycloneDX-style XML software bill of materials (default C<node_modules_sbom.xml>).

=item * C<--junit> produces a JUnit XML test report for CI systems (default C<junit_npm_audit.xml>).

=back

=head2 JSON report structure

The JSON document contains the following top-level keys:

=over 4

=item * C<generated_at>, C<tool>, C<metadata> - run metadata including the config file used.

=item * C<direct_dependencies> - direct dependencies from F<package.json> including their type and version spec.

=item * C<resolved_dependencies> - the resolved dependency graph as reported by the package manager.

=item * C<outdated>, C<outdated_summary> - packages with updates available, grouped by update type.

=item * C<vulnerabilities>, C<vulnerability_summary> - security advisories grouped by severity.

=back

Common C<jq> snippets when reviewing C<dependency_check_results.json>:

=over 4

=item * C<jq '.vulnerability_summary' dependency_check_results.json> - quick counts per severity.

=item * C<jq '.vulnerabilities[] | {package, severity, fixed_in}' dependency_check_results.json> - list actionable upgrade targets.

=item * C<jq '.outdated_summary' dependency_check_results.json> - totals per update channel.

=back

=head2 Exit codes

The script returns zero when no configured thresholds are exceeded. Non-zero exit
codes occur when vulnerability or outdated thresholds fail, or when compromise
checks (handled by L<misc/devel/node_audit_compromise.pl>) detect matches.

=head1 FUNCTIONS

=head2 create_package_manager_strategy($tool)

Creates and returns appropriate package manager strategy object.

=over 4

=item * $tool - String indicating package manager ('yarn' or 'npm')

=back

Returns: Strategy object (Node::Package::Manager::Yarn or Node::Package::Manager::Npm)

=head2 Memoization Functions

The following functions implement memoization using Perl's C<state> keyword
to eliminate argument drilling throughout the application:

=head3 get_context()

Returns the memoized context hashref.

=head3 set_context($key, $value)

Sets a value in the memoized context.

=head3 initialize_context($args)

Initializes the memoized context with common parameters.

=over 4

=item * $args - Hashref containing initial context values

=back

=head3 get_verbose()

Returns verbose flag from context.

=head3 get_config()

Returns configuration hash from context.

=head3 get_project_root()

Returns project root path from context.

=head3 get_tool()

Returns package manager name from context.

=head3 get_tool_config()

Returns tool-specific configuration from context.

=head3 get_direct_deps()

Returns direct dependencies hash from context.

=head3 get_resolved_data()

Returns resolved dependency data from context.

=head3 get_package_json()

Returns package.json data from context.

=head2 main()

Main entry point for the script. Handles command line options,
initializes context, and orchestrates dependency checking operations.

=head2 generate_sbom_output($results, $sbom_config)

Generates CycloneDX SBOM XML file from dependency data.

=head2 sbom_component($name, $version, $scope)

Creates SBOM component hash for a package.

=head2 generate_bugzilla_report($results, $bugzilla_config)

Generates Bugzilla-ready markdown report from dependency data.

=head2 generate_junit_output($results, $junit_config)

Generates JUnit XML test report from vulnerability data. Critical and high
severity vulnerabilities are mapped to test failures, moderate severity to
errors, and low severity to passing tests with warnings. When no vulnerabilities
are found, a single passing test is generated.

=head1 INTERNAL ARCHITECTURE

This script uses a memoized context pattern with Perl's C<state> keyword
to avoid argument drilling. Common parameters (verbose, config, etc.) are
stored in a persistent context and accessed through getter functions.

=head1 AUTHOR

Koha Development Team

=head1 COPYRIGHT

Copyright 2025 Koha

=cut
