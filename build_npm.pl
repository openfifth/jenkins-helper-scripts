#!/usr/bin/perl

# Jenkins helper script for Node.js/npm-related testing in Koha CI
# Uses KTD Docker containers to have all Perl dependencies available

use strict;
use warnings;
use Cwd                   qw(abs_path getcwd);
use File::Spec::Functions qw(catfile catdir);
use File::Temp            qw(tempdir);
use English               qw(-no_match_vars);

my $TOOLS_REPO     = $ENV{TOOLS_REPO}     || 'https://gitlab.com/koha-community/jenkins-helper-scripts/-/raw/main';
my $TOOLS_DIR      = $ENV{TOOLS_DIR}      || q{};                                                                             # For local testing
my $SYNC_REPO      = $ENV{SYNC_REPO}      || q{.};
my $NPM_TEST_SUITE = $ENV{NPM_TEST_SUITE} || 'audit';
my $KOHA_IMAGE     = $ENV{KOHA_IMAGE}     || 'main';

my $NODE_DEP_CHECK_MODES   = $ENV{NODE_DEP_CHECK_MODES}   || 'outdated,audit,sbom,bugzilla,junit';
my $NODE_DEP_CHECK_JSON    = $ENV{NODE_DEP_CHECK_JSON}    || q{};
my $NODE_DEP_CHECK_VERBOSE = $ENV{NODE_DEP_CHECK_VERBOSE} || '0';

print "NPM_TEST_SUITE: $NPM_TEST_SUITE\n";
print "SYNC_REPO: $SYNC_REPO\n";
print "KOHA_IMAGE: $KOHA_IMAGE\n";

chdir $SYNC_REPO or die "Cannot change to $SYNC_REPO: $OS_ERROR";
print join q{}, 'Working directory: ', getcwd(), "\n\n";

my $temp_dir;
my $tools_source_dir;

if ( $TOOLS_DIR && -d catdir( $TOOLS_DIR, 'node-audit-tools' ) ) {
    print "Using local node-audit-tools from $TOOLS_DIR\n";
    $tools_source_dir = $TOOLS_DIR;
}
else {
    $temp_dir = tempdir( CLEANUP => 1 );
    print "Created temp directory: $temp_dir\n";
    print "\nDownloading node-audit-tools\n";

    my @files_to_download = (
        'node-audit-tools/node_ci_audit.pl',                 'node-audit-tools/node_audit_dependencies.pl',
        'node-audit-tools/node_audit_compromise.pl',         'node-audit-tools/node_audit_config.yml',
        'node-audit-tools/lib/Node/Utils.pm',                'node-audit-tools/lib/Node/Package/Manager/Base.pm',
        'node-audit-tools/lib/Node/Package/Manager/Npm.pm',  'node-audit-tools/lib/Node/Package/Manager/Yarn.pm',
        'node-audit-tools/templates/dependency_sbom.xml.tt', 'node-audit-tools/templates/dependency_bugzilla_report.md.tt',
    );

    for my $file (@files_to_download) {
        my $url      = "$TOOLS_REPO/$file";
        my $dest     = catfile( $temp_dir, $file );
        my $dest_dir = $dest;
        $dest_dir =~ s{/[^/]+$}{};
        run("mkdir -p $dest_dir");
        print "Downloading $file...\n";
        run( "wget -q -O $dest $url", { exit_on_error => 1 } );
    }

    run( join q{ }, 'chmod +x', catfile( $temp_dir, 'node-audit-tools', '*.pl' ) );
    $tools_source_dir = $temp_dir;
}

my $koha_image = "koha/koha-testing:$KOHA_IMAGE";

print "\nPulling Docker image: $koha_image\n";
run( "docker pull $koha_image", { exit_on_error => 1 } );

print "\nRunning $NPM_TEST_SUITE test suite\n\n";

my $exit_code = 0;

if ( $NPM_TEST_SUITE eq 'audit' || $NPM_TEST_SUITE eq 'full' ) {
    $exit_code = run_audit_in_container();
}

if ( $NPM_TEST_SUITE eq 'build' || $NPM_TEST_SUITE eq 'full' ) {
    $exit_code = run_build_in_container() if $exit_code == 0;
}

if ( $exit_code == 0 ) {
    print "\nTest suite completed successfully\n";
}
else {
    print "\nTest suite failed with exit code $exit_code\n";
}

exit $exit_code;

sub run_audit_in_container {
    print "Running dependency audit check in container...\n\n";

    my @modes      = split /,/, $NODE_DEP_CHECK_MODES;
    my %mode_flags = map { $_ => 1 } @modes;

    my @args;
    push @args, '--outdated' if $mode_flags{outdated};
    push @args, '--audit'    if $mode_flags{audit};
    push @args, '--sbom'     if $mode_flags{sbom};
    push @args, '--bugzilla' if $mode_flags{bugzilla};
    push @args, '--junit'    if $mode_flags{junit};
    push @args, '--verbose'  if $NODE_DEP_CHECK_VERBOSE;
    push @args, '--json',         $NODE_DEP_CHECK_JSON if $NODE_DEP_CHECK_JSON;
    push @args, '--config-file',  '/kohadevbox/node-audit-tools/node_audit_config.yml';
    push @args, '--template-dir', '/kohadevbox/node-audit-tools/templates';

    my $args_str = join( q{ }, map {"'$_'"} @args );

    my $workspace   = getcwd();
    my $tools_path  = catdir( $tools_source_dir, 'node-audit-tools' );
    my $koha_image  = "koha/koha-testing:$KOHA_IMAGE";

    # Build docker run command with volume mounts
    my $docker_base = qq{docker run --rm -t};
    $docker_base .= qq{ -v "$workspace:/kohadevbox/koha"};
    $docker_base .= qq{ -v "$tools_path:/kohadevbox/node-audit-tools"};
    $docker_base .= qq{ -w /kohadevbox/koha};
    $docker_base .= qq{ $koha_image};

    my $install_cmd = qq{$docker_base bash -c "yarn install --frozen-lockfile"};
    print "Installing dependencies...\n";
    my $result = run( $install_cmd, { exit_on_error => 0, use_pipe => 1 } );
    return $result if $result != 0;

    my $audit_cmd = qq{$docker_base bash -c "PERL5LIB=/kohadevbox/node-audit-tools/lib:\\\$PERL5LIB /usr/bin/perl /kohadevbox/node-audit-tools/node_audit_dependencies.pl $args_str"};
    print "Running dependency audit...\n";
    return run( $audit_cmd, { exit_on_error => 0, use_pipe => 1 } );
}

sub run_build_in_container {
    print "Running build check in container...\n\n";

    my $workspace  = getcwd();
    my $koha_image = "koha/koha-testing:$KOHA_IMAGE";

    my $build_cmd = qq{docker run --rm -t -v "$workspace:/kohadevbox/koha" -w /kohadevbox/koha $koha_image bash -c "yarn build"};
    return run( $build_cmd, { exit_on_error => 0, use_pipe => 1 } );
}

sub run {
    my ( $cmd, $params ) = @_;
    my $exit_on_error = $params->{exit_on_error};
    my $use_pipe      = $params->{use_pipe};

    if ($use_pipe) {
        $cmd .= ' 2>&1';
        my $fh;
        if ($exit_on_error) {
            open( $fh, q{-|}, $cmd ) or die "Failed to execute: $cmd ($OS_ERROR)";
        }
        else {
            if ( !open( $fh, q{-|}, $cmd ) ) {
                warn "Failed to execute: $cmd ($OS_ERROR)";
                return 1;
            }
        }
        while ( my $line = <$fh> ) { print $line }
        close $fh;
        return $CHILD_ERROR >> 8;
    }
    else {
        my $output    = qx{$cmd 2>&1};
        my $exit_code = $CHILD_ERROR >> 8;
        print $output if $output;

        if ( $exit_on_error && $exit_code != 0 ) {
            die "Command failed with exit code $exit_code: $cmd\n";
        }

        return $exit_code;
    }
}
