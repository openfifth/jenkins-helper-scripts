#!/usr/bin/perl

# Jenkins helper script for Node.js/npm-related testing in Koha CI
# Uses KTD Docker containers to have all Perl dependencies available

use strict;
use warnings;
use Cwd                   qw(abs_path getcwd);
use File::Spec::Functions qw(catfile catdir);
use File::Temp            qw(tempdir);
use English               qw(-no_match_vars);

my $TOOLS_REPO     = $ENV{TOOLS_REPO}     || 'https://raw.githubusercontent.com/YOUR_USERNAME/jenkins-helper-scripts/main';
my $TOOLS_DIR      = $ENV{TOOLS_DIR}      || q{};                                                                             # For local testing
my $SYNC_REPO      = $ENV{SYNC_REPO}      || q{.};
my $NPM_TEST_SUITE = $ENV{NPM_TEST_SUITE} || 'audit';
my $KOHA_IMAGE     = $ENV{KOHA_IMAGE}     || 'main';

my $KTD_BRANCH = $ENV{KTD_BRANCH} || 'main';
my $DB_IMAGE   = $ENV{DB_IMAGE}   || q{};
my $DBMS_YML   = $ENV{DBMS_YML}   || q{};

my $NODE_DEP_CHECK_MODES   = $ENV{NODE_DEP_CHECK_MODES}   || 'outdated,audit,bugzilla';
my $NODE_DEP_CHECK_JSON    = $ENV{NODE_DEP_CHECK_JSON}    || q{};
my $NODE_DEP_CHECK_VERBOSE = $ENV{NODE_DEP_CHECK_VERBOSE} || '0';

print "NPM_TEST_SUITE: $NPM_TEST_SUITE\n";
print "SYNC_REPO: $SYNC_REPO\n";
print "KOHA_IMAGE: $KOHA_IMAGE\n";
print "KTD_BRANCH: $KTD_BRANCH\n";

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

my $env_vars = {
    RUN_TESTS_AND_EXIT => 'no',          # We'll run our own scripts
    SYNC_REPO          => q{.},
    LOCAL_USER_ID      => qx{id -u},
    KOHA_IMAGE         => $KOHA_IMAGE,
    KTD_BRANCH         => $KTD_BRANCH,
    DB_IMAGE           => $DB_IMAGE,
    DBMS_YML           => $DBMS_YML,
};
while ( my ( $var, $value ) = each %{$env_vars} ) {
    $ENV{$var} = $value;
}

my @docker_compose_yml;
my $GITLAB_RAW_URL = join q{}, 'https://gitlab.com/koha-community/koha-testing-docker/raw/', $ENV{KTD_BRANCH};

push @docker_compose_yml, 'docker-compose-light.yml';

unless ( $ENV{DB_IMAGE} ) {
    if ( $ENV{DBMS_YML} ) {
        push @docker_compose_yml, $ENV{DBMS_YML};
    }
    else {
        if ( $ENV{KOHA_IMAGE} =~ m{stretch} ) {
            push @docker_compose_yml, 'docker-compose.mariadb_d9.yml';
        }
        elsif ( $ENV{KOHA_IMAGE} =~ m{buster} ) {
            push @docker_compose_yml, 'docker-compose.mariadb_d10.yml';
        }
        elsif ( $ENV{KOHA_IMAGE} =~ m{bullseye} || $ENV{KOHA_IMAGE} eq 'main' ) {
            push @docker_compose_yml, 'docker-compose.mariadb_d11.yml';
        }
        elsif ( $ENV{KOHA_IMAGE} =~ m{bookworm} ) {
            push @docker_compose_yml, 'docker-compose.mariadb_d12.yml';
        }
        elsif ( $ENV{KOHA_IMAGE} =~ m{bionic} ) {
            push @docker_compose_yml, 'docker-compose.mariadb_u18.yml';
        }
        elsif ( $ENV{KOHA_IMAGE} =~ m{focal} ) {
            push @docker_compose_yml, 'docker-compose.mariadb_u20.yml';
        }
        elsif ( $ENV{KOHA_IMAGE} =~ m{jammy} ) {
            push @docker_compose_yml, 'docker-compose.mariadb_u22.yml';
        }
        elsif ( $ENV{KOHA_IMAGE} =~ m{sid} ) {
            push @docker_compose_yml, 'docker-compose.mariadb_latest.yml';
        }
    }
}

print "\nDownloading docker-compose files\n";
for my $yml (@docker_compose_yml) {
    run( qq{wget -O $yml $GITLAB_RAW_URL/$yml}, { exit_on_error => 1 } );
}

my $env_file           = '.env';
my $docker_compose_env = "$GITLAB_RAW_URL/env/defaults.env";
run( qq{wget -O $env_file $docker_compose_env}, { exit_on_error => 1 } );

{
    open my $in_fh, '<', $env_file or die "Cannot open $env_file for reading: $OS_ERROR";
    my @lines = <$in_fh>;
    close $in_fh;

    open my $out_fh, '>', $env_file or die "Cannot open $env_file for writing: $OS_ERROR";
    for my $line (@lines) {
        if ( $line =~ /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/ ) {
            my ( $key, $val ) = ( $1, $2 );
            if ( exists $ENV{$key} ) {
                $line = "$key=$ENV{$key}\n";
            }
        }
        print $out_fh $line;
    }
    close $out_fh;
}

docker_cleanup();

print "\nPulling Docker images\n";
my $cmd = join q{ }, 'docker compose', join( q{ }, map {"-f $_"} @docker_compose_yml ), 'pull --quiet';
run( $cmd, { exit_on_error => 1 } );

print "\nStarting Docker containers\n";
$cmd = join q{ }, 'docker compose', join( q{ }, map {"-f $_"} @docker_compose_yml ), '-p koha up -d';
run( $cmd, { exit_on_error => 1 } );

print "Waiting for containers to be ready...\n";
sleep 5;

print "\nCopying node-audit-tools into container\n";
my $tools_path = catdir( $tools_source_dir, 'node-audit-tools' );
run( "docker compose -p koha cp $tools_path koha:/kohadevbox/", { exit_on_error => 1 } );

print "\nRunning $NPM_TEST_SUITE test suite\n\n";

my $exit_code = 0;

if ( $NPM_TEST_SUITE eq 'audit' || $NPM_TEST_SUITE eq 'full' ) {
    $exit_code = run_audit_in_container();
}

if ( $NPM_TEST_SUITE eq 'build' || $NPM_TEST_SUITE eq 'full' ) {
    $exit_code = run_build_in_container() if $exit_code == 0;
}

print "\nCleaning up\n";
docker_cleanup();
run(qq{rm $_}) for @docker_compose_yml;
run(q{rm -rf .env});

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
    push @args, '--verbose'  if $NODE_DEP_CHECK_VERBOSE;
    push @args, '--json',         $NODE_DEP_CHECK_JSON if $NODE_DEP_CHECK_JSON;
    push @args, '--config-file',  '/kohadevbox/node-audit-tools/node_audit_config.yml';
    push @args, '--template-dir', '/kohadevbox/node-audit-tools/templates';

    my $args_str = join( q{ }, map {"'$_'"} @args );

    my $install_cmd = 'docker compose -p koha exec -T koha bash -c "cd /kohadevbox/koha && yarn install --frozen-lockfile"';
    print "Installing dependencies...\n";
    my $result = run( $install_cmd, { exit_on_error => 0 } );
    return $result if $result != 0;

    my $audit_cmd =
        "docker compose -p koha exec -T koha bash -c 'cd /kohadevbox/koha && PERL5LIB=/kohadevbox/node-audit-tools/lib:\$PERL5LIB /usr/bin/perl /kohadevbox/node-audit-tools/node_audit_dependencies.pl $args_str'";
    print "Running dependency audit...\n";
    return run( $audit_cmd, { exit_on_error => 0, use_pipe => 1 } );
}

sub run_build_in_container {
    print "Running build check in container...\n\n";

    my $build_cmd = 'docker compose -p koha exec -T koha bash -c "cd /kohadevbox/koha && yarn build"';
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

sub docker_cleanup {
    run( join q{ }, q{docker compose}, join( q{ }, map {"-f $_"} @docker_compose_yml ), q{-p koha down} );

    my $containers = qx{docker ps -a -f "name=koha_" -q};
    chomp $containers;
    if ($containers) {
        run(qq{docker stop \$(docker ps -a -f "name=koha_" -q)});
        run(qq{docker rm \$(docker ps -a -f "name=koha_" -q)});
    }

    run(q{docker container prune -f});
    run(q{docker volume prune    -f});
    run(q{docker network prune   -f});

    my $nb_days = $ENV{JENKINS_NODE_KEEP_DOCKER_NB_DAYS};
    run( q{docker image prune -a -f} . ( $nb_days ? sprintf q{ --filter until=%sd}, $nb_days : q{} ) );
}
