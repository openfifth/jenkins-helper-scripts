#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::MockModule;
use FindBin qw($Bin);
use File::Spec::Functions qw(catfile);
use lib catfile($Bin, '..', 'lib');

# Load modules
use_ok('Node::Package::Manager::Npm');

# Helper to read fixture
sub read_fixture {
    my ($filename) = @_;
    my $path = catfile($Bin, 'fixtures', $filename);
    open my $fh, '<', $path or die "Cannot open fixture $path: $!";
    local $/ = undef;
    my $content = <$fh>;
    close $fh;
    return $content;
}

# Test 1: Module loads
ok(1, 'Module loaded successfully');

# Test 2-18: Normal audit output parsing
{
    my $fixture = read_fixture('npm-audit-normal.json');

    # Mock run_command in the Npm namespace (where it's imported to)
    my $mock = Test::MockModule->new('Node::Package::Manager::Npm');
    $mock->mock('run_command', sub { return ($fixture, 1); });  # exit code 1 = vulnerabilities found

    my $npm = Node::Package::Manager::Npm->new();
    my $tool_config = { commands => { audit => 'npm audit --json' } };
    my $direct_deps = {};

    my ($vulns, $summary) = $npm->run_audit_check($tool_config, $direct_deps, 0);

    # Basic structure tests
    ok(defined $vulns, 'Vulnerabilities returned');
    is(ref $vulns, 'ARRAY', 'Vulnerabilities is an array');
    ok(defined $summary, 'Summary returned');
    is(ref $summary, 'HASH', 'Summary is a hash');

    # Count tests
    is(scalar @$vulns, 3, 'Found 3 vulnerabilities');
    is($summary->{total}, 3, 'Summary total is 3');

    # Verify we got expected packages
    my %packages = map { $_->{package} => 1 } @$vulns;
    ok(exists $packages{'postcss'}, 'Found postcss vulnerability');
    ok(exists $packages{'decode-uri-component'}, 'Found decode-uri-component vulnerability');
    ok(exists $packages{'braces'}, 'Found braces vulnerability');

    # Test first vulnerability structure
    my $first_vuln = $vulns->[0];
    ok(defined $first_vuln->{package}, 'First vuln has package field');
    ok(defined $first_vuln->{severity}, 'First vuln has severity field');
    ok(defined $first_vuln->{current_version}, 'First vuln has current_version field');
    ok(defined $first_vuln->{dependency_paths}, 'First vuln has dependency_paths');
    is(ref $first_vuln->{dependency_paths}, 'ARRAY', 'Dependency paths is an array');

    # Test JUnit-required fields (title, cves, vulnerable_versions, patched_versions)
    my %vuln_by_name = map { $_->{package} => $_ } @$vulns;
    my $postcss = $vuln_by_name{'postcss'};
    ok(defined $postcss->{title}, 'Postcss has title field');
    like($postcss->{title}, qr/Regular Expression/i, 'Postcss title extracted correctly');
    ok(defined $postcss->{vulnerable_versions}, 'Postcss has vulnerable_versions field');
    is($postcss->{vulnerable_versions}, '<7.0.36', 'Postcss vulnerable_versions extracted');
    ok(defined $postcss->{cves}, 'Postcss has cves field');
    is(ref $postcss->{cves}, 'ARRAY', 'CVEs is an array');

    # Test severity classification
    ok(exists $summary->{severity_counts}, 'Summary has severity counts');
    is(ref $summary->{severity_counts}, 'HASH', 'Severity counts is a hash');
}

# Test 19-23: Empty output (no vulnerabilities)
{
    my $fixture = read_fixture('npm-audit-empty.json');

    my $mock = Test::MockModule->new('Node::Package::Manager::Npm');
    $mock->mock('run_command', sub { return ($fixture, 0); });  # exit code 0 = no vulnerabilities

    my $npm = Node::Package::Manager::Npm->new();
    my $tool_config = { commands => { audit => 'npm audit --json' } };
    my ($vulns, $summary) = $npm->run_audit_check($tool_config, {}, 0);

    ok(defined $vulns, 'Empty audit returns vulnerabilities array');
    is(ref $vulns, 'ARRAY', 'Empty audit returns array');
    is(scalar @$vulns, 0, 'No vulnerabilities found');
    is($summary->{total}, 0, 'Summary total is 0');
    ok(!keys %{$summary->{severity_counts} || {}}, 'No severity counts');
}

# Test 24-28: Malformed JSON handling
{
    my $fixture = read_fixture('npm-audit-malformed.json');

    my $mock = Test::MockModule->new('Node::Package::Manager::Npm');
    $mock->mock('run_command', sub { return ($fixture, 1); });

    my $npm = Node::Package::Manager::Npm->new();
    my $tool_config = { commands => { audit => 'npm audit --json' } };
    my ($vulns, $summary) = $npm->run_audit_check($tool_config, {}, 0);

    ok(defined $vulns, 'Malformed input returns array');
    is(ref $vulns, 'ARRAY', 'Returns array despite malformed entries');
    # Has 3 entries, but 1 is malformed (string instead of hash), should parse 2 valid ones
    is(scalar @$vulns, 2, 'Parsed valid entries, skipped malformed one');
    ok(exists $summary->{total}, 'Summary still generated');
    is($summary->{total}, 2, 'Summary reflects valid entries only');
}

# Test 29-35: Missing fields handling
{
    my $fixture = read_fixture('npm-audit-missing-fields.json');

    my $mock = Test::MockModule->new('Node::Package::Manager::Npm');
    $mock->mock('run_command', sub { return ($fixture, 1); });

    my $npm = Node::Package::Manager::Npm->new();
    my $tool_config = { commands => { audit => 'npm audit --json' } };
    my ($vulns, $summary) = $npm->run_audit_check($tool_config, {}, 0);

    ok(defined $vulns, 'Missing fields returns array');
    is(scalar @$vulns, 2, 'Parsed entries with missing fields');

    # Find specific packages by name (hash order not guaranteed)
    my %vuln_by_name = map { $_->{package} => $_ } @$vulns;

    # Check package with missing severity
    my $no_severity = $vuln_by_name{'pkg-no-severity'};
    ok(defined $no_severity, 'Found pkg-no-severity');
    ok(defined $no_severity->{severity}, 'Severity has value');
    is($no_severity->{severity}, 'unknown', 'Missing severity defaults to unknown');

    # Check package with missing via
    my $no_via = $vuln_by_name{'pkg-no-via'};
    ok(defined $no_via, 'Found pkg-no-via');
    ok(defined $no_via->{url}, 'URL field exists');
    ok(defined $no_via->{recommendation}, 'Recommendation field exists');
}

done_testing();
