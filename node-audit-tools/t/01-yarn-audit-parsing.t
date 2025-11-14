#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Test::MockModule;
use FindBin qw($Bin);
use File::Spec::Functions qw(catfile);
use lib catfile($Bin, '..', 'lib');

# Load modules
use_ok('Node::Package::Manager::Yarn');

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

# Test 2-16: Normal audit output parsing
{
    my $fixture = read_fixture('yarn-audit-normal.jsonl');

    # Mock run_command in the Yarn namespace (where it's imported to)
    my $mock = Test::MockModule->new('Node::Package::Manager::Yarn');
    $mock->mock('run_command', sub { return ($fixture, 1); });  # exit code 1 = vulnerabilities found

    my $yarn = Node::Package::Manager::Yarn->new();
    my $tool_config = { commands => { audit => 'yarn audit --json' } };
    my $direct_deps = {};

    my ($vulns, $summary) = $yarn->run_audit_check($tool_config, $direct_deps, 0);

    # Basic structure tests
    ok(defined $vulns, 'Vulnerabilities returned');
    is(ref $vulns, 'ARRAY', 'Vulnerabilities is an array');
    ok(defined $summary, 'Summary returned');
    is(ref $summary, 'HASH', 'Summary is a hash');

    # Count tests
    cmp_ok(scalar @$vulns, '>', 0, 'Found vulnerabilities');
    is($summary->{total}, scalar @$vulns, 'Summary total matches array size');

    # Verify we got expected packages
    my %packages = map { $_->{package} => 1 } @$vulns;
    ok(exists $packages{'postcss'}, 'Found postcss vulnerability');
    ok(exists $packages{'decode-uri-component'}, 'Found decode-uri-component vulnerability');
    ok(exists $packages{'braces'}, 'Found braces vulnerability');

    # Test first vulnerability structure
    my $first_vuln = $vulns->[0];
    ok(defined $first_vuln->{package}, 'First vuln has package field');
    ok(defined $first_vuln->{severity}, 'First vuln has severity field');
    ok(defined $first_vuln->{cves}, 'First vuln has cves field');
    is(ref $first_vuln->{cves}, 'ARRAY', 'CVEs is an array');
    ok(defined $first_vuln->{dependency_paths}, 'First vuln has dependency_paths');
    is(ref $first_vuln->{dependency_paths}, 'ARRAY', 'Dependency paths is an array');

    # Test severity classification
    ok(exists $summary->{severity_counts}, 'Summary has severity counts');
    is(ref $summary->{severity_counts}, 'HASH', 'Severity counts is a hash');
}

# Test 17-21: Empty output (no vulnerabilities)
{
    my $fixture = read_fixture('yarn-audit-empty.jsonl');

    my $mock = Test::MockModule->new('Node::Package::Manager::Yarn');
    $mock->mock('run_command', sub { return ($fixture, 0); });  # exit code 0 = no vulnerabilities

    my $yarn = Node::Package::Manager::Yarn->new();
    my $tool_config = { commands => { audit => 'yarn audit --json' } };
    my ($vulns, $summary) = $yarn->run_audit_check($tool_config, {}, 0);

    ok(defined $vulns, 'Empty audit returns vulnerabilities array');
    is(ref $vulns, 'ARRAY', 'Empty audit returns array');
    is(scalar @$vulns, 0, 'No vulnerabilities found');
    is($summary->{total}, 0, 'Summary total is 0');
    ok(!keys %{$summary->{severity_counts} || {}}, 'No severity counts');
}

# Test 22-26: Malformed JSON handling
{
    my $fixture = read_fixture('yarn-audit-malformed.jsonl');

    my $mock = Test::MockModule->new('Node::Package::Manager::Yarn');
    $mock->mock('run_command', sub { return ($fixture, 1); });

    my $yarn = Node::Package::Manager::Yarn->new();
    my $tool_config = { commands => { audit => 'yarn audit --json' } };
    my ($vulns, $summary) = $yarn->run_audit_check($tool_config, {}, 0);

    ok(defined $vulns, 'Malformed input returns array');
    is(ref $vulns, 'ARRAY', 'Returns array despite malformed lines');
    # Should parse the 2 valid advisories, skip the 2 malformed lines
    is(scalar @$vulns, 2, 'Parsed valid lines, skipped malformed');
    ok(exists $summary->{total}, 'Summary still generated');
    is($summary->{total}, 2, 'Summary reflects valid entries only');
}

# Test 27-33: Missing fields handling
{
    my $fixture = read_fixture('yarn-audit-missing-fields.jsonl');

    my $mock = Test::MockModule->new('Node::Package::Manager::Yarn');
    $mock->mock('run_command', sub { return ($fixture, 1); });

    my $yarn = Node::Package::Manager::Yarn->new();
    my $tool_config = { commands => { audit => 'yarn audit --json' } };
    my ($vulns, $summary) = $yarn->run_audit_check($tool_config, {}, 0);

    ok(defined $vulns, 'Missing fields returns array');
    is(scalar @$vulns, 2, 'Parsed entries with missing fields');

    # Check default values are used
    my $first_vuln = $vulns->[0];
    ok(defined $first_vuln->{package}, 'Package has default value');
    ok(defined $first_vuln->{severity}, 'Severity present');

    # Check CVEs handling
    my $second_vuln = $vulns->[1];
    is($second_vuln->{package}, 'pkg-with-no-cves', 'Package name extracted');
    ok(defined $second_vuln->{cves}, 'CVEs field exists');
    is(ref $second_vuln->{cves}, 'ARRAY', 'CVEs is array even if empty');
    is(scalar @{$second_vuln->{cves}}, 0, 'Empty CVEs array for missing CVEs');
}

done_testing();
