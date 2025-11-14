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

# Test 2-14: Normal outdated output parsing
{
    my $fixture = read_fixture('yarn-outdated-normal.jsonl');

    my $mock = Test::MockModule->new('Node::Package::Manager::Yarn');
    $mock->mock('run_command', sub { return ($fixture, 0); });

    my $yarn = Node::Package::Manager::Yarn->new();
    my $tool_config = { commands => { outdated => 'yarn outdated --json' } };
    my $direct_deps = {};

    my ($packages, $summary) = $yarn->run_outdated_check($tool_config, $direct_deps, 0);

    # Basic structure tests
    ok(defined $packages, 'Packages returned');
    is(ref $packages, 'HASH', 'Packages is a hash');
    ok(defined $summary, 'Summary returned');
    is(ref $summary, 'HASH', 'Summary is a hash');

    # Count tests
    is(scalar keys %$packages, 3, 'Found 3 outdated packages');
    is($summary->{total}, 3, 'Summary total is 3');

    # Verify we got expected packages
    ok(exists $packages->{'lodash'}, 'Found lodash');
    ok(exists $packages->{'webpack'}, 'Found webpack');
    ok(exists $packages->{'typescript'}, 'Found typescript');

    # Test package structure
    my $lodash = $packages->{'lodash'};
    is($lodash->{current}, '4.17.19', 'Lodash current version');
    is($lodash->{wanted}, '4.17.21', 'Lodash wanted version');
    is($lodash->{latest}, '4.17.21', 'Lodash latest version');
    ok(defined $lodash->{update}, 'Lodash has update type');
}

# Test 15-18: Empty output (all up-to-date)
{
    my $fixture = read_fixture('yarn-outdated-empty.jsonl');

    my $mock = Test::MockModule->new('Node::Package::Manager::Yarn');
    $mock->mock('run_command', sub { return ($fixture, 0); });

    my $yarn = Node::Package::Manager::Yarn->new();
    my $tool_config = { commands => { outdated => 'yarn outdated --json' } };
    my ($packages, $summary) = $yarn->run_outdated_check($tool_config, {}, 0);

    ok(defined $packages, 'Empty outdated returns packages hash');
    is(ref $packages, 'HASH', 'Empty outdated returns hash');
    is(scalar keys %$packages, 0, 'No outdated packages found');
    is($summary->{total}, 0, 'Summary total is 0');
}

# Test 19-23: Malformed JSON handling
{
    my $fixture = read_fixture('yarn-outdated-malformed.jsonl');

    my $mock = Test::MockModule->new('Node::Package::Manager::Yarn');
    $mock->mock('run_command', sub { return ($fixture, 0); });

    my $yarn = Node::Package::Manager::Yarn->new();
    my $tool_config = { commands => { outdated => 'yarn outdated --json' } };
    my ($packages, $summary) = $yarn->run_outdated_check($tool_config, {}, 0);

    ok(defined $packages, 'Malformed input returns hash');
    is(ref $packages, 'HASH', 'Returns hash despite malformed lines');
    # Should parse valid-package and another-package, skip malformed and incomplete
    is(scalar keys %$packages, 2, 'Parsed valid entries, skipped malformed');
    ok(exists $summary->{total}, 'Summary still generated');
    is($summary->{total}, 2, 'Summary reflects valid entries only');
}

# Test 24-27: Missing fields handling
{
    my $fixture = read_fixture('yarn-outdated-missing-fields.jsonl');

    my $mock = Test::MockModule->new('Node::Package::Manager::Yarn');
    $mock->mock('run_command', sub { return ($fixture, 0); });

    my $yarn = Node::Package::Manager::Yarn->new();
    my $tool_config = { commands => { outdated => 'yarn outdated --json' } };
    my ($packages, $summary) = $yarn->run_outdated_check($tool_config, {}, 0);

    ok(defined $packages, 'Missing fields returns hash');
    is(scalar keys %$packages, 2, 'Parsed entries with missing head');

    # Both should parse since we only check for >= 4 columns in body
    ok(exists $packages->{'pkg-no-head'}, 'Found pkg-no-head');
    ok(exists $packages->{'another-pkg'}, 'Found another-pkg');
}

# Test 28-32: Update type classification
{
    my $fixture = read_fixture('yarn-outdated-normal.jsonl');

    my $mock = Test::MockModule->new('Node::Package::Manager::Yarn');
    $mock->mock('run_command', sub { return ($fixture, 0); });

    my $yarn = Node::Package::Manager::Yarn->new();
    my $tool_config = { commands => { outdated => 'yarn outdated --json' } };
    my ($packages, $summary) = $yarn->run_outdated_check($tool_config, {}, 0);

    # lodash: 4.17.19 -> 4.17.21 (patch)
    is($packages->{'lodash'}{update}, 'patch', 'Lodash is patch update');

    # webpack: 4.46.0 -> 5.88.2 (major)
    is($packages->{'webpack'}{update}, 'major', 'Webpack is major update');

    # typescript: 3.9.7 -> 5.2.2 (major)
    is($packages->{'typescript'}{update}, 'major', 'Typescript is major update');

    # Check counts
    ok(exists $summary->{counts}, 'Summary has counts');
    is($summary->{counts}{major}, 2, 'Two major updates');
}

done_testing();
