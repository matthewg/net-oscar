#!/usr/bin/perl

use Test::More;
use File::Basename;
use strict;
use lib "./blib/lib";
no warnings;

my %do_tests = map {$_ => 1} @ARGV;

my @tests = grep {%do_tests ? exists($do_tests{$_->{template}}) : 1} (
	{
		binary => pack("C", 42),
		data => {x => 42},
		template => "just_byte",
	},{
		binary => pack("n", 1984),
		data => {x => 1984},
		template => "just_word"
	},{
		binary => pack("N", 0xDEADBEEF),
		data => {x => 0xDEADBEEF},
		template => "just_dword"
	},{
		binary => "UML model of a modern major general",
		data => {x => "UML model of a modern major general"},
		template => "just_data"
	},{
		binary => pack("n", 0),
		data => {x => 0},
		template => "just_word",
		name => "zero word"
	},{
		binary => pack("n", 123),
		data => {},
		template => "fixed_value"
	},{
		binary => "foo",
		data => {},
		template => "fixed_value_data"
	},{
		binary => pack("na*", length("Cthulhu"), "Cthulhu"),
		data => {x => "Cthulhu"},
		template => "length_prefix"
	},{
		binary => pack("va*", length("Kessel run"), "Kessel run"),
		data => {x => "Kessel run"},
		template => "vax_prefix"
	},{
		binary => pack("n*", 1, 1, 2, 3, 5, 8, 13),
		data => {x => [1, 1, 2, 3, 5, 8, 13]},
		template => "repeated_data"
	},{
		binary => "1234567890XXX",
		data => {x => "1234567890", y => "XXX"},
		template => "fixed_width_data"
	},{
		binary => "abc",
		data => {foo => [qw(a b c)]},
		template => "count_len"
	},{
		binary => pack("nnn nnn", 1, 2, 3, 2, 2, 20),
		data => {x => 3, y => 20},
		template => "basic_tlv"
	},{
		binary => pack("nnn nnn", 1, 2, 0, 2, 2, 0),
		data => {x => 0, y => 0},
		template => "basic_tlv",
		name => "zero TLV"
	},{
		binary => pack("nna* nna*", 1, length("Baby"), "Baby", 2, length("Surge"), "Surge"),
		data => {foo => {x => "Baby"}, bar => {y => "Surge"}},
		template => "named_tlv"
	},{
		binary => pack("nna*nNC", 1, 10, "foo", 3142, 1793, 27),
		data => {foo => "foo", bar => 3142, baz => 27},
		template => "complex_data_tlv"
	},{
		binary => pack("nCCn nCCn", 1, 1, 2, 3, 1, 2, 2, 20),
		data => {foo => {x => 3}, bar => {y => 20}},
		template => "subtyped_tlv"
	},{
		binary => pack("nCCn nCCn", 1, 1, 2, 0, 1, 2, 2, 0),
		data => {foo => {x => 0}, bar => {y => 0}},
		template => "subtyped_tlv",
		name => "zero subtyped TLV"
	},{
		binary => pack("n nna*", 1, 1, length("foo"), "foo"),
		data => {x => "foo"},
		template => "count_prefix_tlv"
	},{
		binary => pack("nn", 3, 20),
		data => {foo => 3, bar => 20},
		template => "ref"
	}
);


plan(tests => 3+2*@tests);

require_ok("Net::OSCAR");
require_ok("Net::OSCAR::XML");
Net::OSCAR::XML->import('protoparse');

my $oscar = Net::OSCAR->new();
is(Net::OSCAR::XML::load_xml(dirname($0)."/test.xml"), 1, "loading XML test file");

$oscar->loglevel(99) if %do_tests;
foreach (@tests) {
	is(
		protoparse($oscar, $_->{template})->pack(%{$_->{data}}),
		$_->{binary},
		"Encode: " . (exists($_->{name}) ? $_->{name} : $_->{template})
	);

	is_deeply(
		{protoparse($oscar, $_->{template})->unpack($_->{binary})},
		$_->{data},
		"Decode: " . (exists($_->{name}) ? $_->{name} : $_->{template})
	);
}

