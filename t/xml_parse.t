#!/usr/bin/perl

use Test::More tests => 16;
use File::Basename;
use strict;
no warnings;

require_ok("Net::OSCAR");
require_ok("Net::OSCAR::XML");
Net::OSCAR::XML->import('protoparse');

my $oscar = Net::OSCAR->new();
is(Net::OSCAR::XML::load_xml(dirname($0)."/test.xml"), 1, "loading XML test file");

is_deeply([sort keys(%Net::OSCAR::XML::xmlmap)], [sort qw(
		just_byte
		just_word
		just_dword
		just_data
		named_element
		fixed_value
		length_prefix
		count_prefix
		vax_prefix
		repeated_data
		fixed_width_data
		basic_tlv
		named_tlv
		complex_data_tlv
		subtyped_tlv
		count_prefic_tlv
		ref_foo
		ref_bar
		ref
		snac
		empty_def
	)], "forward name mapping");

is_deeply({%Net::OSCAR::XML::xml_revmap}, {1 => { 2 => "snac" }}, "reverse name mapping");

$Net::OSCAR::XML::PROTOPARSE_DEBUG = 1;

is_deeply(
	[sort (protoparse($oscar, "just_byte"))],
	[sort ({len => 1, type => 'num', packlet => 'C'})],
	"byte"
);
is_deeply(
	[sort (protoparse($oscar, "just_word"))],
	[sort ({len => 2, type => 'num', packlet => 'n'})],
	"word"
);
is_deeply(
	[sort (protoparse($oscar, "just_dword"))],
	[sort ({len => 4, type => 'num', packlet => 'N'})],
	"dword"
);
is_deeply(
	[sort (protoparse($oscar, "just_data"))],
	[sort ({type => 'data'})],
	"data"
);

is_deeply(
	[sort (protoparse($oscar, "named_element"))],
	[sort ({type => 'data', name => 'foo'})],
	"named data"
);

is_deeply(
	[sort (protoparse($oscar, "fixed_value"))],
	[sort ({len => 2, type => 'num', packlet => 'n', value => 123})],
	"fixed-value data"
);

is_deeply(
	[sort (protoparse($oscar, "length_prefix"))],
	[sort ({len => 2, type => 'data', packlet => 'n', prefix => 'length'})],
	"length prefix"
);
is_deeply(
	[sort (protoparse($oscar, "vax_prefix"))],
	[sort ({len => 2, type => 'data', packlet => 'v', prefix => 'length'})],
	"vax-order length prefix"
);
is_deeply(
	[sort (protoparse($oscar, "count_prefix"))],
	[sort ({len => 2, type => 'data', packlet => 'n', prefix => 'count'})],
	"fixed-value data"
);
is_deeply(
	[sort (protoparse($oscar, "repeated_data"))],
	[sort ({type => 'data', count => -1})],
	"repeated data"
);
is_deeply(
	[sort (protoparse($oscar, "fixed_width_data"))],
	[sort ({type => 'data', length => 10})],
	"fixed-width data"
);

__END__
	<!-- TLVs -->
	<define name="basic_tlv">
		<tlvchain>
			<tlv type="1"><data /></tlv>
			<tlv type="2"><data /></tlv>
		</tlvchain>
	</define>
	<define name="named_tlv">
		<tlvchain>
			<tlv type="1" name="foo"><data /></tlv>
			<tlv type="2" name="bar"><data /></tlv>
		</tlvchain>
	</define>
	<define name="complex_data_tlv">
		<tlvchain>
			<tlv type="1">
				<data name="foo" />
				<word name="bar" />
				<dword />
				<byte name="baz" />
			</tlv>
		</tlvchain>
	</define>
	<define name="subtyped_tlv">
		<tlvchain subtyped="yes">
			<tlv type="1" subtype="1" name="foo"><data /></tlv>
			<tlv type="1" subtype="2" name="bar"><data /></tlv>
		</tlvchain>
	</define>
	<define name="count_prefic_tlv">
		<tlvchain count_prefix="word">
			<tlv type="1"><data /></tlv>
		</tlvchain>
	</define>

	<!-- ref -->
	<define name="ref_foo"><data /></define>
	<define name="ref_bar"><data /></define>
	<define name="ref"><ref name="ref_foo" /><ref name="ref_bar" /></define>

	<!-- Miscellaneous -->
	<define name="empty_def" />
