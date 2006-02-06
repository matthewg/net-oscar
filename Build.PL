#!/usr/bin/perl

use Module::Build;

$build = Module::Build->new (
        module_name => "Net::OSCAR",
	license => "perl",
        requires => {
                'perl' => '5.6.1',
                'Digest::MD5' => '>= 2.0',
                'Scalar::Util' => '>= 1.0',
		'Module::Build' => '>= 0.26',
	},
	recommends => {
		'Test::More' => '>= 0.01',
		'XML::Parser' => '>= 0.01',
		'Time::HiRes' => '>= 0.01',
		'MIME::Base64' => '>= 0.01'
	},
	create_makefile_pl => "traditional",
	create_readme => 1,
	PL_files => { 'xmlcache' => 'lib/Net/OSCAR/XML/Protocol.parsed-xml' },
	script_files => ["oscartest"],
	sign => 1,
);
$build->add_build_element("xml");
$build->add_build_element("parsed-xml");
$build->create_build_script;

