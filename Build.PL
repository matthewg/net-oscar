#!/usr/bin/perl

use Module::Build;

$build = Module::Build->new (
        module_name => "Net::OSCAR",
	license => "perl",
        requires => {
                'perl' => '5.6',
                'Digest::MD5' => '>= 2.0',
                'Scalar::Util' => '>= 1.0'
	},
	create_makefile_pl => "traditional",
	dist_version_from => "OSCAR.pm",
	pm_files => {
		'OSCAR.pm' => 'lib/Net/OSCAR.pm',
		'OSCAR/Connection/Chat.pm' => 'lib/Net/OSCAR/Connection/Chat.pm',
		'OSCAR/Buddylist.pm' => 'lib/Net/OSCAR/Buddylist.pm',
		'OSCAR/Callbacks.pm' => 'lib/Net/OSCAR/Callbacks.pm',
		'OSCAR/Common.pm' => 'lib/Net/OSCAR/Common.pm',
		'OSCAR/Connection.pm' => 'lib/Net/OSCAR/Connection.pm',
		'OSCAR/Constants.pm' => 'lib/Net/OSCAR/Constants.pm',
		'OSCAR/Proxy.pm' => 'lib/Net/OSCAR/Proxy.pm',
		'OSCAR/Screenname.pm' => 'lib/Net/OSCAR/Screenname.pm',
		'OSCAR/TLV.pm' => 'lib/Net/OSCAR/TLV.pm',
		'OSCAR/Utility.pm' => 'lib/Net/OSCAR/Utility.pm',
		'OSCAR/_BLInternal.pm' => 'lib/Net/OSCAR/_BLInternal.pm',
		'OSCAR/XML.pm' => 'lib/Net/OSCAR/XML.pm',
		'OSCAR/XML/Protocol.xml' => 'lib/Net/OSCAR/XML/Protocol.xml',
		'OSCAR/XML/Protocol.dtd' => 'lib/Net/OSCAR/XML/Protocol.dtd'
	},
);
$build->create_build_script;

