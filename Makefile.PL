use 5.006;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.


WriteMakefile(
    'dist'		=> { DIST_DEFAULT => 'predist tardist' },
    'NAME'		=> 'Net::OSCAR',
    'VERSION_FROM'	=> 'OSCAR.pm', # finds $VERSION
    'PREREQ_PM'		=> { Digest::MD5 => 2.0, Scalar::Util => 1.00 }, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?    ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM => 'OSCAR.pm', # retrieve abstract from module
       AUTHOR     => 'Matthew Sachs <matthewg@zevils.com>') : ()),
);

sub MY::postamble {
	# BSD make uses .ifdef, GNU make uses just ifdef.
	# Feh.
	my $makever = `make -v | head -1`;
	my $dot = "";
	$dot = "." if $makever !~ /GNU/;
	<<EOF;

.PHONY: predist

${dot}ifdef OSCARVER
VERSION = \$(OSCARVER)
VERSION_SYM = \$(OSCARVER)
XS_VERSION = \$(OSCARVER)
CVS_TAG = RELEASE_\$(subst .,_,\$(OSCARVER))
predist:
	\@rcs2log -R > ~/tmp/rcslog
	\@pico OSCAR.pm
	\@find -name \\*.pm -exec perl -npi -e "s/VERSION = .*/VERSION = \$(OSCARVER);/" \\{\\} \\;
	\@cvs commit -m "Changed version number for release \$(OSCARVER)"
	\@cvs rtag -R -F \$(CVS_TAG) net-oscar
	\@pod2html OSCAR.pm > /home/webstuff/programs/net-oscar/net-oscar.html
	\@pod2text OSCAR.pm > README
${dot}else
predist:
	\@echo "You must define OSCARVER!"
	\@false
${dot}endif
EOF
}
