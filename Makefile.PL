use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'Net::OSCAR',
    'VERSION_FROM'	=> 'OSCAR.pm', # finds $VERSION
    'PREREQ_PM'		=> { Digest::MD5 => 2.0 }, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?    ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM => 'OSCAR.pm', # retrieve abstract from module
       AUTHOR     => 'Matthew Sachs <matthewg@zevils.com>') : ()),
);
