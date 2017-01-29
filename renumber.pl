open(FH, $ARGV[0]);

$testcount = 0;

while(<FH>) {
	if($_ =~ /^(#define\s+TEST)(\d+)(\s+.*)$/) {
		$testcount = $testcount + 1;
		print $1 . $testcount . $3 ."\n";
	}
	else {
		print $_;
	}
}
