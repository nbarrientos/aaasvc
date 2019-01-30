task :default => [:test]

desc "Run just tests no measurements"
task :test do
  sh "ginkgo -r -skipMeasurements ."
end

desc "Run tests including measure tests"
task :test_and_measure do
  sh "ginkgo -r ."
end


desc "Builds packages"
task :build do
  version = ENV["VERSION"] || "0.0.0"
  sha = `git rev-parse --short HEAD`.chomp
  build = ENV["BUILD"] || "foss"
  packages = (ENV["PACKAGES"] || "").split(",")
  packages = ["el7_64", "el6_64"] if packages.empty?

  source = "/go/src/github.com/choria-io/aaasvc"

  packages.each do |pkg|
    if pkg =~ /^(.+?)_(.+)$/
      builder = "choria/packager:%s-go1.10" % $1
    elsif pkg == "puppet"
      builder = "choria/packager:el7-go1.10-puppet"
    else
      builder = "choria/packager:el7-go1.10"
    end

    sh 'docker run --rm -v `pwd`:%s -e SOURCE_DIR=%s -e ARTIFACTS=%s -e SHA1="%s" -e BUILD="%s" -e VERSION="%s" -e PACKAGE=%s %s' % [
      source,
      source,
      source,
      sha,
      build,
      version,
      pkg,
      builder
    ]
  end
end

desc "Builds binaries"
task :build_binaries do
  version = ENV["VERSION"] || "0.0.0"
  sha = `git rev-parse --short HEAD`.chomp
  build = ENV["BUILD"] || "foss"

  source = "/go/src/github.com/choria-io/aaasvc"

  sh 'docker run --rm  -v `pwd`:%s -e SOURCE_DIR=%s -e ARTIFACTS=%s -e SHA1="%s" -e BUILD="%s" -e VERSION="%s" -e BINARY_ONLY=1 choria/packager:el7-go9.2' % [
    source,
    source,
    source,
    sha,
    build,
    version
  ]
end