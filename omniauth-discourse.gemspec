require File.expand_path("../lib/omniauth-discourse/version", __FILE__)

Gem::Specification.new do |gem|
  gem.authors       = ["Noah Lackstein"]
  gem.email         = ["noah@lackstein.com"]
  gem.description   = "A generic strategy for OmniAuth to authenticate against Discourse forum's SSO."
  gem.summary       = gem.description
  gem.homepage      = "https://github.com/lackstein/omniauth-discourse"
  gem.license       = "MIT"

  gem.add_dependency "omniauth", ">= 1.0", "< 3"
  gem.add_development_dependency "bundler", "~> 1.9"

  gem.executables   = `git ls-files -- bin/*`.split("\n").map { |f| File.basename(f) }
  gem.files         = `git ls-files`.split("\n")
  gem.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  gem.name          = "omniauth-discourse"
  gem.require_paths = ["lib"]
  gem.version       = OmniAuth::Discourse::VERSION
end
