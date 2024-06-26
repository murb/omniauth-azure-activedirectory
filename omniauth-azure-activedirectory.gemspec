$LOAD_PATH.push File.expand_path('../lib', __FILE__)
require 'omniauth/azureactivedirectory/version'

Gem::Specification.new do |s|
  s.name            = 'omniauth-azure-activedirectory'
  s.version         = OmniAuth::AzureActiveDirectory::VERSION
  s.author          = 'Microsoft Corporation'
  s.email           = 'nugetaad@microsoft.com'
  s.summary         = 'Azure Active Directory strategy for OmniAuth'
  s.description     = 'Allows developers to authenticate to AAD'
  s.homepage        = 'https://github.com/AzureAD/omniauth-azure-activedirectory'
  s.license         = 'MIT'

  s.files           = `git ls-files`.split("\n")
  s.require_paths   = ['lib']

  s.add_runtime_dependency 'jwt', '~> 2.2'
  s.add_runtime_dependency 'omniauth', '~> 2.0'

  s.add_development_dependency 'rake', '~> 12.3'
  s.add_development_dependency 'rspec', '~> 3.3'
  s.add_development_dependency 'rubocop', '~> 0.93'
  s.add_development_dependency 'simplecov', '~> 0.10'
  s.add_development_dependency 'webmock', '~> 3.0'
end
