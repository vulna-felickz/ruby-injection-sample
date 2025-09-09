require 'rspec'
require 'rack/test'
require_relative '../app'
require_relative '../lib/secure_cache'
require_relative '../lib/checkout_system'
require_relative '../lib/models'

RSpec.configure do |config|
  config.include Rack::Test::Methods
  
  def app
    SecureApp
  end
end