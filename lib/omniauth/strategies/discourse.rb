require "omniauth"
require "omniauth/strategies/discourse/sso"

module OmniAuth
  module Strategies
    class Discourse
      include OmniAuth::Strategy
      
      args [:sso_url, :sso_secret]
      option :sso_url, nil
      option :sso_secret, nil
    end
  end
end
