require "omniauth"
require "omniauth/strategies/discourse/sso"

module OmniAuth
  module Strategies
    class Discourse
      include OmniAuth::Strategy
      
      args [:sso_secret, :sso_url]
      option :sso_secret, nil
      option :sso_url, nil
      
      attr_reader :user_info
      
      def request_phase
        sso = SSO.new(options.sso_secret, options.sso_url, callback_url)
        session[:sso_nonce] = sso.nonce
          
        redirect sso.request_url
      end
      
      def callback_phase
        sso = SSO.new(options.sso_secret, options.sso_url, callback_url, session[:sso_nonce])
        sso.parse(request.params)
        
        fail!(:invalid_credentials, "Username or password are not valid") if sso.status == "error"
        
        @user_info = sso.user_info
      end
      
      uid do
        user_info[:external_id]
      end
      
      info do
        {
          "name" => user_info[:name],
          "email" => user_info[:email],
          "nickname" => user_info[:username]
        }
      end
      
      extra do
        {
          "admin" => user_info[:admin] == "true",
          "moderator" => user_info[:moderator] == "true"
        }
      end
    end
  end
end
