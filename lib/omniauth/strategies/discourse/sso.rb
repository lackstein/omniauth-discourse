require "securerandom"

module OmniAuth
  module Strategies
    class Discourse
      class SSO
        attr_accessor :nonce, :user_info, :status, :message
        
        def initialize(sso_secret, sso_url, return_url, nonce = nil)
          @sso_secret, @sso_url, @return_url = sso_secret, sso_url, return_url
          @nonce = nonce ? nonce : generate_nonce!
        end

        def generate_nonce!
          SecureRandom.hex()
        end

        def request_url
          "#{ @sso_url }?sso=#{ url_encoded_payload }&sig=#{ hex_signature }"
        end

        def parse(params)
          #params should be something that looks like: {"sso": "xxxxxx", "sig": "yyyyyy"} 
          if get_hmac_hex_string(params["sso"]) == params["sig"] 
            if base64? params["sso"]
              decoded_hash = Rack::Utils.parse_query(Base64.decode64(params["sso"]))
              decoded_hash.symbolize_keys!
              if decoded_hash[:nonce] == @nonce   
                @status = "success"
                decoded_hash.delete(:nonce)
                @user_info = decoded_hash
                @message = "SSO verification passed."
                return self
              else
                @status = "error"
                @user_info = nil
                @message = "SSO verification failed. Nonce mismatch."
                return nil
              end  
            else
              @status = "error"
              @user_info = nil
              @message = "The sso string is supposed to be encoded in Base64."
              return nil       
            end
          else
            @status = "error"
            @user_info = nil
            @message = "HMAC mismatch. The message may have been tampered with."
            return nil          
          end
        end

        private 
          def raw_payload
            unless @nonce
              raise "You must generate a nonce by calling generate_nonce! first."
            else
              "nonce=#{ @nonce }&return_sso_url=#{ @return_url }"
            end
          end

          def base64_encoded_payload
            Base64.encode64(raw_payload)
          end

          def url_encoded_payload
            URI.escape(base64_encoded_payload)
          end

          def hex_signature
            get_hmac_hex_string base64_encoded_payload
          end

          def get_hmac_hex_string payload
            OpenSSL::HMAC.hexdigest("sha256", @sso_secret, payload)
          end

          def base64? data
            !(data =~ /[^a-zA-Z0-9=\r\n\/+]/m)
          end

      end
    end
  end
end