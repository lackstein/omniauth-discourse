# OmniAuth Discourse

Allows OmniAuth to authenticate against a Discourse forum.

## Setup

On your Discourse forum, go into the Admin Settings, check "enable sso provider" and generate a strong secret for "sso secret".

In your Rails app:

Add the following line to your Gemfile:

    gem 'omniauth-discourse'

Then add the following line to your OmniAuth initializer:

    provider :discourse,
      sso_url: "https://forum.example.com/session/sso_provider",
      sso_secret: Rails.application.secrets.sso_secret
Make sure you set the URL to point to your forum, and the secret to the secret generated earlier.

That's it!

## Information provided by Discourse

The following information about each user will be available in the OmniAuth authhash:

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