# OmniAuth2 Azure Active Directory

OmniAuth strategy to authenticate to Azure Active Directory via OpenId Connect.

Before starting, set up a tenant and register a Web Application at [https://manage.windowsazure.com](https://manage.windowsazure.com). Note your client id and tenant for later.

## Samples and Documentation

[We provide a full suite of sample applications and documentation on GitHub](https://github.com/AzureADSamples) to help you get started with learning the Azure Identity system. This includes tutorials for native clients such as Windows, Windows Phone, iOS, OSX, Android, and Linux. We also provide full walkthroughs for authentication flows such as OAuth2, OpenID Connect, Graph API, and other awesome features.

## Community Help and Support

We leverage [Stack Overflow](http://stackoverflow.com/) to work with the community on supporting Azure Active Directory and its SDKs, including this one! We highly recommend you ask your questions on Stack Overflow (we're all on there!) Also browser existing issues to see if someone has had your question before.

We recommend you use the "adal" tag so we can see it! Here is the latest Q&A on Stack Overflow for ADAL: [http://stackoverflow.com/questions/tagged/adal](http://stackoverflow.com/questions/tagged/adal)

## Security Reporting

If you find a security issue with our libraries or services please report it to [secure@microsoft.com](mailto:secure@microsoft.com) with as much detail as possible. Your submission may be eligible for a bounty through the [Microsoft Bounty](http://aka.ms/bugbounty) program. Please do not post security issues to GitHub Issues or any other public site. We will contact you shortly upon receiving the information. We encourage you to get notifications of when security incidents occur by visiting [this page](https://technet.microsoft.com/en-us/security/dd252948) and subscribing to Security Advisory Alerts.

## We Value and Adhere to the Microsoft Open Source Code of Conduct

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## How to use this SDK

#### Installation

Add to your Gemfile:

```ruby
gem 'omniauth-azure-activedirectory'
```

### Usage

If you are already using OmniAuth, adding AzureAD is as simple as adding a new provider to your `OmniAuth::Builder`. The provider requires your AzureAD client id and your AzureAD tenant.

For example, in Rails you would add this in `config/initializers/omniauth.rb`:

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :azureactivedirectory, ENV['AAD_CLIENT_ID'], ENV['AAD_TENANT']
  # other providers here
end
```

If you are using Sinatra or something else that requires you to configure Rack yourself, you should add this to your `config.ru`:

```ruby
use OmniAuth::Builder do
  provider :azureactivedirectory, ENV['AAD_CLIENT_ID'], ENV['AAD_TENANT']
end
```

When you want to authenticate the user, simply redirect them to `/auth/azureactivedirectory`. From there, OmniAuth will takeover. Once the user authenticates (or fails to authenticate), they will be redirected to `/auth/azureactivedirectory/callback` or `/auth/azureactivedirectory/failure`. The authentication result is available in `request.env['omniauth.auth']`.

If you are supporting multiple OmniAuth providers, you will likely have something like this in your code:

```ruby
%w(get post).each do |method|
  send(method, '/auth/:provider/callback') do
    auth = request.env['omniauth.auth']

    # Do what you see fit with your newly authenticated user.

  end
end
```

### Auth Hash

OmniAuth AzureAD tries to be consistent with the auth hash schema recommended by OmniAuth. [https://github.com/intridea/omniauth/wiki/Auth-Hash-Schema](https://github.com/intridea/omniauth/wiki/Auth-Hash-Schema).

Here's an example of an authentication hash available in the callback. You can access this hash as `request.env['omniauth.auth']`.

```
  :provider => "azureactivedirectory",
  :uid => "123456abcdef",
  :info => {
    :name => "John Smith",
    :email => "jsmith@contoso.net",
    :first_name => "John",
    :last_name => "Smith"
  },
  :credentials => {
    :code => "ffdsjap9fdjw893-rt2wj8r9r32jnkdsflaofdsa9"
  },
  :extra => {
    :session_state => '532fgdsgtfera32',
    :raw_info => {
      :id_token => "fjeri9wqrfe98r23.fdsaf121435rt.f42qfdsaf",
      :id_token_claims => {
        "aud" => "fdsafdsa-fdsafd-fdsa-sfdasfds",
        "iss" => "https://sts.windows.net/fdsafdsa-fdsafdsa/",
        "iat" => 53315113,
        "nbf" => 53143215,
        "exp" => 53425123,
        "ver" => "1.0",
        "tid" => "5ffdsa2f-dsafds-sda-sds",
        "oid" => "fdsafdsaafdsa",
        "upn" => "jsmith@contoso.com",
        "sub" => "123456abcdef",
        "nonce" => "fdsaf342rfdsafdsafsads"
      },
      :id_token_header => {
        "typ" => "JWT",
        "alg" => "RS256",
        "x5t" => "fdsafdsafdsafdsa4t4er32",
        "kid" => "tjiofpjd8ap9fgdsa44"
      }
    }
  }
```

## Using it with Ruby on Rails (nonce issue)

Below code I use in some of my Rails projects. I am not sure how to integrate this properly in this very gem itself as it should also work outside of the rails ecosystem:

- a cookie is set
- it references ActiveSupport methods

Patches welcome.

```ruby
####
# Monkey patching the updated azuread gem from Microsoft 2015: https://github.com/murb/omniauth-azure-activedirectory.git
####

module OmniAuth
  module Strategies
    # A strategy for authentication against Azure Active Directory.
    class AzureActiveDirectory
      private

      ##
      # Stores the nonce generated nonces; optional response for cookie binding
      #
      # @return String
      def store_nonce
        new_response.set_cookie("omniauth.azure.nonce", {value: encrypt(new_nonce), path: "/", expires: (Time.now + 60 * 60), secure: true, httponly: true, same_site: :none})
      end

      def generate_salt
        len = ActiveSupport::MessageEncryptor.key_len
        @generate_salt ||= SecureRandom.random_bytes(len)
      end

      def crypt(salt = generate_salt)
        return @crypt if @crypt
        len = ActiveSupport::MessageEncryptor.key_len
        key = ActiveSupport::KeyGenerator.new(Rails.application.secrets.secret_key_base).generate_key(salt, len)
        @crypt = ActiveSupport::MessageEncryptor.new(key)
      end

      def encrypt(string)
        "#{Base64.encode64(generate_salt).strip}----#{crypt.encrypt_and_sign(string)}"
      end

      def decrypt(salt_with_encrypted_data)
        salt, encrypted_data = salt_with_encrypted_data.split("----")
        crypt(Base64.decode64(salt)).decrypt_and_verify(encrypted_data)
      end

      ##
      # Returns the most recent nonce for the session and deletes it from the
      # session.
      #
      # @return String
      def read_nonce
        azure_nonce_cookie = request.cookies.delete("omniauth.azure.nonce")
        decrypt(azure_nonce_cookie) if azure_nonce_cookie
      end
    end
  end
end
```

## License

Copyright (c) Microsoft Corporation. Licensed under the MIT License.
