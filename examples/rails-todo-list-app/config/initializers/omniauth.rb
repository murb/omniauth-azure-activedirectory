Rails.application.config.middleware.use OmniAuth::Builder do
  provider :azureactivedirectory, ENV['CLIENT_ID'], ENV['TENANT']
end
