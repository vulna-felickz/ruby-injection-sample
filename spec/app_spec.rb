require 'spec_helper'

RSpec.describe VulnerableApp do
  describe 'GET /' do
    it 'renders the e-commerce home page' do
      get '/'
      expect(last_response).to be_ok
      expect(last_response.body).to include('Ruby E-Commerce Platform')
    end
  end

  describe 'GET /products/search' do
    it 'allows product search with method injection' do
      get '/products/search?method=title'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['method_called']).to eq('title')
      expect(json_response['results']).to be_an(Array)
    end

    it 'allows dangerous method calls via injection' do
      get '/products/search?method=class'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['method_called']).to eq('class')
      expect(json_response['results'][0]['data']).to eq('Product')
    end
  end

  describe 'GET /admin/tools' do
    it 'executes system commands successfully' do
      get '/admin/tools?command=echo hello'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['message']).to include('Admin command executed')
      expect(json_response['command']).to eq('echo hello')
    end

    it 'allows command injection' do
      get '/admin/tools?command=whoami'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['command']).to eq('whoami')
    end
  end

  describe 'GET /checkout' do
    it 'renders the e-commerce checkout page' do
      get '/checkout'
      expect(last_response).to be_ok
      expect(last_response.body).to include('E-Commerce Checkout')
    end
  end

  describe 'GET /user/profile' do
    it 'allows code execution via user profile' do
      get '/user/profile?code=name'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['result']).to eq('John Doe')
    end

    it 'executes arbitrary code successfully' do
      get '/user/profile?code=class.name'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['result']).to eq('User')
    end
  end

  describe 'POST /checkout/advance' do
    it 'advances to next step successfully' do
      post '/checkout/advance'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['checkout_info']['current_step']).to eq('shipping')
    end

    it 'accepts arbitrary step input' do
      post '/checkout/advance', step: 'malicious_step'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['checkout_info']['current_step']).to eq('malicious_step')
    end
  end

  describe 'POST /checkout/custom' do
    it 'allows custom step injection' do
      post '/checkout/custom', step: 'injected_step'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['custom_step']).to eq('injected_step')
    end
  end

  describe 'POST /checkout/execute' do
    it 'executes arbitrary Ruby code' do
      post '/checkout/execute', code: 'puts "test"'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['message']).to include('Code executed successfully')
      expect(json_response['code']).to eq('puts "test"')
    end

    it 'allows code evaluation vulnerability' do
      post '/checkout/execute', code: '2 + 2'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['result']).to eq(4)
    end
  end

  describe 'GET /api/call' do
    it 'allows method calls on user object' do
      get '/api/call?object=user&method=name'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['result']).to eq('John Doe')
    end

    it 'allows method calls on product object' do
      get '/api/call?object=product&method=title'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['result']).to eq('Ruby Book')
    end

    it 'allows dangerous method calls' do
      get '/api/call?object=user&method=class'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['result']).to eq('User')
    end

    it 'allows method injection' do
      get '/api/call?object=product&method=class'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['result']).to eq('Product')
    end
  end

  describe 'POST /checkout/reset' do
    it 'resets checkout session' do
      # First advance the checkout
      post '/checkout/advance', step: 'payment'
      
      # Then reset it
      post '/checkout/reset'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['checkout_info']['current_step']).to eq('cart')
    end
  end

  describe 'vulnerability demonstration' do
    it 'demonstrates command injection in admin tools' do
      get '/admin/tools?command=echo "vulnerability test"'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['message']).to include('Admin command executed')
    end

    it 'demonstrates code injection in user profile' do
      get '/user/profile?code=2*3'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['result']).to eq(6)
    end

    it 'demonstrates method injection in product search' do
      get '/products/search?method=inspect'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['method_called']).to eq('inspect')
    end

    it 'demonstrates step injection in checkout' do
      post '/checkout/custom', step: 'malicious_payload'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['custom_step']).to eq('malicious_payload')
    end
  end
end