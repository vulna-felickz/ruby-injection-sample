require 'spec_helper'

RSpec.describe SecureApp do
  describe 'GET /' do
    it 'renders the home page' do
      get '/'
      expect(last_response).to be_ok
      expect(last_response.body).to include('Secure Ruby Injection Prevention Demo')
    end
  end

  describe 'GET /demo/cache' do
    it 'returns successful cache operations' do
      get '/demo/cache'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['data']).to include('user_name', 'user_email', 'product_title')
    end
  end

  describe 'GET /demo/cache/unsafe' do
    it 'blocks unsafe method calls' do
      get '/demo/cache/unsafe?method=system'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['message']).to include('Security validation worked!')
      expect(json_response['error']).to include('not in the safe methods list')
    end

    it 'blocks eval attempts' do
      get '/demo/cache/unsafe?method=eval'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['error']).to include('not in the safe methods list')
    end

    it 'blocks backtick execution' do
      get '/demo/cache/unsafe?method=`'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['error']).to include('not in the safe methods list')
    end
  end

  describe 'GET /checkout' do
    it 'renders the checkout page' do
      get '/checkout'
      expect(last_response).to be_ok
      expect(last_response.body).to include('Secure Checkout System Demo')
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

    it 'advances to specific valid step' do
      post '/checkout/advance', step: 'payment'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['checkout_info']['current_step']).to eq('payment')
    end

    it 'rejects invalid steps' do
      post '/checkout/advance', step: 'invalid_step'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('error')
      expect(json_response['message']).to include('Invalid step')
    end
  end

  describe 'POST /checkout/inject' do
    it 'blocks system command injection' do
      post '/checkout/inject', malicious_step: 'system("whoami")'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['message']).to include('Injection attempt blocked')
      expect(json_response['attempted_injection']).to eq('system("whoami")')
    end

    it 'blocks eval injection' do
      post '/checkout/inject', malicious_step: 'eval("puts `whoami`")'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['message']).to include('Injection attempt blocked')
    end

    it 'blocks backtick execution' do
      post '/checkout/inject', malicious_step: '`ls -la`'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['message']).to include('Injection attempt blocked')
    end

    it 'blocks send method manipulation' do
      post '/checkout/inject', malicious_step: '__send__(:system, "whoami")'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['message']).to include('Injection attempt blocked')
    end
  end

  describe 'GET /api/safe_call' do
    it 'allows safe method calls on user object' do
      get '/api/safe_call?object=user&method=name'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['result']).to eq('John Doe')
    end

    it 'allows safe method calls on product object' do
      get '/api/safe_call?object=product&method=title'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('success')
      expect(json_response['result']).to eq('Ruby Book')
    end

    it 'blocks unsafe method calls' do
      get '/api/safe_call?object=user&method=system'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('error')
      expect(json_response['message']).to include('not in the safe methods list')
    end

    it 'blocks eval attempts' do
      get '/api/safe_call?object=user&method=eval'
      expect(last_response).to be_ok
      
      json_response = JSON.parse(last_response.body)
      expect(json_response['status']).to eq('error')
      expect(json_response['message']).to include('not in the safe methods list')
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

  describe 'GET /security' do
    it 'renders the security documentation page' do
      get '/security'
      expect(last_response).to be_ok
      expect(last_response.body).to include('Security Features Explained')
      expect(last_response.body).to include('Safe Method Whitelisting')
      expect(last_response.body).to include('Predefined Steps Array')
    end
  end

  describe 'comprehensive injection testing' do
    let(:injection_payloads) do
      [
        # Command execution
        'system("whoami")',
        'exec("whoami")',
        '`whoami`',
        'Kernel.system("whoami")',
        
        # Code evaluation
        'eval("puts `whoami`")',
        'instance_eval("system(\'whoami\')")',
        'class_eval("system(\'whoami\')")',
        'module_eval("system(\'whoami\')")',
        
        # Method manipulation
        'send(:system, "whoami")',
        '__send__(:system, "whoami")',
        'public_send(:system, "whoami")',
        'method(:system).call("whoami")',
        
        # Object manipulation
        'Object.new.system("whoami")',
        'Class.new.system("whoami")',
        'self.class.system("whoami")',
        
        # Constant manipulation
        'Object.const_get(:Kernel).system("whoami")',
        'const_get(:Kernel).system("whoami")',
        
        # File operations
        'File.open("/etc/passwd")',
        'IO.popen("whoami")',
        'open("|whoami")',
        
        # Network operations
        'Net::HTTP.get(URI("http://evil.com"))',
        'open("http://evil.com")',
        
        # Process manipulation
        'Process.spawn("whoami")',
        'fork { system("whoami") }',
        
        # Environment manipulation
        'ENV["PATH"] = "/tmp"',
        '$0 = "malicious"'
      ]
    end

    it 'blocks all injection attempts in checkout steps' do
      injection_payloads.each do |payload|
        post '/checkout/inject', malicious_step: payload
        expect(last_response).to be_ok
        
        json_response = JSON.parse(last_response.body)
        expect(json_response['status']).to eq('success'), 
          "Failed to block payload: #{payload}"
        expect(json_response['message']).to include('Injection attempt blocked'),
          "Failed to block payload: #{payload}"
      end
    end

    it 'blocks all injection attempts in cache method calls' do
      injection_payloads.each do |payload|
        get "/demo/cache/unsafe?method=#{CGI.escape(payload)}"
        expect(last_response).to be_ok
        
        json_response = JSON.parse(last_response.body)
        expect(json_response['status']).to eq('success'),
          "Failed to block payload: #{payload}"
        expect(json_response['error']).to include('not in the safe methods list'),
          "Failed to block payload: #{payload}"
      end
    end

    it 'blocks all injection attempts in safe_call API' do
      injection_payloads.each do |payload|
        get "/api/safe_call?object=user&method=#{CGI.escape(payload)}"
        expect(last_response).to be_ok
        
        json_response = JSON.parse(last_response.body)
        expect(json_response['status']).to eq('error'),
          "Failed to block payload: #{payload}"
        expect(json_response['message']).to include('not in the safe methods list'),
          "Failed to block payload: #{payload}"
      end
    end
  end
end