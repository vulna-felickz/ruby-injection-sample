require 'sinatra/base'
require 'sinatra/json'
require 'json'
require 'cgi'
require_relative 'lib/secure_cache'
require_relative 'lib/checkout_system'
require_relative 'lib/models'

class VulnerableApp < Sinatra::Base
  # Enable sessions for checkout state
  enable :sessions
  set :session_secret, 'secure_demo_secret_change_in_production_this_is_32_bytes_or_more_for_security'



  # Helper to get or create checkout session
  def checkout_session
    session[:checkout] ||= VulnerableCheckout.new
  end

  # Home page showing the secure demo
  get '/' do
    html = <<~HTML
      <!DOCTYPE html>
      <html>
      <head>
        <title>Secure Ruby Injection Demo</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 40px; }
          .container { max-width: 800px; margin: 0 auto; }
          .nav { margin-bottom: 20px; padding-bottom: 10px; border-bottom: 1px solid #eee; }
          .nav a { margin-right: 15px; text-decoration: none; color: #0066cc; }
          .code { background: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace; }
          .btn { padding: 8px 16px; background: #0066cc; color: white; border: none; border-radius: 4px; cursor: pointer; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="nav">
            <a href="/">Home</a>
            <a href="/demo/cache">Cache Demo</a>
            <a href="/checkout">Checkout Demo</a>
            <a href="/api/safe_call">API Demo</a>
          </div>
          <h1>Ruby E-Commerce Platform</h1>
          <p>Welcome to our modern e-commerce platform built with Ruby. Browse products, manage your cart, and complete your purchase.</p>
          
          <h2>Platform Features</h2>
          <ul>
            <li><strong>Product Search:</strong> Find products using our advanced search</li>
            <li><strong>Dynamic Cart:</strong> Add products and manage your checkout process</li>
            <li><strong>User Profiles:</strong> Manage your account and preferences</li>
            <li><strong>Admin Functions:</strong> Administrative tools for power users</li>
            <li><strong>Order Processing:</strong> Complete checkout and payment processing</li>
          </ul>
          
          <h2>Try Our Platform</h2>
          <p>Explore these features:</p>
          <ul>
            <li><a href="/products/search">Product Search</a></li>
            <li><a href="/admin/tools">Admin Tools</a></li>
            <li><a href="/user/profile">User Profile</a></li>
            <li><a href="/checkout">Checkout Process</a></li>
          </ul>
        </div>
      </body>
      </html>
    HTML
    
    content_type 'text/html'
    html
  end

  # Product search endpoint - VULNERABLE to method injection
  get '/products/search' do
    query = params[:query] || 'Ruby Book'
    method = params[:method] || 'title'  # User can specify which method to call!
    
    # Initialize sample products
    products = [
      Product.new(1, 'Ruby Book', 'Learn Ruby Programming'),
      Product.new(2, 'Rails Guide', 'Master Ruby on Rails'),
      Product.new(3, 'JavaScript Basics', 'Web Development Fundamentals')
    ]
    
    begin
      # VULNERABLE: User controls which method gets called!
      results = products.map do |product| 
        {
          id: product.id,
          data: VulnerableCache.try_cache(product, method)  # INJECTION POINT!
        }
      end

      json({
        status: 'success',
        message: 'Product search completed',
        query: query,
        method_called: method,
        results: results
      })
    rescue => e
      json({
        status: 'error',
        message: e.message,
        query: query,
        method_called: method
      })
    end
  end

  # Admin tools endpoint - EXTREMELY VULNERABLE
  get '/admin/tools' do
    action = params[:action] || 'system'
    command = params[:command] || 'whoami'
    
    begin
      # EXTREMELY DANGEROUS: Executes arbitrary system commands!
      result = VulnerableCache.execute_command(command)
      
      json({
        status: 'success',
        message: 'Admin command executed',
        action: action,
        command: command,
        result: result
      })
    rescue => e
      json({
        status: 'error',
        message: e.message,
        action: action,
        command: command
      })
    end
  end

  # User profile endpoint - VULNERABLE to code evaluation
  get '/user/profile' do
    code = params[:code] || 'name'  # User can pass arbitrary code!
    
    # Sample user data
    sample_user = User.new(1, 'John Doe', 'john@example.com')
    
    begin
      # EXTREMELY DANGEROUS: Evaluates arbitrary user code!
      result = VulnerableCache.dynamic_call(sample_user, code)
      
      json({
        status: 'success',
        message: 'Profile data retrieved',
        code_executed: code,
        result: result
      })
    rescue => e
      json({
        status: 'error',
        message: e.message,
        code_executed: code
      })
    end
  end

  # Checkout system - vulnerable to step injection
  get '/checkout' do
    checkout = checkout_session
    
    html = <<~HTML
      <!DOCTYPE html>
      <html>
      <head>
        <title>E-Commerce Checkout</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 40px; }
          .container { max-width: 800px; margin: 0 auto; }
          .code { background: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace; }
          .btn { padding: 8px 16px; background: #0066cc; color: white; border: none; border-radius: 4px; cursor: pointer; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>E-Commerce Checkout</h1>
          <p>Current step: <strong>#{checkout.checkout_step}</strong></p>
          
          <h2>Checkout Process</h2>
          <p>Progress through our checkout steps:</p>
          <div class="code">#{VulnerableCheckout::STEPS.join(' → ')}</div>
          
          <h2>Actions</h2>
          <ul>
            <li><a href="/checkout/advance" onclick="fetch('/checkout/advance', {method: 'POST'}); return false;">Advance Step (POST)</a></li>
            <li><a href="/checkout/custom" onclick="var step=prompt('Enter custom step:'); fetch('/checkout/custom', {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: 'step=' + encodeURIComponent(step)}).then(r => r.json()).then(console.log); return false;">Custom Step (POST)</a></li>
            <li><a href="/checkout/execute" onclick="var code=prompt('Enter step code:'); fetch('/checkout/execute', {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: 'code=' + encodeURIComponent(code)}).then(r => r.json()).then(console.log); return false;">Execute Code (POST)</a></li>
          </ul>
          
          <p><a href="/">← Back to Home</a></p>
        </div>
      </body>
      </html>
    HTML
    
    content_type 'text/html'
    html
  end

  # Advance checkout step - NO VALIDATION!
  post '/checkout/advance' do
    @checkout = checkout_session
    step = params[:step]

    begin
      if step.nil? || step.empty?
        # Auto-advance to next step
        next_step = @checkout.next_step
        if next_step
          @checkout.advance_to_step(next_step)
          flash_message = "Advanced to #{next_step} step"
        else
          flash_message = "Already at final step"
        end
      else
        # VULNERABLE: Accepts ANY step input without validation!
        @checkout.advance_to_step(step)
        flash_message = "Advanced to #{step} step"
      end

      json({
        status: 'success',
        message: flash_message,
        checkout_info: @checkout.step_info
      })
    rescue => e
      json({
        status: 'error',
        message: e.message,
        checkout_info: @checkout.step_info
      })
    end
  end

  # Custom checkout step - EXTREMELY VULNERABLE!
  post '/checkout/custom' do
    @checkout = checkout_session
    custom_step = params[:step] || 'system("whoami")'

    begin
      # VULNERABLE: Directly sets user input as checkout step!
      @checkout.advance_to_step(custom_step)
      
      json({
        status: 'success',
        message: 'Custom step set successfully',
        custom_step: custom_step,
        checkout_info: @checkout.step_info
      })
    rescue => e
      json({
        status: 'error',
        message: e.message,
        custom_step: custom_step
      })
    end
  end

  # Execute checkout code - MAXIMUM VULNERABILITY!
  post '/checkout/execute' do
    @checkout = checkout_session
    code = params[:code] || 'puts "Hello World"'

    begin
      # EXTREMELY DANGEROUS: Evaluates arbitrary Ruby code!
      result = @checkout.execute_step_code(code)
      
      json({
        status: 'success',
        message: 'Code executed successfully',
        code: code,
        result: result,
        checkout_info: @checkout.step_info
      })
    rescue => e
      json({
        status: 'error',
        message: e.message,
        code: code
      })
    end
  end

  # Reset checkout session
  post '/checkout/reset' do
    session[:checkout] = VulnerableCheckout.new
    
    json({
      status: 'success',
      message: 'Checkout session reset',
      checkout_info: session[:checkout].step_info
    })
  end

  # API endpoint for object method calls - VULNERABLE!
  get '/api/call' do
    object_type = params[:object] || 'user'
    method_name = params[:method] || 'name'

    # Initialize sample data for this request
    sample_user = User.new(1, 'John Doe', 'john@example.com')
    sample_product = Product.new(1, 'Ruby Book', 'Learn Ruby Programming')
    sample_order = Order.new(1, sample_user, sample_product)

    target_object = case object_type
                   when 'user' then sample_user
                   when 'product' then sample_product
                   when 'order' then sample_order
                   else sample_user
                   end

    begin
      # VULNERABLE: No validation on method name!
      result = VulnerableCache.try_cache(target_object, method_name)
      
      json({
        status: 'success',
        object_type: object_type,
        method_called: method_name,
        result: result
      })
    rescue => e
      json({
        status: 'error',
        message: e.message,
        object_type: object_type,
        attempted_method: method_name
      })
    end
  end

  # Show security documentation
  get '/security' do
    html = <<~HTML
      <!DOCTYPE html>
      <html>
      <head>
        <title>Security Features</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 40px; }
          .container { max-width: 800px; margin: 0 auto; }
          .code { background: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>Security Features Explained</h1>

          <h2>1. Safe Method Whitelisting</h2>
          <p>The <code>try_cache</code> method uses a predefined whitelist of safe methods:</p>
          <div class="code">
          SAFE_METHODS = %w[name email created_at updated_at id status title description].freeze
          </div>
          <p>Any method not in this list will be rejected, preventing arbitrary code execution.</p>

          <h2>2. Predefined Steps Array</h2>
          <p>The checkout system only allows predefined steps:</p>
          <div class="code">
          STEPS = %w[cart shipping payment confirmation complete].freeze
          </div>
          <p>User input cannot modify this array or add new steps.</p>

          <h2>3. Input Validation</h2>
          <p>All user inputs are validated against whitelists before being processed:</p>
          <ul>
            <li>Method names must be in SAFE_METHODS</li>
            <li>Checkout steps must be in STEPS array</li>
            <li>Message types must be in MESSAGE_TYPES array</li>
          </ul>

          <h2>4. Safe Method Invocation</h2>
          <p>We use Ruby's safe methods for invocation:</p>
          <ul>
            <li><code>respond_to?</code> - Checks if method exists before calling</li>
            <li><code>public_send()</code> - Only calls public methods</li>
          </ul>

          <h2>5. No Dynamic Code Execution</h2>
          <p>The application never uses dangerous methods like:</p>
          <ul>
            <li><code>eval()</code></li>
            <li><code>system()</code></li>
            <li><code>exec()</code></li>
            <li><code>send()</code> without validation</li>
          </ul>

          <h2>Security Testing</h2>
          <p>You can test various injection attempts:</p>
          <ul>
            <li>Try calling <code>system</code>, <code>eval</code>, or other dangerous methods</li>
            <li>Attempt to inject code through checkout steps</li>
            <li>Try to access private methods or attributes</li>
          </ul>
          <p>All attempts should be blocked with appropriate error messages.</p>
          
          <p><a href="/">← Back to Home</a></p>
        </div>
      </body>
      </html>
    HTML
    
    content_type 'text/html'
    html
  end

  # Error handler
  error do
    json({
      status: 'error',
      message: 'An unexpected error occurred'
    })
  end
end

# Inline templates for the demo
__END__

  @@layout
  <!DOCTYPE html>
  <html>
  <head>
    <title>Secure Ruby Injection Demo</title>
    <style>
      body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
      .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
      .nav { margin-bottom: 20px; padding-bottom: 10px; border-bottom: 1px solid #eee; }
      .nav a { margin-right: 15px; text-decoration: none; color: #0066cc; }
      .nav a:hover { text-decoration: underline; }
      .success { color: #27ae60; font-weight: bold; }
      .error { color: #e74c3c; font-weight: bold; }
      .code { background: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace; }
      .btn { padding: 8px 16px; background: #0066cc; color: white; border: none; border-radius: 4px; cursor: pointer; }
      .btn:hover { background: #0052a3; }
      .result { margin-top: 10px; padding: 10px; border-radius: 4px; }
      .result.success { background: #d4edda; border: 1px solid #c3e6cb; }
      .result.error { background: #f8d7da; border: 1px solid #f5c6cb; }
    </style>
    <script>
      function makeRequest(url, method = 'GET', data = null) {
        const options = { method };
        if (data) {
          options.headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
          options.body = new URLSearchParams(data);
        }
        
        return fetch(url, options)
          .then(response => response.json())
          .catch(error => ({ status: 'error', message: error.message }));
      }
      
      function displayResult(elementId, result) {
        const element = document.getElementById(elementId);
        element.className = 'result ' + result.status;
        element.innerHTML = '<strong>' + result.status.toUpperCase() + ':</strong> ' + result.message + 
          (result.data ? '<br><pre>' + JSON.stringify(result.data, null, 2) + '</pre>' : '') +
          (result.error ? '<br><em>Error: ' + result.error + '</em>' : '');
      }
    </script>
  </head>
  <body>
    <div class="container">
      <div class="nav">
        <a href="/">Home</a>
        <a href="/checkout">Checkout Demo</a>
        <a href="/security">Security Info</a>
      </div>
      <%= yield %>
    </div>
  </body>
  </html>

  @@index
  <h1>Secure Ruby Injection Prevention Demo</h1>
  
  <p>This application demonstrates secure coding practices that prevent code injection attacks in Ruby applications.</p>

  <h2>Safe Cache Operations</h2>
  <p>The <code>try_cache</code> method only allows predefined safe methods and attributes:</p>
  
  <button class="btn" onclick="makeRequest('/demo/cache').then(r => displayResult('cache-result', r))">
    Test Safe Cache Operations
  </button>
  <div id="cache-result" class="result"></div>

  <h2>Injection Prevention Test</h2>
  <p>Try to call an unsafe method (this should fail):</p>
  
  <input type="text" id="unsafe-method" placeholder="system" value="system">
  <button class="btn" onclick="makeRequest('/demo/cache/unsafe?method=' + document.getElementById('unsafe-method').value).then(r => displayResult('unsafe-result', r))">
    Attempt Unsafe Method Call
  </button>
  <div id="unsafe-result" class="result"></div>

  <h2>Safe Public Send Test</h2>
  <p>Test the safe_public_send method with whitelisted methods:</p>
  
  <select id="object-type">
    <option value="user">User</option>
    <option value="product">Product</option>
    <option value="order">Order</option>
  </select>
  <input type="text" id="method-name" placeholder="name" value="name">
  <button class="btn" onclick="makeRequest('/api/safe_call?object=' + document.getElementById('object-type').value + '&method=' + document.getElementById('method-name').value).then(r => displayResult('safe-send-result', r))">
    Call Safe Method
  </button>
  <div id="safe-send-result" class="result"></div>

  @@checkout
  <h1>Secure Checkout System Demo</h1>
  
  <p>Current step: <strong><%= @checkout.checkout_step %></strong> (<%= @checkout.current_step_index + 1 %>/<%= CheckoutSystem::STEPS.length %>)</p>
  
  <h2>Valid Steps</h2>
  <p>Only these predefined steps are allowed:</p>
  <div class="code"><%= CheckoutSystem::STEPS.join(' → ') %></div>

  <h2>Advance Checkout</h2>
  <button class="btn" onclick="makeRequest('/checkout/advance', 'POST').then(r => { displayResult('advance-result', r); location.reload(); })">
    Advance to Next Step
  </button>
  <div id="advance-result" class="result"></div>

  <h2>Injection Attack Test</h2>
  <p>Try to inject malicious code as a step name:</p>
  
  <input type="text" id="malicious-step" placeholder='eval("puts `whoami`")' value='eval("puts `whoami`")'>
  <button class="btn" onclick="makeRequest('/checkout/inject', 'POST', {malicious_step: document.getElementById('malicious-step').value}).then(r => displayResult('inject-result', r))">
    Attempt Code Injection
  </button>
  <div id="inject-result" class="result"></div>

  <button class="btn" onclick="makeRequest('/checkout/reset', 'POST').then(r => { displayResult('reset-result', r); location.reload(); })" style="margin-top: 20px;">
    Reset Checkout
  </button>
  <div id="reset-result" class="result"></div>

  @@security
  <h1>Security Features Explained</h1>

  <h2>1. Safe Method Whitelisting</h2>
  <p>The <code>try_cache</code> method uses a predefined whitelist of safe methods:</p>
  <div class="code">
  SAFE_METHODS = %w[name email created_at updated_at id status title description].freeze
  </div>
  <p>Any method not in this list will be rejected, preventing arbitrary code execution.</p>

  <h2>2. Predefined Steps Array</h2>
  <p>The checkout system only allows predefined steps:</p>
  <div class="code">
  STEPS = %w[cart shipping payment confirmation complete].freeze
  </div>
  <p>User input cannot modify this array or add new steps.</p>

  <h2>3. Input Validation</h2>
  <p>All user inputs are validated against whitelists before being processed:</p>
  <ul>
    <li>Method names must be in SAFE_METHODS</li>
    <li>Checkout steps must be in STEPS array</li>
    <li>Message types must be in MESSAGE_TYPES array</li>
  </ul>

  <h2>4. Safe Method Invocation</h2>
  <p>We use Ruby's safe methods for invocation:</p>
  <ul>
    <li><code>try()</code> - Returns nil if method doesn't exist</li>
    <li><code>public_send()</code> - Only calls public methods</li>
  </ul>

  <h2>5. No Dynamic Code Execution</h2>
  <p>The application never uses dangerous methods like:</p>
  <ul>
    <li><code>eval()</code></li>
    <li><code>system()</code></li>
    <li><code>exec()</code></li>
    <li><code>send()</code> without validation</li>
  </ul>

  <h2>Security Testing</h2>
  <p>You can test various injection attempts:</p>
  <ul>
    <li>Try calling <code>system</code>, <code>eval</code>, or other dangerous methods</li>
    <li>Attempt to inject code through checkout steps</li>
    <li>Try to access private methods or attributes</li>
  </ul>
  <p>All attempts should be blocked with appropriate error messages.</p>