require 'sinatra/base'
require 'sinatra/json'
require 'json'
require 'cgi'
require_relative 'lib/secure_cache'
require_relative 'lib/checkout_system'
require_relative 'lib/models'

class SecureApp < Sinatra::Base
  # Enable sessions for checkout state
  enable :sessions
  set :session_secret, 'secure_demo_secret_change_in_production_this_is_32_bytes_or_more_for_security'

  # Initialize sample data
  def initialize
    super
    @sample_user = User.new(1, 'John Doe', 'john@example.com')
    @sample_product = Product.new(1, 'Ruby Book', 'Learn Ruby Programming')
    @sample_order = Order.new(1, @sample_user, @sample_product)
  end

  # Helper to get or create checkout session
  def checkout_session
    session[:checkout] ||= CheckoutSystem.new
  end

  # Home page showing the secure demo
  get '/' do
    erb :index
  end

  # Demo endpoint showing secure cache usage
  get '/demo/cache' do
    begin
      # These are examples of SAFE operations using try_cache
      safe_examples = {
        user_name: SecureCache.try_cache(@sample_user, 'name'),
        user_email: SecureCache.try_cache(@sample_user, 'email'),
        product_title: SecureCache.try_cache(@sample_product, 'title'),
        order_user_name: SecureCache.try_cache(@sample_order, 'name', 'user'),
        order_product_title: SecureCache.try_cache(@sample_order, 'title', 'product')
      }

      json({
        status: 'success',
        message: 'Secure cache operations completed successfully',
        data: safe_examples
      })
    rescue => e
      json({
        status: 'error',
        message: e.message
      })
    end
  end

  # Attempt to use unsafe method (should fail)
  get '/demo/cache/unsafe' do
    method_name = params[:method] || 'system'
    
    begin
      # This will fail because 'system' is not in SAFE_METHODS
      result = SecureCache.try_cache(@sample_user, method_name)
      
      json({
        status: 'error',
        message: 'This should not have succeeded!'
      })
    rescue ArgumentError => e
      json({
        status: 'success',
        message: 'Security validation worked!',
        error: e.message
      })
    end
  end

  # Checkout demo endpoints
  get '/checkout' do
    @checkout = checkout_session
    erb :checkout
  end

  # Advance checkout step (with validation)
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
        # Try to advance to specific step
        @checkout.advance_to_step(step)
        flash_message = "Advanced to #{step} step"
      end

      json({
        status: 'success',
        message: flash_message,
        checkout_info: @checkout.step_info
      })
    rescue ArgumentError => e
      json({
        status: 'error',
        message: e.message,
        checkout_info: @checkout.step_info
      })
    end
  end

  # Try to inject malicious step (should fail)
  post '/checkout/inject' do
    @checkout = checkout_session
    malicious_step = params[:malicious_step] || 'eval("puts `whoami`")'

    begin
      @checkout.advance_to_step(malicious_step)
      
      json({
        status: 'error',
        message: 'Injection should have been blocked!'
      })
    rescue ArgumentError => e
      json({
        status: 'success',
        message: 'Injection attempt blocked successfully!',
        error: e.message,
        attempted_injection: malicious_step
      })
    end
  end

  # Reset checkout session
  post '/checkout/reset' do
    session[:checkout] = CheckoutSystem.new
    
    json({
      status: 'success',
      message: 'Checkout session reset',
      checkout_info: session[:checkout].step_info
    })
  end

  # API endpoint to demonstrate safe public_send usage
  get '/api/safe_call' do
    object_type = params[:object] || 'user'
    method_name = params[:method] || 'name'

    target_object = case object_type
                   when 'user' then @sample_user
                   when 'product' then @sample_product
                   when 'order' then @sample_order
                   else @sample_user
                   end

    begin
      result = SecureCache.safe_public_send(target_object, method_name)
      
      json({
        status: 'success',
        object_type: object_type,
        method_called: method_name,
        result: result
      })
    rescue ArgumentError => e
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
    erb :security
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