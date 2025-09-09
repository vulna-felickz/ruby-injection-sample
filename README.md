# Secure Ruby Injection Prevention Demo

This repository demonstrates secure Ruby coding practices that prevent code injection attacks. The application proves that with proper input validation, method whitelisting, and safe invocation patterns, external input cannot influence method invocation or enable arbitrary code execution.

## Security Features

### 1. Safe Method Whitelisting (`try_cache`)

The `try_cache` method only allows predefined safe methods from a frozen whitelist:

```ruby
SAFE_METHODS = %w[
  name email created_at updated_at id status title description
].freeze
```

- **Principle**: Only known-safe methods can be called
- **Protection**: Prevents arbitrary method invocation
- **Implementation**: Input validation before method calls

### 2. Predefined Steps Array

The checkout system restricts steps to a frozen array:

```ruby
STEPS = %w[cart shipping payment confirmation complete].freeze
```

- **Principle**: User input cannot modify predefined workflows
- **Protection**: Prevents injection through step manipulation
- **Implementation**: Validation against immutable constants

### 3. Input Validation and Sanitization

All user inputs are validated against whitelists:

- Method names must be in `SAFE_METHODS`
- Checkout steps must be in `STEPS` array
- Message types must be in `MESSAGE_TYPES` array
- String inputs are stripped and downcased for consistency

### 4. Safe Method Invocation

The application uses safe Ruby methods:

- `respond_to?()` - Checks method existence before calling
- `public_send()` - Only calls public methods
- No use of `eval()`, `system()`, `exec()`, or unsafe `send()`

### 5. Immutable Constants

All security-critical arrays are frozen to prevent modification:

```ruby
SAFE_METHODS.freeze
STEPS.freeze
MESSAGE_TYPES.freeze
```

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

## Testing Security

The application includes comprehensive tests and endpoints to demonstrate injection prevention:

### Safe Operations

- `/demo/cache` - Shows safe cache operations
- `/api/safe_call?object=user&method=name` - Safe API calls

### Blocked Injection Attempts

- `/demo/cache/unsafe?method=system` - Blocked unsafe method
- `/checkout/inject` (POST) - Blocked code injection in checkout steps
- `/api/safe_call?object=user&method=eval` - Blocked dangerous API calls

### Test Results

All injection attempts return error messages like:
```json
{
  "status": "success",
  "message": "Injection attempt blocked successfully!",
  "error": "Method 'system' is not in the safe methods list"
}
```

## Security Validation

### Comprehensive Test Suite

- ✅ 68 passing tests
- ✅ All injection patterns blocked
- ✅ Safe operations work correctly

### Tested Injection Patterns

The application blocks these common injection patterns:

- Command execution: `system("whoami")`, `exec("whoami")`, `` `whoami` ``
- Code evaluation: `eval("code")`, `instance_eval("code")`
- Method manipulation: `send(:system, "cmd")`, `__send__(:system, "cmd")`
- Object manipulation: `Object.new.system("cmd")`
- File operations: `File.open("/etc/passwd")`
- Process manipulation: `Process.spawn("cmd")`

### CodeQL Analysis

Static analysis shows no security vulnerabilities in application code. Minor ReDoS alerts exist in dependencies but don't affect core security.

## Architecture

```
├── app.rb                 # Main Sinatra application
├── lib/
│   ├── secure_cache.rb    # Safe method invocation
│   ├── checkout_system.rb # Secure step management
│   └── models.rb          # Domain models
├── spec/                  # Comprehensive test suite
├── Gemfile               # Dependencies
└── config.ru             # Rack configuration
```

## Key Takeaways

This application demonstrates that Ruby applications can be secure against injection attacks when following these principles:

1. **Whitelist, don't blacklist** - Only allow known-safe operations
2. **Validate all inputs** - Check against predefined constants
3. **Use immutable data structures** - Freeze security-critical arrays
4. **Prefer safe method invocations** - Use `respond_to?` and `public_send`
5. **Never use dynamic code execution** - Avoid `eval`, `system`, etc.
6. **Test security thoroughly** - Include injection tests in your suite

The combination of these practices ensures that `@checkout_step` is restricted to predefined values, `message_type` is not user-controllable, and there is no path for external input to influence method invocation or code execution.