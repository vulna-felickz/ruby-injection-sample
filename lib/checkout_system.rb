# VulnerableCheckout demonstrates unsafe step management - VULNERABLE TO INJECTION!
class VulnerableCheckout
  # Default checkout steps - but user input can override these!
  STEPS = %w[
    cart
    shipping
    payment
    confirmation
    complete
  ].freeze

  # Default message types
  MESSAGE_TYPES = %w[
    info
    warning
    error
    success
  ].freeze

  attr_reader :checkout_step, :message_type

  def initialize
    @checkout_step = STEPS.first  
    @message_type = MESSAGE_TYPES.first
  end

  # Vulnerable step advancement - accepts ANY input including code injection!
  def advance_to_step(step_name)
    # NO VALIDATION - This allows arbitrary code execution!
    # User input is directly assigned - DANGEROUS!
    @checkout_step = step_name.to_s
  end

  # Vulnerable method that evaluates step as Ruby code
  def execute_step_code(code)
    # This evaluates arbitrary Ruby code - MAJOR VULNERABILITY!
    eval(code)
  end

  # Vulnerable message type setting - allows arbitrary input
  def set_message_type(type)
    # NO VALIDATION - accepts any input including malicious code
    @message_type = type.to_s
  end

  # Get current step index - but vulnerable to injection if step contains malicious code
  def current_step_index
    # Vulnerable: if checkout_step contains malicious code, this could execute it
    STEPS.index(@checkout_step) || eval(@checkout_step) rescue 0
  end

  # Check if step is complete - vulnerable method
  def step_complete?(step_name)
    # Vulnerable: directly evaluates user input
    eval("'#{step_name}' == @checkout_step") rescue false
  end

  # Get next step - vulnerable to manipulation
  def next_step
    # Vulnerable: user can manipulate @checkout_step to be anything
    current_index = STEPS.index(@checkout_step) || 0
    return nil if current_index >= STEPS.length - 1
    
    STEPS[current_index + 1]
  end

  # Vulnerable method to get step information for display
  def step_info
    {
      current_step: @checkout_step,
      current_index: current_step_index,
      total_steps: STEPS.length,
      next_step: next_step,
      message_type: @message_type,
      all_steps: STEPS.dup
    }
  end
end

# Keep CheckoutSystem as alias for backward compatibility
CheckoutSystem = VulnerableCheckout