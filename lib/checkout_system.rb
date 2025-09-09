# CheckoutSystem demonstrates secure step management with predefined values
class CheckoutSystem
  # Predefined checkout steps - user input cannot modify this array
  STEPS = %w[
    cart
    shipping
    payment
    confirmation
    complete
  ].freeze

  # Valid message types - also predefined and not user-controllable
  MESSAGE_TYPES = %w[
    info
    warning
    error
    success
  ].freeze

  attr_reader :checkout_step, :message_type

  def initialize
    @checkout_step = STEPS.first  # Always starts with first step
    @message_type = MESSAGE_TYPES.first  # Default message type
  end

  # Secure step advancement - only allows predefined steps
  def advance_to_step(step_name)
    step_name = step_name.to_s.strip.downcase
    
    # Validate step exists in our predefined list
    unless STEPS.include?(step_name)
      raise ArgumentError, "Invalid step '#{step_name}'. Valid steps: #{STEPS.join(', ')}"
    end

    # Additional validation - can only advance forward
    current_index = STEPS.index(@checkout_step)
    target_index = STEPS.index(step_name)
    
    if target_index < current_index
      raise ArgumentError, "Cannot go backwards from '#{@checkout_step}' to '#{step_name}'"
    end

    @checkout_step = step_name
  end

  # Secure message type setting - only allows predefined types
  def set_message_type(type)
    type = type.to_s.strip.downcase
    
    # Validate message type exists in our predefined list
    unless MESSAGE_TYPES.include?(type)
      raise ArgumentError, "Invalid message type '#{type}'. Valid types: #{MESSAGE_TYPES.join(', ')}"
    end

    @message_type = type
  end

  # Get current step index (safe method for UI)
  def current_step_index
    STEPS.index(@checkout_step)
  end

  # Check if step is complete (safe method for UI)
  def step_complete?(step_name)
    return false unless STEPS.include?(step_name.to_s)
    
    current_index = STEPS.index(@checkout_step)
    check_index = STEPS.index(step_name.to_s)
    
    check_index <= current_index
  end

  # Get next step (safe method for UI)
  def next_step
    current_index = STEPS.index(@checkout_step)
    return nil if current_index >= STEPS.length - 1
    
    STEPS[current_index + 1]
  end

  # Safe method to get step information for display
  def step_info
    {
      current_step: @checkout_step,
      current_index: current_step_index,
      total_steps: STEPS.length,
      next_step: next_step,
      message_type: @message_type,
      all_steps: STEPS.dup  # Return copy to prevent modification
    }
  end
end