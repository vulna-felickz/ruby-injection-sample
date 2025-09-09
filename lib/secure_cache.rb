# VulnerableCache demonstrates unsafe method invocation - VULNERABLE TO INJECTION!
class VulnerableCache
  # The vulnerable try_cache method - allows ANY method to be called!
  def self.try_cache(object, method_name, attribute = nil)
    # NO VALIDATION - This allows arbitrary method calls!
    # This is vulnerable to method injection attacks
    
    if attribute
      # Access object attribute, then call method - DANGEROUS!
      target = object.send(attribute.to_sym)
      target.send(method_name.to_sym) if target
    else
      # Call method directly on object - DANGEROUS!
      object.send(method_name.to_sym)
    end
  end

  # Vulnerable alternative that evaluates user input - EXTREMELY DANGEROUS!
  def self.dynamic_call(object, code_string)
    # This evaluates arbitrary Ruby code - MAJOR VULNERABILITY!
    eval("object.#{code_string}")
  end

  # Vulnerable method that executes system commands based on user input
  def self.execute_command(command)
    # Directly execute system commands - COMMAND INJECTION VULNERABILITY!
    system(command)
  end
end

# Keep SecureCache as alias for backward compatibility with existing code
SecureCache = VulnerableCache