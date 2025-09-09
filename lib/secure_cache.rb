# SecureCache demonstrates safe method invocation with strict validation
class SecureCache
  # Predefined safe methods that can be called via try_cache
  SAFE_METHODS = %w[
    name
    email
    created_at
    updated_at
    id
    status
    title
    description
  ].freeze

  # Predefined object attributes that are safe to access
  SAFE_ATTRIBUTES = %w[
    user
    order
    product
    category
  ].freeze

  # The secure try_cache method - only allows predefined safe operations
  def self.try_cache(object, method_name, attribute = nil)
    # Validate method name is in our whitelist
    unless SAFE_METHODS.include?(method_name.to_s)
      raise ArgumentError, "Method '#{method_name}' is not in the safe methods list"
    end

    # Validate attribute if provided
    if attribute && !SAFE_ATTRIBUTES.include?(attribute.to_s)
      raise ArgumentError, "Attribute '#{attribute}' is not in the safe attributes list"
    end

    # Use safe method invocation - returns nil if method doesn't exist
    if attribute
      # Access object attribute safely, then call method
      target = object.respond_to?(attribute.to_sym) ? object.send(attribute.to_sym) : nil
      target&.respond_to?(method_name.to_sym) ? target.send(method_name.to_sym) : nil
    else
      # Call method directly on object
      object.respond_to?(method_name.to_sym) ? object.send(method_name.to_sym) : nil
    end
  end

  # Alternative implementation using public_send with validation
  def self.safe_public_send(object, method_name, *args)
    # Validate method name is in our whitelist
    unless SAFE_METHODS.include?(method_name.to_s)
      raise ArgumentError, "Method '#{method_name}' is not in the safe methods list"
    end

    # Only allow public methods, no private/protected methods
    unless object.respond_to?(method_name.to_sym)
      return nil
    end

    # Use public_send for safe method invocation
    object.public_send(method_name.to_sym, *args)
  end
end