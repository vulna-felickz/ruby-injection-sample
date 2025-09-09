# Simple models for demonstration purposes
class User
  attr_reader :id, :name, :email, :created_at, :updated_at, :status

  def initialize(id, name, email)
    @id = id
    @name = name
    @email = email
    @created_at = Time.now
    @updated_at = Time.now
    @status = 'active'
  end
end

class Product
  attr_reader :id, :title, :description, :created_at, :updated_at

  def initialize(id, title, description)
    @id = id
    @title = title
    @description = description
    @created_at = Time.now
    @updated_at = Time.now
  end
end

class Order
  attr_reader :id, :user, :product, :status, :created_at, :updated_at

  def initialize(id, user, product)
    @id = id
    @user = user
    @product = product
    @status = 'pending'
    @created_at = Time.now
    @updated_at = Time.now
  end

  # Safe method for getting user name through association
  def user_name
    user&.name
  end

  # Safe method for getting product title through association
  def product_title
    product&.title
  end
end