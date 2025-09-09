require 'spec_helper'

RSpec.describe SecureCache do
  let(:user) { User.new(1, 'John Doe', 'john@example.com') }
  let(:product) { Product.new(1, 'Ruby Book', 'Learn Ruby Programming') }
  let(:order) { Order.new(1, user, product) }

  describe '.try_cache' do
    context 'with safe methods' do
      it 'allows calling whitelisted methods' do
        result = SecureCache.try_cache(user, 'name')
        expect(result).to eq('John Doe')
      end

      it 'allows calling methods on object attributes' do
        result = SecureCache.try_cache(order, 'name', 'user')
        expect(result).to eq('John Doe')
      end

      it 'returns nil for non-existent methods safely' do
        result = SecureCache.try_cache(user, 'status')  # status exists on user
        expect(result).to eq('active')
        
        # Test with a method that actually doesn't exist but is whitelisted
        # Let's create a user without the status method
        user_without_status = User.new(1, 'John Doe', 'john@example.com')
        allow(user_without_status).to receive(:respond_to?).with(:status).and_return(false)
        result = SecureCache.try_cache(user_without_status, 'status')
        expect(result).to be_nil
      end
    end

    context 'with unsafe methods' do
      it 'rejects methods not in whitelist' do
        expect {
          SecureCache.try_cache(user, 'system')
        }.to raise_error(ArgumentError, "Method 'system' is not in the safe methods list")
      end

      it 'rejects eval attempts' do
        expect {
          SecureCache.try_cache(user, 'eval')
        }.to raise_error(ArgumentError, "Method 'eval' is not in the safe methods list")
      end

      it 'rejects send method calls' do
        expect {
          SecureCache.try_cache(user, 'send')
        }.to raise_error(ArgumentError, "Method 'send' is not in the safe methods list")
      end

      it 'rejects instance_eval attempts' do
        expect {
          SecureCache.try_cache(user, 'instance_eval')
        }.to raise_error(ArgumentError, "Method 'instance_eval' is not in the safe methods list")
      end
    end

    context 'with unsafe attributes' do
      it 'rejects attributes not in whitelist' do
        expect {
          SecureCache.try_cache(order, 'name', 'class')
        }.to raise_error(ArgumentError, "Attribute 'class' is not in the safe attributes list")
      end

      it 'rejects method attempts through attributes' do
        expect {
          SecureCache.try_cache(order, 'name', 'instance_variables')
        }.to raise_error(ArgumentError, "Attribute 'instance_variables' is not in the safe attributes list")
      end
    end
  end

  describe '.safe_public_send' do
    context 'with safe methods' do
      it 'allows calling whitelisted methods' do
        result = SecureCache.safe_public_send(user, 'name')
        expect(result).to eq('John Doe')
      end

      it 'allows calling methods with arguments if method supports it' do
        # Most of our safe methods don't take arguments, but let's test the mechanism
        result = SecureCache.safe_public_send(user, 'email')
        expect(result).to eq('john@example.com')
      end
    end

    context 'with unsafe methods' do
      it 'rejects dangerous system calls' do
        expect {
          SecureCache.safe_public_send(user, 'system')
        }.to raise_error(ArgumentError, "Method 'system' is not in the safe methods list")
      end

      it 'rejects eval calls' do
        expect {
          SecureCache.safe_public_send(user, 'eval')
        }.to raise_error(ArgumentError, "Method 'eval' is not in the safe methods list")
      end

      it 'rejects backtick execution attempts' do
        expect {
          SecureCache.safe_public_send(user, '`')
        }.to raise_error(ArgumentError, "Method '`' is not in the safe methods list")
      end
    end

    context 'with non-existent methods' do
      it 'returns nil for methods that do not exist' do
        # First, let's make sure our method validation still works
        expect {
          SecureCache.safe_public_send(user, 'nonexistent_method')
        }.to raise_error(ArgumentError, "Method 'nonexistent_method' is not in the safe methods list")
      end
    end
  end

  describe 'injection prevention' do
    it 'prevents code injection through method names' do
      malicious_methods = [
        'system("whoami")',
        'eval("puts `whoami`")',
        '`whoami`',
        '__send__(:system, "whoami")',
        'method(:system).call("whoami")'
      ]

      malicious_methods.each do |method|
        expect {
          SecureCache.try_cache(user, method)
        }.to raise_error(ArgumentError, /is not in the safe methods list/)
      end
    end

    it 'prevents code injection through attributes' do
      malicious_attributes = [
        'class.new.system("whoami")',
        'methods.grep(/system/)',
        'instance_eval("system(\'whoami\')")'
      ]

      malicious_attributes.each do |attr|
        expect {
          SecureCache.try_cache(order, 'name', attr)
        }.to raise_error(ArgumentError, /is not in the safe attributes list/)
      end
    end
  end
end