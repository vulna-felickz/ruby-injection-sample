require 'spec_helper'

RSpec.describe VulnerableCache do
  let(:user) { User.new(1, 'John Doe', 'john@example.com') }
  let(:product) { Product.new(1, 'Ruby Book', 'Learn Ruby Programming') }
  let(:order) { Order.new(1, user, product) }

  describe '.try_cache' do
    context 'with regular methods' do
      it 'allows calling any method' do
        result = VulnerableCache.try_cache(user, 'name')
        expect(result).to eq('John Doe')
      end

      it 'allows calling methods on object attributes' do
        result = VulnerableCache.try_cache(order, 'name', 'user')
        expect(result).to eq('John Doe')
      end

      it 'allows calling class method' do
        result = VulnerableCache.try_cache(user, 'class')
        expect(result).to eq(User)
      end
    end

    context 'vulnerability demonstrations' do
      it 'allows dangerous method calls - class introspection' do
        result = VulnerableCache.try_cache(user, 'class')
        expect(result).to eq(User)
      end

      it 'allows object inspection' do
        result = VulnerableCache.try_cache(user, 'inspect')
        expect(result).to be_a(String)
        expect(result).to include('User')
      end

      it 'allows method enumeration' do
        result = VulnerableCache.try_cache(user, 'methods')
        expect(result).to be_an(Array)
        expect(result).to include(:name, :email)
      end

    end
  end

  describe '.dynamic_call' do
    it 'executes arbitrary Ruby code' do
      result = VulnerableCache.dynamic_call(user, 'name')
      expect(result).to eq('John Doe')
    end

    it 'allows code evaluation vulnerability' do
      result = VulnerableCache.dynamic_call(user, 'class.name')
      expect(result).to eq('User')
    end

    it 'demonstrates eval vulnerability' do
      result = VulnerableCache.dynamic_call(user, 'id * 2')
      expect(result).to eq(2)
    end
  end

  describe '.execute_command' do
    it 'executes system commands' do
      result = VulnerableCache.execute_command('echo test')
      expect(result).to be true
    end

    it 'allows command injection' do
      result = VulnerableCache.execute_command('whoami')
      expect(result).to be true
    end
  end

  describe 'vulnerability demonstrations' do
    it 'demonstrates method injection through try_cache' do
      dangerous_methods = [
        'class',
        'methods',
        'inspect',
        'to_s'
      ]

      dangerous_methods.each do |method|
        result = VulnerableCache.try_cache(user, method)
        expect(result).not_to be_nil
      end
    end

    it 'demonstrates code execution through dynamic_call' do
      code_examples = [
        'name.upcase',
        'id + 10', 
        'class.ancestors.first.name'
      ]

      code_examples.each do |code|
        expect {
          VulnerableCache.dynamic_call(user, code)
        }.not_to raise_error
      end
    end
  end
end