require 'spec_helper'

RSpec.describe VulnerableCheckout do
  let(:checkout) { VulnerableCheckout.new }

  describe 'initialization' do
    it 'starts with the first step' do
      expect(checkout.checkout_step).to eq('cart')
    end

    it 'starts with default message type' do
      expect(checkout.message_type).to eq('info')
    end
  end

  describe '#advance_to_step' do
    context 'with normal steps' do
      it 'allows advancing to next step' do
        checkout.advance_to_step('shipping')
        expect(checkout.checkout_step).to eq('shipping')
      end

      it 'allows advancing multiple steps forward' do
        checkout.advance_to_step('payment')
        expect(checkout.checkout_step).to eq('payment')
      end

      it 'allows advancing to final step' do
        checkout.advance_to_step('complete')
        expect(checkout.checkout_step).to eq('complete')
      end
    end

    context 'vulnerability demonstrations' do
      it 'accepts arbitrary step input' do
        checkout.advance_to_step('malicious_step')
        expect(checkout.checkout_step).to eq('malicious_step')
      end

      it 'allows code as step names' do
        checkout.advance_to_step('system("whoami")')
        expect(checkout.checkout_step).to eq('system("whoami")')
      end

      it 'accepts injection attempts' do
        checkout.advance_to_step('eval("puts 123")')
        expect(checkout.checkout_step).to eq('eval("puts 123")')
      end

    end
  end

  describe '#execute_step_code' do
    it 'executes arbitrary Ruby code' do
      result = checkout.execute_step_code('2 + 2')
      expect(result).to eq(4)
    end

    it 'allows dangerous code execution' do
      result = checkout.execute_step_code('"hello".upcase')
      expect(result).to eq('HELLO')
    end

    it 'demonstrates eval vulnerability' do
      expect {
        checkout.execute_step_code('puts "code executed"')
      }.not_to raise_error
    end
  end

  describe '#set_message_type' do
    it 'accepts any message type input' do
      checkout.set_message_type('custom_type')
      expect(checkout.message_type).to eq('custom_type')
    end

    it 'allows injection in message types' do
      checkout.set_message_type('malicious_payload')
      expect(checkout.message_type).to eq('malicious_payload')
    end

    it 'accepts code as message type' do
      checkout.set_message_type('system("whoami")')
      expect(checkout.message_type).to eq('system("whoami")')
    end
  end

  describe 'vulnerable query methods' do
    before do
      checkout.advance_to_step('payment')
    end

    describe '#current_step_index' do
      it 'returns index for normal steps' do
        expect(checkout.current_step_index).to eq(2)  # payment is index 2
      end

      it 'is vulnerable when step contains malicious code' do
        checkout.advance_to_step('malicious_step')
        # The vulnerable implementation tries to eval the step if not found
        expect(checkout.current_step_index).to eq(0)  # fallback value
      end
    end

    describe '#step_complete?' do
      it 'uses dangerous eval for comparison' do
        # This method is vulnerable because it uses eval
        expect(checkout.step_complete?('payment')).to be true
      end

      it 'demonstrates eval vulnerability' do
        # The vulnerable implementation uses eval for comparisons
        expect {
          checkout.step_complete?('anything')
        }.not_to raise_error
      end
    end

    describe '#step_info' do
      it 'returns step information including vulnerable data' do
        info = checkout.step_info
        
        expect(info[:current_step]).to eq('payment')
        expect(info[:current_index]).to eq(2)
        expect(info[:total_steps]).to eq(5)
        expect(info[:next_step]).to eq('confirmation')
        expect(info[:message_type]).to eq('info')
        expect(info[:all_steps]).to eq(VulnerableCheckout::STEPS)
      end
    end
  end

  describe 'vulnerability demonstrations' do
    it 'allows all injection patterns in steps' do
      injection_attempts = [
        'system("echo test")',
        'eval("1+1")',
        'Object.new.to_s',
        'Class.new.name'
      ]

      injection_attempts.each do |attempt|
        expect {
          checkout.advance_to_step(attempt)
        }.not_to raise_error
        expect(checkout.checkout_step).to eq(attempt)
      end
    end

    it 'allows code execution through execute_step_code' do
      code_examples = [
        '1 + 1',
        '"hello".length',
        'Time.now.to_s',
        'Math.sqrt(16)'
      ]

      code_examples.each do |code|
        expect {
          checkout.execute_step_code(code)
        }.not_to raise_error
      end
    end

    it 'demonstrates message type injection' do
      malicious_types = [
        'system("echo test")',
        'eval("puts 123")',
        'File.exist?("/etc/passwd")',
        'ENV["USER"]'
      ]

      malicious_types.each do |type|
        expect {
          checkout.set_message_type(type)
        }.not_to raise_error
        expect(checkout.message_type).to eq(type)
      end
    end
  end
end