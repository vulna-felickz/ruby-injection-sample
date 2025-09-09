require 'spec_helper'

RSpec.describe CheckoutSystem do
  let(:checkout) { CheckoutSystem.new }

  describe 'initialization' do
    it 'starts with the first step' do
      expect(checkout.checkout_step).to eq('cart')
    end

    it 'starts with default message type' do
      expect(checkout.message_type).to eq('info')
    end
  end

  describe '#advance_to_step' do
    context 'with valid steps' do
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

      it 'handles string input with whitespace' do
        checkout.advance_to_step('  shipping  ')
        expect(checkout.checkout_step).to eq('shipping')
      end

      it 'handles uppercase input' do
        checkout.advance_to_step('SHIPPING')
        expect(checkout.checkout_step).to eq('shipping')
      end
    end

    context 'with invalid steps' do
      it 'rejects steps not in STEPS array' do
        expect {
          checkout.advance_to_step('invalid_step')
        }.to raise_error(ArgumentError, /Invalid step 'invalid_step'/)
      end

      it 'prevents going backwards' do
        checkout.advance_to_step('payment')
        
        expect {
          checkout.advance_to_step('shipping')
        }.to raise_error(ArgumentError, /Cannot go backwards/)
      end

      it 'rejects malicious code injection attempts' do
        malicious_steps = [
          'system("whoami")',
          'eval("puts `whoami`")',
          '`ls -la`',
          '__send__(:system, "whoami")',
          'Object.new.system("whoami")'
        ]

        malicious_steps.each do |malicious_step|
          expect {
            checkout.advance_to_step(malicious_step)
          }.to raise_error(ArgumentError, /Invalid step/)
        end
      end
    end
  end

  describe '#set_message_type' do
    context 'with valid message types' do
      it 'allows setting valid message types' do
        checkout.set_message_type('warning')
        expect(checkout.message_type).to eq('warning')
      end

      it 'handles string input with whitespace' do
        checkout.set_message_type('  error  ')
        expect(checkout.message_type).to eq('error')
      end

      it 'handles uppercase input' do
        checkout.set_message_type('SUCCESS')
        expect(checkout.message_type).to eq('success')
      end
    end

    context 'with invalid message types' do
      it 'rejects message types not in MESSAGE_TYPES array' do
        expect {
          checkout.set_message_type('invalid_type')
        }.to raise_error(ArgumentError, /Invalid message type/)
      end

      it 'prevents code injection through message type' do
        malicious_types = [
          'system("whoami")',
          'eval("puts `whoami`")',
          '`whoami`',
          'Object.new.system("whoami")'
        ]

        malicious_types.each do |malicious_type|
          expect {
            checkout.set_message_type(malicious_type)
          }.to raise_error(ArgumentError, /Invalid message type/)
        end
      end
    end
  end

  describe 'safe query methods' do
    before do
      checkout.advance_to_step('payment')
    end

    describe '#current_step_index' do
      it 'returns correct index' do
        expect(checkout.current_step_index).to eq(2)  # payment is index 2
      end
    end

    describe '#step_complete?' do
      it 'returns true for completed steps' do
        expect(checkout.step_complete?('cart')).to be true
        expect(checkout.step_complete?('shipping')).to be true
        expect(checkout.step_complete?('payment')).to be true
      end

      it 'returns false for future steps' do
        expect(checkout.step_complete?('confirmation')).to be false
        expect(checkout.step_complete?('complete')).to be false
      end

      it 'returns false for invalid steps' do
        expect(checkout.step_complete?('invalid')).to be false
      end
    end

    describe '#next_step' do
      it 'returns next step when available' do
        expect(checkout.next_step).to eq('confirmation')
      end

      it 'returns nil when at final step' do
        checkout.advance_to_step('complete')
        expect(checkout.next_step).to be_nil
      end
    end

    describe '#step_info' do
      it 'returns complete step information' do
        info = checkout.step_info
        
        expect(info[:current_step]).to eq('payment')
        expect(info[:current_index]).to eq(2)
        expect(info[:total_steps]).to eq(5)
        expect(info[:next_step]).to eq('confirmation')
        expect(info[:message_type]).to eq('info')
        expect(info[:all_steps]).to eq(CheckoutSystem::STEPS)
      end

      it 'returns a copy of steps array to prevent modification' do
        info = checkout.step_info
        original_steps = CheckoutSystem::STEPS.dup
        
        # Try to modify the returned array
        info[:all_steps] << 'malicious_step'
        
        # Original should be unchanged
        expect(CheckoutSystem::STEPS).to eq(original_steps)
      end
    end
  end

  describe 'immutable constants' do
    it 'has frozen STEPS array' do
      expect(CheckoutSystem::STEPS).to be_frozen
    end

    it 'has frozen MESSAGE_TYPES array' do
      expect(CheckoutSystem::MESSAGE_TYPES).to be_frozen
    end

    it 'prevents modification of STEPS' do
      expect {
        CheckoutSystem::STEPS << 'malicious_step'
      }.to raise_error(FrozenError)
    end

    it 'prevents modification of MESSAGE_TYPES' do
      expect {
        CheckoutSystem::MESSAGE_TYPES << 'malicious_type'
      }.to raise_error(FrozenError)
    end
  end

  describe 'injection prevention' do
    it 'prevents all common injection patterns in steps' do
      injection_attempts = [
        # Command injection
        'system("whoami")',
        '`whoami`',
        'exec("whoami")',
        
        # Code evaluation
        'eval("puts `whoami`")',
        'instance_eval("system(\'whoami\')")',
        
        # Method manipulation
        '__send__(:system, "whoami")',
        'send(:system, "whoami")',
        'method(:system).call("whoami")',
        
        # Object manipulation
        'Object.new.system("whoami")',
        'Kernel.system("whoami")',
        
        # File operations
        'File.open("/etc/passwd")',
        'IO.popen("whoami")',
        
        # Class manipulation
        'Class.new.system("whoami")',
        'self.class.system("whoami")'
      ]

      injection_attempts.each do |attempt|
        expect {
          checkout.advance_to_step(attempt)
        }.to raise_error(ArgumentError, /Invalid step/), 
          "Failed to block injection attempt: #{attempt}"
      end
    end

    it 'prevents injection in message types' do
      injection_attempts = [
        'system("whoami")',
        'eval("puts `whoami`")',
        '`whoami`',
        '__send__(:system, "whoami")'
      ]

      injection_attempts.each do |attempt|
        expect {
          checkout.set_message_type(attempt)
        }.to raise_error(ArgumentError, /Invalid message type/),
          "Failed to block injection attempt: #{attempt}"
      end
    end
  end
end