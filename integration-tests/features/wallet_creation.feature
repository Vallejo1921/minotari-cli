Feature: Wallet Creation
  As a user
  I want to create a new wallet
  So that I can receive and send Tari

  Scenario: Create a new wallet without encryption
    When I create a new address without a password
    Then the wallet file should be created
    And the wallet should contain a valid address
    And the wallet should contain view and spend keys
    And the wallet should contain seed words

  Scenario: Create a new wallet with password encryption
    When I create a new address with password "MySecurePassword123456789012345678"
    Then the wallet file should be created
    And the wallet should contain encrypted view key
    And the wallet should contain encrypted spend key
    And the wallet should contain encrypted seed words
    And the wallet should contain a nonce

  Scenario: Create wallet with custom output file
    When I create a new address with output file "custom_wallet.json"
    Then the file "custom_wallet.json" should exist
    And the wallet should contain a valid address
