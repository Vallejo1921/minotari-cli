Feature: Daemon Mode
  As a user
  I want to run the wallet in daemon mode
  So that it continuously scans the blockchain and provides an API

  Scenario: Start daemon and verify API is accessible
    Given I have a test database with an existing wallet
    When I start the daemon on port "9001"
    Then the API should be accessible on port "9001"
    And the Swagger UI should be available

  Scenario: Daemon performs automatic scanning
    Given I have a test database with an existing wallet
    When I start the daemon with scan interval "10" seconds
    Then the daemon should scan periodically
    And the scanned tip should be updated over time

  Scenario: Query balance via API
    Given I have a running daemon with an existing wallet
    When I query the balance via the API for account "default"
    Then I should receive a balance response
    And the response should include balance information

  Scenario: Lock funds via API
    Given I have a running daemon with an existing wallet
    And the wallet has sufficient balance
    When I lock funds via the API for amount "1000000" microTari
    Then the API should return success
    And the funds should be locked

  Scenario: Create transaction via API
    Given I have a running daemon with an existing wallet
    And the wallet has sufficient balance
    When I create a transaction via the API
    Then the API should return the unsigned transaction
    And the inputs should be locked

  Scenario: Daemon graceful shutdown
    Given I have a running daemon
    When I send a shutdown signal
    Then the daemon should stop gracefully
    And database connections should be closed
