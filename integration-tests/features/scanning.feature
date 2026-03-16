Feature: Blockchain Scanning
  As a user
  I want to scan the blockchain
  So that I can detect incoming transactions

  Scenario: Scan blockchain with mined blocks
    Given I have a seed node MinerNode
    And I have a test database with an existing wallet
    When I mine 10 blocks on MinerNode
    And I perform a scan with max blocks "20"
    Then the scan should complete successfully
    And the scanned tip should be updated

  Scenario: Incremental scan from last scanned height
    Given I have a seed node MinerNode
    And I have a test database with an existing wallet
    When I mine 5 blocks on MinerNode
    And I perform a scan with max blocks "10"
    And I mine 3 blocks on MinerNode
    And I perform an incremental scan
    Then the scan should start from the last scanned height
    And new blocks should be processed

  Scenario: Re-scan from specific height
    Given I have a seed node MinerNode
    And I have a test database with an existing wallet
    When I mine 10 blocks on MinerNode
    And I perform a scan with max blocks "20"
    And I re-scan from height "5"
    Then the wallet state should be rolled back to height "5"
    And scanning should resume from height "5"

  Scenario: Scan with custom batch size
    Given I have a seed node MinerNode
    And I have a test database with an existing wallet
    When I mine 10 blocks on MinerNode
    And I perform a scan with batch size "5"
    Then blocks should be fetched in batches of "5"
    And the scan should complete successfully

  Scenario: Fast sync with small safety buffer
    Given I have a seed node MinerNode
    And I have a test database with an existing wallet
    When I mine 10 blocks on MinerNode
    And I perform a fast sync with safety buffer "5"
    Then the fast sync should complete successfully

  Scenario: Fast sync completes successfully
    Given I have a seed node MinerNode
    And I have a test database with an existing wallet
    When I mine 10 blocks on MinerNode
    And I perform a fast sync
    Then the fast sync should complete successfully
