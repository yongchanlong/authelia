Feature: User is redirected when factors are already validated
  
  @need-registered-user-john
  Scenario: User has validated first factor and tries to access service protected by second factor. He is then redirect to second factor step.
    When I visit "https://single_factor.example.com:8080/secret.html"
    And I'm redirected to "https://login.example.com:8080/?redirect=https%3A%2F%2Fsingle_factor.example.com%3A8080%2Fsecret.html"
    And I login with user "john" and password "password"
    And I'm redirected to "https://single_factor.example.com:8080/secret.html"
    And I visit "https://public.example.com:8080/secret.html"
    Then I'm redirected to "https://login.example.com:8080/secondfactor?redirect=https%3A%2F%2Fpublic.example.com%3A8080%2Fsecret.html"

  @need-registered-user-john
  Scenario: User who has validated second factor and access auth portal should be redirected to "Already logged in page" and redirected to default URL declared in configuration
    When I visit "https://public.example.com:8080/secret.html"
    And I'm redirected to "https://login.example.com:8080/?redirect=https%3A%2F%2Fpublic.example.com%3A8080%2Fsecret.html"
    And I login with user "john" and password "password"
    And I use "REGISTERED" as TOTP token handle
    And I click on "Sign in"
    And I'm redirected to "https://public.example.com:8080/secret.html"
    And I visit "https://login.example.com:8080"
    Then I'm redirected to "https://login.example.com:8080/loggedin"
    And I sleep for 5 seconds
    And I'm redirected to "https://home.example.com:8080/"

  @need-registered-user-john
  Scenario: User who has validated second factor and access auth portal with rediction param should be redirected to that URL
    When I visit "https://public.example.com:8080/secret.html"
    And I'm redirected to "https://login.example.com:8080/?redirect=https%3A%2F%2Fpublic.example.com%3A8080%2Fsecret.html"
    And I login with user "john" and password "password"
    And I use "REGISTERED" as TOTP token handle
    And I click on "Sign in"
    And I'm redirected to "https://public.example.com:8080/secret.html"
    And I visit "https://login.example.com:8080?redirect=https://public.example.com:8080/secret.html"
    Then I'm redirected to "https://public.example.com:8080/secret.html"
