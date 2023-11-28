package main

import (
	"context"
	"errors"
	"flag"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

var (
	logger log.Logger
)

// Help function to generate an IAM policy
func generatePolicy(principalId, effect, resource string) events.APIGatewayCustomAuthorizerResponse {
	authResponse := events.APIGatewayCustomAuthorizerResponse{PrincipalID: principalId}

	if effect != "" && resource != "" {
		authResponse.PolicyDocument = events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Action:   []string{"execute-api:Invoke"},
					Effect:   effect,
					Resource: []string{resource},
				},
			},
		}
	}

	// Optional output with custom properties of the String, Number or Boolean type.
	authResponse.Context = map[string]interface{}{
		"stringKey":  "stringval",
		"numberKey":  123,
		"booleanKey": true,
	}
	return authResponse
}

func handleRequest(ctx context.Context, event events.APIGatewayCustomAuthorizerRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	token := event.AuthorizationToken
	switch strings.ToLower(token) {
	case "allow":
		//TODO need to allow other methods as well, as the returned policy will get cached and used for future calls to other methods
		// In future I think we can use the RBAC roles in Auth0 to hold a list of methodArn's each role (admin, reg-user) can access
		//return generatePolicy("user", "Allow", event.MethodArn), nil
		return generatePolicy("user", "Allow", "*"), nil
	case "deny":
		//return generatePolicy("user", "Deny", event.MethodArn), nil
		return generatePolicy("user", "Deny", "*"), nil
	case "unauthorized":
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized") // Return a 401 Unauthorized response
	default:
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Error: Invalid token")
	}
}

func main() {
	logger = log.NewLogfmtLogger(os.Stderr)
	logger = log.NewSyncLogger(logger)
	logger = log.With(logger,
		"service", "bathrc-accounts-backend",
		"time:", log.DefaultTimestampUTC,
		"caller", log.DefaultCaller,
	)

	_ = level.Info(logger).Log("msg", "service started")
	defer func() { _ = level.Info(logger).Log("msg", "service finished") }()

	flag.Parse()

	logLevel, exists := os.LookupEnv("LOG_LEVEL")
	if !exists {
		logLevel = "debug"
	}

	switch logLevel {
	case "debug":
		logger = level.NewFilter(logger, level.AllowDebug())
	case "info":
		logger = level.NewFilter(logger, level.AllowInfo())
	case "warn":
		logger = level.NewFilter(logger, level.AllowWarn())
	case "error":
		logger = level.NewFilter(logger, level.AllowError())
	default:
		logger = level.NewFilter(logger, level.AllowAll())
		_ = level.Error(logger).Log("msg", "bad logging level, defaulting to all")
	}

	lambda.Start(handleRequest)
}
