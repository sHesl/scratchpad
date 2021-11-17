package githuboidc

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/pkg/errors"
)

var (
	githubWorkflowEnvVar = os.Getenv("GITHUB_WORKFLOW")
	githubShaEnvVar      = os.Getenv("GITHUB_SHA")

	githubActionTokenRequestTokenEnvVar = os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	githubActionTokenRequestURLEnvVar   = os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
)

type GithubOIDCTokenAssumer struct {
	SessionPrefix string
	RoleARN       string
	Region        string
}

func (o *GithubOIDCTokenAssumer) Retrieve(ctx context.Context) (aws.Credentials, error) {
	workflowName := strings.ToLower(githubWorkflowEnvVar)
	sessionName := strings.Join([]string{o.SessionPrefix, githubShaEnvVar[:7], workflowName}, "_")

	oidcToken, err := oidcAuthToken()
	if err != nil {
		return aws.Credentials{}, errors.Wrap(err, "oidc: unable to retrieve OIDC auth token from github")
	}

	stsClient := sts.New(sts.Options{Region: o.Region})
	input := &sts.AssumeRoleWithWebIdentityInput{
		DurationSeconds:  aws.Int32(900), // Minimum allowed session duration
		RoleArn:          aws.String(o.RoleARN),
		RoleSessionName:  aws.String(sessionName),
		WebIdentityToken: aws.String(oidcToken),
	}

	result, err := stsClient.AssumeRoleWithWebIdentity(context.Background(), input)
	if err != nil {
		return aws.Credentials{}, errors.Wrapf(err, "oidc: unable to assume %s via OIDC.", o.RoleARN)
	}

	return aws.Credentials{
		AccessKeyID:     aws.ToString(result.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(result.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(result.Credentials.SessionToken),
		CanExpire:       true,
		Expires:         aws.ToTime(result.Credentials.Expiration),
	}, nil
}

func oidcAuthToken() (string, error) {
	req, err := http.NewRequest("GET", githubActionTokenRequestURLEnvVar, nil)
	if err != nil {
		return "", err
	}

	req.Header.Add("Authorization", "bearer "+githubActionTokenRequestTokenEnvVar)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var payload struct {
		Value string `json:"value"`
	}

	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&payload); err != nil {
		return "", err
	}

	return payload.Value, nil
}
