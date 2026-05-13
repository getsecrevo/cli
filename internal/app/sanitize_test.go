package app

import "testing"

func TestSanitizeEnvName(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want string
	}{
		{"OPENAI_API_KEY", "OPENAI_API_KEY"},
		{"aws.cloudwatch.webhooks.primary.url", "AWS_CLOUDWATCH_WEBHOOKS_PRIMARY_URL"},
		{"prysmid/oidc_apps/platform.client_id", "PRYSMID_OIDC_APPS_PLATFORM_CLIENT_ID"},
		{"foo..bar", "FOO_BAR"},
		{"1password-token", "_1PASSWORD_TOKEN"},
		{"_already_clean", "_ALREADY_CLEAN"},
		{"snake_case", "SNAKE_CASE"},
		{"", ""},
	}
	for _, c := range cases {
		c := c
		t.Run(c.in, func(t *testing.T) {
			got := sanitizeEnvName(c.in)
			if got != c.want {
				t.Fatalf("sanitizeEnvName(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
