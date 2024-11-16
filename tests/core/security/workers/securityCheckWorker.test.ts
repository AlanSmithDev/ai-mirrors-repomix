import type { SecretLintCoreConfig } from '@secretlint/types';
import { describe, expect, test } from 'vitest';
import { createSecretLintConfig, runSecretLint } from '../../../../src/core/security/workers/securityCheckWorker.js';

describe('securityCheck', () => {
  const config: SecretLintCoreConfig = createSecretLintConfig();

  test('should detect sensitive information', async () => {
    // Sensitive content with secrets from https://secretlint.github.io/
    // secretlint-disable
    const sensitiveContent = `
# Secretlint Demo

URL: https://user:REDACTED@example.com

GitHub Token: GITHUB_PAT_REDACTED

SendGrid: "SENDGRID_REDACTED"

AWS_SECRET_ACCESS_KEY = AWS_SECRET_REDACTED

Slack:
SLACK_REDACTED
SLACK_REDACTED
SLACK_REDACTED

Private Key:

RSA_PRIVATE_KEY_REDACTED
    `;
    // secretlint-enable

    const secretLintResult = await runSecretLint('test.md', sensitiveContent, 'file', config);
    expect(secretLintResult).not.toBeNull();
  });

  test('should not detect sensitive information in normal content', async () => {
    const normalContent = `
# Normal Content

This is a regular markdown file with no sensitive information.

Here's some code:

\`\`\`javascript
function greet(name) {
  console.log(\`Hello, \${name}!\`);
}
\`\`\`

And here's a list:

1. Item 1
2. Item 2
3. Item 3

That's all!
    `;

    const secretLintResult = await runSecretLint('normal.md', normalContent, 'file', config);
    expect(secretLintResult).toBeNull();
  });
});
