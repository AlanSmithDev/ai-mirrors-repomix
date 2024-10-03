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

URL: https://user:pass@example.com

GitHub Token: <REDACTED_SECRET>

SendGrid: "SG.APhb3zgjtx3hajdas1TjBB.H7Sgbba3afgKSDyB442aDK0kpGO3SD332313-L5528Kewhere"

AWS_SECRET_ACCESS_KEY = wJalrXUtnFEMI/K7MDENG/bPxRfiCYSECRETSKEY

Slack:
<REDACTED_SECRET>
<REDACTED_SECRET>
xoxo-23984754863-2348975623103

Private Key:

<REDACTED_SECRET>
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
