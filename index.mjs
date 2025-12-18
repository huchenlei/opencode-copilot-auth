/**
 * @type {import('@opencode-ai/plugin').Plugin}
 */
export async function CopilotAuthPlugin({ client }) {
  const CLIENT_ID = "Iv1.b507a08c87ecfe98";
  const HEADERS = {
    "User-Agent": "GitHubCopilotChat/0.32.4",
    "Editor-Version": "vscode/1.105.1",
    "Editor-Plugin-Version": "copilot-chat/0.32.4",
    "Copilot-Integration-Id": "vscode-chat",
  };
  const RESPONSES_API_ALTERNATE_INPUT_TYPES = [
    "file_search_call",
    "computer_call",
    "computer_call_output",
    "web_search_call",
    "function_call",
    "function_call_output",
    "image_generation_call",
    "code_interpreter_call",
    "local_shell_call",
    "local_shell_call_output",
    "mcp_list_tools",
    "mcp_approval_request",
    "mcp_approval_response",
    "mcp_call",
    "reasoning",
  ];

  // File logger to avoid breaking TUI
  async function logToFile(message) {
    try {
      const { appendFile } = await import("node:fs/promises");
      const { homedir } = await import("node:os");
      const { join } = await import("node:path");

      const logPath = join(homedir(), ".copilot-auth.log");
      const timestamp = new Date().toISOString();
      await appendFile(logPath, `[${timestamp}] ${message}\n`);
    } catch {
      // Silently fail if logging fails
    }
  }

  function normalizeDomain(url) {
    return url.replace(/^https?:\/\//, "").replace(/\/$/, "");
  }

  function getUrls(domain) {
    return {
      DEVICE_CODE_URL: `https://${domain}/login/device/code`,
      ACCESS_TOKEN_URL: `https://${domain}/login/oauth/access_token`,
      COPILOT_API_KEY_URL: `https://api.${domain}/copilot_internal/v2/token`,
      AUTHORIZE_URL: `https://${domain}/login/oauth/authorize`,
      TOKEN_EXCHANGE_URL: `https://${domain}/login/oauth/access_token`,
    };
  }

  // PKCE utility functions for OAuth flow
  function generateRandomString(length) {
    const array = new Uint8Array(length);
    globalThis.crypto.getRandomValues(array);
    return Array.from(array, (b) => b.toString(16).padStart(2, "0"))
      .join("")
      .substring(0, length);
  }

  function base64UrlEncode(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }

  async function generateCodeChallenge(codeVerifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(codeVerifier);
    const digest = await globalThis.crypto.subtle.digest("SHA-256", data);
    return base64UrlEncode(digest);
  }

  // Poll for access token with timeout and cancellation support
  async function pollForToken(
    urls,
    deviceCode,
    interval,
    timeout,
    signal,
    onProgress,
  ) {
    const startTime = Date.now();
    const AUTH_TIMEOUT = timeout || 5 * 60 * 1000; // 5 minutes default

    while (true) {
      // Check cancellation
      if (signal?.aborted) {
        throw {
          code: "USER_CANCELLED",
          message: "Authentication cancelled by user",
          canFallback: false,
        };
      }

      // Check timeout
      if (Date.now() - startTime > AUTH_TIMEOUT) {
        throw {
          code: "TIMEOUT",
          message: "Authentication timed out after 5 minutes",
          canFallback: false,
        };
      }

      const response = await fetch(urls.ACCESS_TOKEN_URL, {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          "User-Agent": "GitHubCopilotChat/0.35.0",
        },
        body: JSON.stringify({
          client_id: CLIENT_ID,
          device_code: deviceCode,
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        }),
      });

      if (!response.ok) {
        throw {
          code: "TOKEN_REQUEST_FAILED",
          message: `Token request failed: ${response.status}`,
          canFallback: true,
        };
      }

      const data = await response.json();

      if (data.access_token) {
        onProgress?.("Authentication successful!");
        return data.access_token;
      }

      if (data.error === "authorization_pending") {
        onProgress?.("Waiting for authorization...");
        await new Promise((resolve) => setTimeout(resolve, interval * 1000));
        continue;
      }

      if (data.error) {
        throw {
          code: "AUTH_ERROR",
          message: data.error_description || data.error,
          canFallback: data.error === "access_denied" ? false : true,
        };
      }

      await new Promise((resolve) => setTimeout(resolve, interval * 1000));
    }
  }

  // Device Code Flow (enhanced with error handling)
  async function tryDeviceCodeFlow(domain, urls, onProgress) {
    try {
      onProgress?.("Initiating device code authentication...");

      const deviceResponse = await fetch(urls.DEVICE_CODE_URL, {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          "User-Agent": "GitHubCopilotChat/0.35.0",
        },
        body: JSON.stringify({
          client_id: CLIENT_ID,
          scope: "read:user",
        }),
      });

      // Enhanced error handling
      if (!deviceResponse.ok) {
        if (deviceResponse.status === 404) {
          throw {
            code: "ENDPOINT_NOT_FOUND",
            message:
              "Device code authentication is not available on this GitHub instance. " +
              "This may occur if:\n" +
              "• GitHub Enterprise Server version is older than 3.1\n" +
              "• Device flow is disabled by your administrator\n\n" +
              "Trying alternative authentication method...",
            canFallback: true,
          };
        }
        throw {
          code: "DEVICE_CODE_FAILED",
          message: `Device code request failed: ${deviceResponse.status} ${deviceResponse.statusText}`,
          canFallback: true,
        };
      }

      const deviceData = await deviceResponse.json();

      return {
        url: deviceData.verification_uri,
        instructions: `Enter code: ${deviceData.user_code}`,
        method: "auto",
        callback: async (signal) => {
          const accessToken = await pollForToken(
            urls,
            deviceData.device_code,
            deviceData.interval,
            5 * 60 * 1000,
            signal,
            onProgress,
          );
          return {
            type: "success",
            refresh: accessToken,
            access: "",
            expires: 0,
          };
        },
      };
    } catch (error) {
      // Re-throw with flow context
      throw {
        flow: "device_code",
        ...error,
      };
    }
  }

  // Create local loopback server for OAuth callback
  async function createLoopbackServer() {
    const http = await import("node:http");

    let resolveCallback;
    const callbackPromise = new Promise((resolve) => {
      resolveCallback = resolve;
    });

    const server = http.createServer((req, res) => {
      const url = new URL(req.url, `http://${req.headers.host}`);

      if (url.pathname === "/callback") {
        const code = url.searchParams.get("code");
        const state = url.searchParams.get("state");
        const error = url.searchParams.get("error");
        const errorDescription = url.searchParams.get("error_description");

        // Send response to browser
        res.writeHead(200, { "Content-Type": "text/html" });
        if (error) {
          res.end(`
            <html>
              <head><title>Authentication Failed</title></head>
              <body style="font-family: system-ui; max-width: 600px; margin: 100px auto; text-align: center;">
                <h1>❌ Authentication Failed</h1>
                <p style="color: #666;">${errorDescription || error}</p>
                <p>You can close this window and return to your application.</p>
              </body>
            </html>
          `);
        } else {
          res.end(`
            <html>
              <head><title>Authentication Successful</title></head>
              <body style="font-family: system-ui; max-width: 600px; margin: 100px auto; text-align: center;">
                <h1>✓ Authentication Successful!</h1>
                <p style="color: #666;">You can close this window and return to your application.</p>
              </body>
            </html>
          `);
        }

        // Resolve with callback data
        resolveCallback({
          code,
          state,
          error,
          error_description: errorDescription,
        });
      } else {
        res.writeHead(404);
        res.end("Not Found");
      }
    });

    // Find available port
    return new Promise((resolve, reject) => {
      server.listen(0, "127.0.0.1", (err) => {
        if (err) reject(err);
        const port = server.address().port;
        resolve({
          server,
          port,
          callbackPromise,
        });
      });
    });
  }

  // OAuth Authorization Code Flow with PKCE
  async function tryOAuthPKCEFlow(domain, urls, onProgress) {
    try {
      onProgress?.("Initiating OAuth authorization flow...");

      // Generate PKCE parameters
      const codeVerifier = generateRandomString(64);
      const codeChallenge = await generateCodeChallenge(codeVerifier);
      const state = generateRandomString(32);

      // Create local loopback server
      const { server, port, callbackPromise } = await createLoopbackServer();
      const redirectUri = `http://127.0.0.1:${port}/callback`;

      // Construct authorization URL
      const authUrl = new URL(urls.AUTHORIZE_URL);
      authUrl.searchParams.set("client_id", CLIENT_ID);
      authUrl.searchParams.set("redirect_uri", redirectUri);
      authUrl.searchParams.set("scope", "read:user");
      authUrl.searchParams.set("state", state);
      authUrl.searchParams.set("code_challenge", codeChallenge);
      authUrl.searchParams.set("code_challenge_method", "S256");

      return {
        url: authUrl.toString(),
        instructions: "Complete authorization in your browser",
        method: "auto",
        callback: async (signal) => {
          try {
            // Race between callback, timeout, and cancellation
            const result = await Promise.race([
              callbackPromise,
              new Promise((_, reject) =>
                setTimeout(
                  () =>
                    reject({
                      code: "TIMEOUT",
                      message: "OAuth flow timed out after 5 minutes",
                      canFallback: true,
                    }),
                  5 * 60 * 1000,
                ),
              ),
              new Promise((_, reject) => {
                if (signal) {
                  signal.addEventListener("abort", () =>
                    reject({
                      code: "USER_CANCELLED",
                      message: "Authentication cancelled by user",
                      canFallback: false,
                    }),
                  );
                }
              }),
            ]);

            // Validate state
            if (result.state !== state) {
              throw {
                code: "STATE_MISMATCH",
                message: "OAuth state validation failed (possible CSRF attack)",
                canFallback: false,
              };
            }

            if (result.error) {
              throw {
                code: "AUTH_ERROR",
                message: result.error_description || result.error,
                canFallback: result.error === "access_denied" ? false : true,
              };
            }

            // Exchange code for token
            onProgress?.("Exchanging authorization code for token...");

            const tokenResponse = await fetch(urls.TOKEN_EXCHANGE_URL, {
              method: "POST",
              headers: {
                Accept: "application/json",
                "Content-Type": "application/json",
              },
              body: JSON.stringify({
                client_id: CLIENT_ID,
                code: result.code,
                code_verifier: codeVerifier,
                redirect_uri: redirectUri,
                grant_type: "authorization_code",
              }),
            });

            if (!tokenResponse.ok) {
              const errorText = await tokenResponse.text();
              throw {
                code: "TOKEN_EXCHANGE_FAILED",
                message: `Token exchange failed: ${tokenResponse.status} - ${errorText}`,
                canFallback: true,
              };
            }

            const tokenData = await tokenResponse.json();

            if (!tokenData.access_token) {
              throw {
                code: "NO_ACCESS_TOKEN",
                message: "No access token received from GitHub",
                canFallback: true,
              };
            }

            onProgress?.("Authentication successful!");

            return {
              type: "success",
              refresh: tokenData.access_token,
              access: "",
              expires: 0,
            };
          } finally {
            // Cleanup server after delay
            setTimeout(() => server.close(), 5000);
          }
        },
      };
    } catch (error) {
      throw {
        flow: "oauth_pkce",
        ...error,
      };
    }
  }

  return {
    auth: {
      provider: "github-copilot",
      loader: async (getAuth, provider) => {
        let info = await getAuth();
        if (!info || info.type !== "oauth") return {};

        if (provider && provider.models) {
          for (const model of Object.values(provider.models)) {
            model.cost = {
              input: 0,
              output: 0,
              cache: {
                read: 0,
                write: 0,
              },
            };
          }
        }

        // Set baseURL based on deployment type
        const enterpriseUrl = info.enterpriseUrl;
        const baseURL = enterpriseUrl
          ? `https://copilot-api.${normalizeDomain(enterpriseUrl)}`
          : "https://api.githubcopilot.com";

        return {
          baseURL,
          apiKey: "",
          async fetch(input, init) {
            const info = await getAuth();
            if (info.type !== "oauth") return {};
            if (!info.access || info.expires < Date.now()) {
              const domain = info.enterpriseUrl
                ? normalizeDomain(info.enterpriseUrl)
                : "github.com";
              const urls = getUrls(domain);

              const response = await fetch(urls.COPILOT_API_KEY_URL, {
                headers: {
                  Accept: "application/json",
                  Authorization: `Bearer ${info.refresh}`,
                  ...HEADERS,
                },
              });

              if (!response.ok) {
                throw new Error(`Token refresh failed: ${response.status}`);
              }

              const tokenData = await response.json();

              const saveProviderID = info.enterpriseUrl
                ? "github-copilot-enterprise"
                : "github-copilot";
              await client.auth.set({
                path: {
                  id: saveProviderID,
                },
                body: {
                  type: "oauth",
                  refresh: info.refresh,
                  access: tokenData.token,
                  expires: tokenData.expires_at * 1000,
                  ...(info.enterpriseUrl && {
                    enterpriseUrl: info.enterpriseUrl,
                  }),
                },
              });
              info.access = tokenData.token;
            }
            let isAgentCall = false;
            let isVisionRequest = false;
            try {
              const body =
                typeof init.body === "string"
                  ? JSON.parse(init.body)
                  : init.body;
              if (body?.messages) {
                isAgentCall = body.messages.some(
                  (msg) => msg.role && ["tool", "assistant"].includes(msg.role),
                );
                isVisionRequest = body.messages.some(
                  (msg) =>
                    Array.isArray(msg.content) &&
                    msg.content.some((part) => part.type === "image_url"),
                );
              }

              if (body?.input) {
                const lastInput = body.input[body.input.length - 1];

                const isAssistant = lastInput?.role === "assistant";
                const hasAgentType = lastInput?.type
                  ? RESPONSES_API_ALTERNATE_INPUT_TYPES.includes(lastInput.type)
                  : false;
                isAgentCall = isAssistant || hasAgentType;

                isVisionRequest =
                  Array.isArray(lastInput?.content) &&
                  lastInput.content.some((part) => part.type === "input_image");
              }
            } catch {}
            const headers = {
              ...init.headers,
              ...HEADERS,
              Authorization: `Bearer ${info.access}`,
              "Openai-Intent": "conversation-edits",
              "X-Initiator": isAgentCall ? "agent" : "user",
            };
            if (isVisionRequest) {
              headers["Copilot-Vision-Request"] = "true";
            }

            delete headers["x-api-key"];
            delete headers["authorization"];

            return fetch(input, {
              ...init,
              headers,
            });
          },
        };
      },
      methods: [
        {
          type: "oauth",
          label: "Login with GitHub Copilot",
          prompts: [
            {
              type: "select",
              key: "deploymentType",
              message: "Select GitHub deployment type",
              options: [
                {
                  label: "GitHub.com",
                  value: "github.com",
                  hint: "Public",
                },
                {
                  label: "GitHub Enterprise",
                  value: "enterprise",
                  hint: "Data residency or self-hosted",
                },
              ],
            },
            {
              type: "text",
              key: "enterpriseUrl",
              message: "Enter your GitHub Enterprise URL or domain",
              placeholder: "company.ghe.com or https://company.ghe.com",
              condition: (inputs) => inputs.deploymentType === "enterprise",
              validate: (value) => {
                if (!value) return "URL or domain is required";
                try {
                  const url = value.includes("://")
                    ? new URL(value)
                    : new URL(`https://${value}`);
                  if (!url.hostname)
                    return "Please enter a valid URL or domain";
                  return undefined;
                } catch {
                  return "Please enter a valid URL (e.g., company.ghe.com or https://company.ghe.com)";
                }
              },
            },
          ],
          async authorize(inputs = {}) {
            const deploymentType = inputs.deploymentType || "github.com";

            let domain = "github.com";
            let actualProvider = "github-copilot";

            if (deploymentType === "enterprise") {
              const enterpriseUrl = inputs.enterpriseUrl;
              domain = normalizeDomain(enterpriseUrl);
              actualProvider = "github-copilot-enterprise";
            }

            const urls = getUrls(domain);
            const errors = [];

            // Define flow order
            const flows = [
              { name: "Device Code", fn: tryDeviceCodeFlow },
              { name: "OAuth with PKCE", fn: tryOAuthPKCEFlow },
            ];

            // Progress callback for logging
            const onProgress = (msg) => {
              logToFile(`[Auth] ${msg}`);
            };

            // Try each flow in order
            for (const flow of flows) {
              try {
                const result = await flow.fn(domain, urls, onProgress);

                // Wrap callback to add provider info
                const originalCallback = result.callback;
                result.callback = async (signal) => {
                  const authResult = await originalCallback(signal);

                  if (authResult.type === "success") {
                    // Add provider info for enterprise
                    if (actualProvider === "github-copilot-enterprise") {
                      authResult.provider = "github-copilot-enterprise";
                      authResult.enterpriseUrl = domain;
                    }
                  }

                  return authResult;
                };

                return result;
              } catch (error) {
                errors.push({
                  flow: flow.name,
                  error: error.message || error.code || "Unknown error",
                });

                // Check if we should fallback
                if (error.canFallback === false) {
                  // Don't try more flows for certain errors
                  throw new Error(
                    `Authentication failed (${flow.name}): ${error.message}\n\n` +
                      "Please check your credentials and try again.",
                  );
                }

                // Log fallback attempt
                logToFile(
                  `[Auth] ${flow.name} failed: ${error.message}. Trying next method...`,
                );
                continue;
              }
            }

            // All flows failed
            throw new Error(
              "All authentication methods failed:\n\n" +
                errors.map((e) => `• ${e.flow}: ${e.error}`).join("\n") +
                "\n\nPlease check:\n" +
                "1. Your network connection\n" +
                "2. GitHub instance availability\n" +
                "3. Your GitHub Copilot subscription status",
            );
          },
        },
      ],
    },
  };
}
