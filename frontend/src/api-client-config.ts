// Runtime configuration for the generated API client
// This file is referenced in openapi-ts.config.ts via runtimeConfigPath

import type { Config, ClientOptions } from './api/client/types.gen';

export const createClientConfig = (config?: Config<ClientOptions>): Config<ClientOptions> => ({
  ...config,
  baseUrl: config?.baseUrl ?? 'http://localhost:8080',
  credentials: 'include' as RequestCredentials,
});
