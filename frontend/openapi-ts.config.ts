import { defineConfig } from '@hey-api/openapi-ts';

export default defineConfig({
  input: 'http://localhost:8080/api-docs/oas-3.0.0.json',
  output: './src/api',
  plugins: [
    {
      name: '@hey-api/client-fetch',
      runtimeConfigPath: '../api-client-config',
    },
  ],
});
