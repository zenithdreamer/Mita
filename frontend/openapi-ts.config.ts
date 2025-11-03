import { defineConfig } from '@hey-api/openapi-ts';

export default defineConfig({
  client: '@hey-api/client-fetch',
  input: 'http://localhost:8080/api-docs/oas-3.0.0.json',
  output: './src/api',
});
