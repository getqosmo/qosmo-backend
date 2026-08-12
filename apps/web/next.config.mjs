/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // The API base URL is the only thing the browser bundle needs to know.
  // No secret is ever exposed to the client; every privileged operation goes
  // through the authenticated API.
  env: {
    NEXT_PUBLIC_API_BASE_URL:
      process.env.NEXT_PUBLIC_API_BASE_URL ?? 'http://localhost:8000',
  },
};
export default nextConfig;
