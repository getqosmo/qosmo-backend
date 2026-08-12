import type { Metadata, Viewport } from 'next';

import { AppShell } from '@/components/shell';
import './globals.css';

export const metadata: Metadata = {
  title: {
    default: 'MyBot',
    template: '%s · MyBot',
  },
  description: 'Your life. Running itself.',
  applicationName: 'MyBot',
  manifest: '/manifest.webmanifest',
  icons: {
    icon: [
      { url: '/brand/mark.svg', type: 'image/svg+xml' },
      { url: '/brand/icon-192.png', sizes: '192x192', type: 'image/png' },
    ],
    apple: '/brand/icon-180.png',
  },
  openGraph: {
    title: 'MyBot',
    description: 'Your life. Running itself.',
    images: ['/brand/og.png'],
    type: 'website',
  },
  // MyBot holds a person's entire life. It should never be indexed, and no
  // referrer should leak which page of it somebody was on.
  robots: { index: false, follow: false },
  referrer: 'no-referrer',
};

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  themeColor: [
    { media: '(prefers-color-scheme: light)', color: '#fbfaf9' },
    { media: '(prefers-color-scheme: dark)', color: '#131211' },
  ],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}
