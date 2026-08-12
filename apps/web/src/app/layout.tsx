import type { Metadata, Viewport } from 'next';

import { AppShell } from '@/components/shell';
import './globals.css';

export const metadata: Metadata = {
  title: 'MyBot',
  description: 'Your life. Running itself.',
};

export const viewport: Viewport = {
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
