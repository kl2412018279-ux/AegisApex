//C:\Users\hp\aiops-securewatch\dashboard\app\layout.tsx
import React from 'react';
import type { Metadata } from 'next';
import './global.css';
import { Toaster } from 'sonner';

export const metadata: Metadata = {
  title: 'AIOps SecureWatch | SecOps Center',
  description: 'AI-powered network infrastructure telemetry, vulnerability analysis, and change simulation.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-[#0b0f19] text-slate-100 antialiased min-h-screen flex flex-col selection:bg-blue-500 selection:text-white">
        {/* Render children unconstrained so inner page shells (e.g. sidebar + header) control their viewport */}
        <div className="flex-1 flex flex-col min-h-screen w-full overflow-hidden">
          {children}
        </div>

        {/* Global Toast Notification System */}
        <Toaster position="top-right" richColors theme="dark" closeButton />
      </body>
    </html>
  );
}