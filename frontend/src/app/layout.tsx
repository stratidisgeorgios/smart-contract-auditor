import type { Metadata } from 'next'
import './globals.css' // Import global styles so that it applies to every page in the app

export const metadata: Metadata = {
  title: 'Smart Contract Auditor',
  description: 'LLM + Slither powered security auditing for Solidity smart contracts',
}

export default function RootLayout({ children }: { children: React.ReactNode }) { // RootLayout wraps every single page in the app.
  return (
    <html lang="en">
      <body className="antialiased">{children}</body>
    </html>
  )
}
