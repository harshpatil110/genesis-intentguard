import "./globals.css";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "IntentGuard // PS 01 Forensic X-Ray & Policy Gateway",
  description:
    "GENESIS 2.0 | Track: EVA 03 | Problem Statement PS 01 — Separating Data from Authority: Securing AI Agents Against Indirect Prompt Injection",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-[#FAF9F6] text-[#1C1917] antialiased">
        {children}
      </body>
    </html>
  );
}
