import type { Metadata, Viewport } from "next";
import { Sidebar } from "@/components/sidebar";
import { Providers } from "./providers";
import "./globals.css";

export const metadata: Metadata = {
  title: "CyberRange · 攻防演練平台",
  description:
    "整合 open-source 與 GitHub 資源的攻防演練平台。產生指定廠牌、版本與事件型態的範例日誌，餵給 Wazuh / ELK 驗證 SOC 偵測規則與 AI 引擎效度。",
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  themeColor: "#0a0f1a",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="zh-Hant" suppressHydrationWarning>
      <body suppressHydrationWarning>
        <Providers>
          <Sidebar />
          <main className="md:ml-[240px] min-h-screen pt-20 md:pt-12 px-4 sm:px-6 md:px-10 pb-10 md:pb-16">
            <div className="max-w-7xl mx-auto">{children}</div>
          </main>
        </Providers>
      </body>
    </html>
  );
}
