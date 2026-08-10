import { CatalogGrid } from "@/components/catalog-grid";
import { PageHeader } from "@/components/page-header";

export default function HomePage() {
  return (
    <div className="space-y-10">
      <PageHeader
        eyebrow="Log 目錄"
        title="廠牌 Log 格式庫"
        subtitle="挑選廠牌、版本與事件型態,即時預覽範例 log,並可批次派送到 Wazuh 或 ELK 驗證偵測規則涵蓋率。"
      />
      <CatalogGrid />
    </div>
  );
}
