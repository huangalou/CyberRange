import { JobsTable } from "@/components/jobs-table";
import { PageHeader } from "@/components/page-header";

export default function JobsPage() {
  return (
    <div className="space-y-10">
      <PageHeader
        eyebrow="派送工作"
        title="歷史派送與即時狀態"
        subtitle="背景 worker 會把樣本 log 依設定 sink 串流送出。本頁每 1.5 秒輪詢一次,可即時看到工作進度。"
      />
      <JobsTable />
    </div>
  );
}
