import type { JobStatus } from "@/lib/api";

const LABEL: Record<JobStatus["status"], string> = {
  pending: "待派送",
  running: "派送中",
  completed: "已完成",
  failed: "失敗",
};

export function JobStatusPill({ status }: { status: JobStatus["status"] }) {
  return <span className={`pill pill-${status}`}>{LABEL[status]}</span>;
}
