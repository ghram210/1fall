import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { useAuth } from "@/contexts/AuthContext";
import AppSidebar from "@/components/AppSidebar";
import TopBar from "@/components/TopBar";
import { Eye, Trash2, CheckCircle2, Loader2, Clock, AlertCircle, ChevronDown, ChevronUp } from "lucide-react";

interface ScanResult {
  id: string;
  name: string;
  target: string;
  tool: string;
  status: string;
  options: string;
  description: string;
  raw_output: string | null;
  started_at: string;
  completed_at: string | null;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  total_findings: number;
  created_at: string;
}

const statusConfig: Record<string, { label: string; icon: React.ReactNode; className: string }> = {
  running: {
    label: "Running",
    icon: <Loader2 className="w-3 h-3 animate-spin" />,
    className: "bg-blue-500/20 text-blue-400",
  },
  completed: {
    label: "Completed",
    icon: <CheckCircle2 className="w-3 h-3" />,
    className: "bg-emerald-500/20 text-emerald-400",
  },
  failed: {
    label: "Failed",
    icon: <AlertCircle className="w-3 h-3" />,
    className: "bg-red-500/20 text-red-400",
  },
  pending: {
    label: "Pending",
    icon: <Clock className="w-3 h-3" />,
    className: "bg-yellow-500/20 text-yellow-400",
  },
};

const ScanResults = () => {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [showRawOutput, setShowRawOutput] = useState(false);
  const queryClient = useQueryClient();
  const { userRole } = useAuth();

  const { data: scans = [] } = useQuery({
    queryKey: ["scan_results"],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("scan_results")
        .select("*")
        .order("created_at", { ascending: false });
      if (error) throw error;
      return data as ScanResult[];
    },
    refetchInterval: 5000,
  });

  const hasRunningScans = scans.some((s) => s.status === "running" || s.status === "pending");

  const selectedScanUpdated = selectedScan
    ? (scans.find((s) => s.id === selectedScan.id) ?? selectedScan)
    : null;

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await supabase.from("scan_results").delete().eq("id", id);
      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scan_results"] });
      setSelectedScan(null);
    },
  });

  const formatDate = (dateStr: string) => {
    const d = new Date(dateStr);
    return d.toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  const formatShortDate = (dateStr: string) => {
    const d = new Date(dateStr);
    return `${d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })} ${d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", hour12: false })}`;
  };

  const getStatus = (status: string) => statusConfig[status] ?? statusConfig["pending"];

  return (
    <div className="flex h-screen overflow-hidden">
      <AppSidebar
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
        activePage="scan-results"
      />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar />
        <main className="flex-1 overflow-y-auto p-6 space-y-6">
          <div className="flex items-center justify-between">
            <h1 className="text-2xl font-bold text-foreground">Scan Results</h1>
            {hasRunningScans && (
              <div className="flex items-center gap-2 text-sm text-blue-400">
                <Loader2 className="w-4 h-4 animate-spin" />
                Scans running — updating every 5 seconds
              </div>
            )}
          </div>

          <div className="flex gap-6">
            {/* Scan List */}
            <div className="flex-1 space-y-3">
              {scans.length === 0 ? (
                <div className="bg-card border border-border rounded-lg p-8 text-center text-muted-foreground">
                  No scans found. Start a new scan from the sidebar.
                </div>
              ) : (
                scans.map((scan) => {
                  const st = getStatus(scan.status);
                  return (
                    <div
                      key={scan.id}
                      onClick={() => { setSelectedScan(scan); setShowRawOutput(false); }}
                      className={`bg-card border rounded-lg p-4 cursor-pointer transition-colors hover:border-primary/50 ${
                        selectedScanUpdated?.id === scan.id ? "border-primary" : "border-border"
                      }`}
                    >
                      <div className="flex items-start justify-between">
                        <div className="space-y-2">
                          <div className="flex items-center gap-3">
                            <span className="font-semibold text-foreground">{scan.name}</span>
                            <span className={`inline-flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded-full ${st.className}`}>
                              {st.icon}
                              {st.label}
                            </span>
                          </div>
                          <div className="flex items-center gap-4 text-sm text-muted-foreground">
                            <span>Target: <span className="font-mono text-foreground">{scan.target}</span></span>
                            <span>Tool: <span className="text-primary">{scan.tool}</span></span>
                            <span>{formatShortDate(scan.created_at)}</span>
                          </div>
                          {scan.status === "completed" && (
                            <div className="flex items-center gap-3 text-sm">
                              <span className="flex items-center gap-1">
                                <span className="w-2 h-2 rounded-full bg-red-500" />
                                <span className="text-foreground">{scan.critical_count}</span>
                              </span>
                              <span className="flex items-center gap-1">
                                <span className="w-2 h-2 rounded-full bg-orange-500" />
                                <span className="text-foreground">{scan.high_count}</span>
                              </span>
                              <span className="flex items-center gap-1">
                                <span className="w-2 h-2 rounded-full bg-yellow-500" />
                                <span className="text-foreground">{scan.medium_count}</span>
                              </span>
                              <span className="flex items-center gap-1">
                                <span className="w-2 h-2 rounded-full bg-blue-500" />
                                <span className="text-foreground">{scan.low_count}</span>
                              </span>
                              <span className="text-muted-foreground">{scan.total_findings} findings</span>
                            </div>
                          )}
                          {scan.status === "running" && (
                            <div className="w-48 bg-muted rounded-full h-1.5 overflow-hidden">
                              <div className="bg-blue-500 h-full rounded-full animate-pulse" style={{ width: "70%" }} />
                            </div>
                          )}
                        </div>
                        {userRole === "admin" && (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              deleteMutation.mutate(scan.id);
                            }}
                            className="text-destructive hover:text-destructive/80 transition-colors p-1"
                          >
                            <Trash2 className="w-5 h-5" />
                          </button>
                        )}
                      </div>
                    </div>
                  );
                })
              )}
            </div>

            {/* Detail Panel */}
            <div className="w-[380px] shrink-0">
              <div className="bg-card border border-border rounded-lg p-6 sticky top-0 max-h-[calc(100vh-8rem)] overflow-y-auto">
                {selectedScanUpdated ? (
                  <div className="space-y-4">
                    <div className="flex items-center gap-2 text-foreground font-semibold">
                      <Eye className="w-5 h-5" />
                      Scan Details
                    </div>

                    <div className="space-y-3 text-sm">
                      <div>
                        <p className="text-xs text-muted-foreground">Name</p>
                        <p className="text-foreground font-medium">{selectedScanUpdated.name}</p>
                      </div>
                      <div>
                        <p className="text-xs text-muted-foreground">Target</p>
                        <p className="text-foreground font-mono text-xs break-all">{selectedScanUpdated.target}</p>
                      </div>
                      <div>
                        <p className="text-xs text-muted-foreground">Tool</p>
                        <p className="text-primary font-mono">{selectedScanUpdated.tool}</p>
                      </div>
                      <div>
                        <p className="text-xs text-muted-foreground">Status</p>
                        <span className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full font-medium ${getStatus(selectedScanUpdated.status).className}`}>
                          {getStatus(selectedScanUpdated.status).icon}
                          {getStatus(selectedScanUpdated.status).label}
                        </span>
                      </div>
                      {selectedScanUpdated.options && (
                        <div>
                          <p className="text-xs text-muted-foreground">Options</p>
                          <p className="text-foreground font-mono text-xs">{selectedScanUpdated.options}</p>
                        </div>
                      )}
                      <div>
                        <p className="text-xs text-muted-foreground">Started</p>
                        <p className="text-foreground">{formatDate(selectedScanUpdated.started_at)}</p>
                      </div>
                      {selectedScanUpdated.completed_at && (
                        <div>
                          <p className="text-xs text-muted-foreground">Completed</p>
                          <p className="text-foreground">{formatDate(selectedScanUpdated.completed_at)}</p>
                        </div>
                      )}
                      <div>
                        <p className="text-xs text-muted-foreground">Total Findings</p>
                        <p className="text-foreground font-semibold">{selectedScanUpdated.total_findings}</p>
                      </div>
                    </div>

                    {/* Raw Output */}
                    {selectedScanUpdated.raw_output && (
                      <div className="border-t border-border pt-4">
                        <button
                          onClick={() => setShowRawOutput(!showRawOutput)}
                          className="flex items-center justify-between w-full text-sm font-medium text-muted-foreground hover:text-foreground transition-colors"
                        >
                          <span>Raw Output</span>
                          {showRawOutput ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                        </button>
                        {showRawOutput && (
                          <pre className="mt-3 bg-background border border-border rounded-lg p-3 text-xs font-mono text-foreground whitespace-pre-wrap break-all overflow-auto max-h-64">
                            {selectedScanUpdated.raw_output}
                          </pre>
                        )}
                      </div>
                    )}

                    {selectedScanUpdated.status === "running" && (
                      <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-3 text-xs text-blue-400">
                        <div className="flex items-center gap-2">
                          <Loader2 className="w-3 h-3 animate-spin" />
                          Scan in progress. Updating automatically...
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center py-12 text-muted-foreground space-y-3">
                    <Eye className="w-10 h-10 opacity-40" />
                    <p className="text-sm">Select a scan to view details</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
};

export default ScanResults;
