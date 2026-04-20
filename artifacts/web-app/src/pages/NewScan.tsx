import { useState } from "react";
import { Globe, Terminal, Zap, Shield, Maximize2, Loader2 } from "lucide-react";
import { useMutation } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import AppSidebar from "@/components/AppSidebar";
import TopBar from "@/components/TopBar";
import { cn } from "@/lib/utils";

const GATEWAY_URL = "http://localhost:8080";

const tools = [
  { key: "NMAP", label: "Nmap", desc: "Network discovery and port scanning", icon: Globe },
  { key: "SQLMAP", label: "SQLmap", desc: "SQL injection detection and exploitation", icon: Terminal },
  { key: "FFUF", label: "FFUF", desc: "Fast web fuzzer for content discovery", icon: Zap },
  { key: "NIKTO", label: "Nikto", desc: "Web server vulnerability scanner", icon: Shield },
  { key: "FULL", label: "Full Scan", desc: "Comprehensive scan using all tools", icon: Maximize2 },
];

const NewScan = () => {
  const [collapsed, setCollapsed] = useState(false);
  const [scanName, setScanName] = useState("");
  const [target, setTarget] = useState("");
  const [description, setDescription] = useState("");
  const [selectedTool, setSelectedTool] = useState("");
  const [options, setOptions] = useState("");
  const navigate = useNavigate();

  const mutation = useMutation({
    mutationFn: async () => {
      const { data: { session } } = await supabase.auth.getSession();
      if (!session?.access_token) {
        throw new Error("Not authenticated. Please log in.");
      }

      const response = await fetch(`${GATEWAY_URL}/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${session.access_token}`,
        },
        body: JSON.stringify({
          name: scanName,
          target,
          tool: selectedTool,
          description,
          options,
        }),
      });

      if (!response.ok) {
        const err = await response.json().catch(() => ({ detail: "Unknown error" }));
        throw new Error(err.detail || `Gateway error: ${response.status}`);
      }

      return response.json();
    },
    onSuccess: () => {
      toast.success("Scan started! Redirecting to results...");
      navigate("/scan-results");
    },
    onError: (err: Error) => {
      toast.error(err.message || "Failed to start scan");
    },
  });

  const canSubmit = scanName.trim() && target.trim() && selectedTool && !mutation.isPending;

  return (
    <div className="flex h-screen bg-background text-foreground">
      <AppSidebar collapsed={collapsed} onToggle={() => setCollapsed(!collapsed)} activePage="new-scan" />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar />
        <main className="flex-1 overflow-y-auto p-6">

          {/* Target Configuration */}
          <div className="bg-card border border-border rounded-xl p-6 mb-6">
            <div className="flex items-center gap-2 mb-6">
              <Globe className="w-5 h-5 text-primary" />
              <h2 className="text-lg font-semibold text-primary">Target Configuration</h2>
            </div>

            <div className="space-y-5">
              <div>
                <label className="text-sm text-muted-foreground mb-1.5 block">Scan Name</label>
                <input
                  value={scanName}
                  onChange={(e) => setScanName(e.target.value)}
                  placeholder="e.g. Production Server Scan"
                  className="w-full bg-background border border-border rounded-lg px-4 py-2.5 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>
              <div>
                <label className="text-sm text-muted-foreground mb-1.5 block">Target URL or IP Address</label>
                <input
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="e.g. https://example.com or 192.168.1.1"
                  className="w-full bg-background border border-primary/50 rounded-lg px-4 py-2.5 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>
              <div>
                <label className="text-sm text-muted-foreground mb-1.5 block">Description (optional)</label>
                <input
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Brief description of this scan"
                  className="w-full bg-background border border-border rounded-lg px-4 py-2.5 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>
              <div>
                <label className="text-sm text-muted-foreground mb-1.5 block">Extra Options (optional)</label>
                <input
                  value={options}
                  onChange={(e) => setOptions(e.target.value)}
                  placeholder="e.g. --top-ports 100"
                  className="w-full bg-background border border-border rounded-lg px-4 py-2.5 text-sm font-mono text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>
            </div>
          </div>

          {/* Tool Selection */}
          <div className="bg-card border border-border rounded-xl p-6 mb-6">
            <div className="flex items-center gap-2 mb-4">
              <Terminal className="w-5 h-5 text-muted-foreground" />
              <h2 className="text-lg font-semibold">Select Scan Tool</h2>
            </div>
            <div className="grid grid-cols-3 gap-4">
              {tools.map((tool) => {
                const Icon = tool.icon;
                const isSelected = selectedTool === tool.key;
                return (
                  <button
                    key={tool.key}
                    onClick={() => setSelectedTool(tool.key)}
                    className={cn(
                      "flex flex-col items-start gap-3 p-5 rounded-xl border transition-all text-left",
                      isSelected
                        ? "border-primary bg-primary/10"
                        : "border-border bg-card hover:border-muted-foreground"
                    )}
                  >
                    <Icon className={cn("w-6 h-6", isSelected ? "text-primary" : "text-primary/60")} />
                    <div>
                      <p className="font-medium text-sm">{tool.label}</p>
                      <p className="text-xs text-muted-foreground mt-1">{tool.desc}</p>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Submit */}
          <button
            disabled={!canSubmit}
            onClick={() => {
              if (!canSubmit) {
                toast.error("Please fill in Scan Name, Target, and select a tool");
                return;
              }
              mutation.mutate();
            }}
            className={cn(
              "flex items-center gap-2 px-8 py-3 rounded-lg font-medium text-sm transition-all",
              canSubmit
                ? "bg-primary text-primary-foreground hover:bg-primary/90"
                : "bg-muted text-muted-foreground cursor-not-allowed opacity-50"
            )}
          >
            {mutation.isPending ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Starting Scan...
              </>
            ) : (
              <>
                <Globe className="w-4 h-4" />
                Start Scan
              </>
            )}
          </button>

          {mutation.isPending && (
            <div className="bg-card border border-primary/30 rounded-xl p-5 mt-4">
              <div className="flex items-center gap-3 mb-2">
                <div className="w-3 h-3 bg-primary rounded-full animate-pulse" />
                <p className="text-primary font-semibold">Dispatching Scan...</p>
              </div>
              <p className="text-muted-foreground text-sm">
                Sending scan request for <span className="text-foreground font-mono">{target}</span> to the gateway.
                Results update every 5 seconds in Scan Results.
              </p>
            </div>
          )}

          <div className="mt-4 text-xs text-muted-foreground bg-muted/30 rounded-lg px-4 py-3 border border-border">
            <strong>Note:</strong> Scans run in the background. The Scan Results page polls for updates automatically every 5 seconds.
          </div>

        </main>
      </div>
    </div>
  );
};

export default NewScan;
