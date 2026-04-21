import { useState } from "react";
import AppSidebar from "@/components/AppSidebar";
import TopBar from "@/components/TopBar";
import { Users, Scan, Bug, Activity, UserPlus, Send, FileText, Trash2, Copy, Check } from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { toast } from "sonner";
import { useAuth } from "@/contexts/AuthContext";

const AdminPanel = () => {
  const [collapsed, setCollapsed] = useState(false);
  const [showInvite, setShowInvite] = useState(false);
  const [inviteEmail, setInviteEmail] = useState("");
  const [generatedLink, setGeneratedLink] = useState("");
  const [copied, setCopied] = useState(false);
  const { userRole, session } = useAuth();
  const queryClient = useQueryClient();

  const { data: users } = useQuery({
    queryKey: ["admin_users"],
    queryFn: async () => {
      const { data } = await supabase.from("admin_users").select("*").order("joined_at", { ascending: false });
      return data || [];
    },
  });

  const { data: scanResults } = useQuery({
    queryKey: ["scan_results"],
    queryFn: async () => {
      const { data } = await supabase.from("scan_results").select("*").order("created_at", { ascending: false });
      return data || [];
    },
  });

  const { data: vulnCount } = useQuery({
    queryKey: ["vulnerabilities_count"],
    queryFn: async () => {
      const { count } = await supabase.from("vulnerabilities").select("*", { count: "exact", head: true });
      return count || 0;
    },
  });

  const { data: systemLogs } = useQuery({
    queryKey: ["system_logs"],
    queryFn: async () => {
      const { data } = await supabase.from("system_logs").select("*").order("sort_order");
      return data || [];
    },
  });

  const removeUserMutation = useMutation({
    mutationFn: async (userId: string) => {
      // Delete from admin_users
      const { error } = await supabase.from("admin_users").delete().eq("id", userId);
      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin_users"] });
      toast.success("User removed successfully");
    },
    onError: () => {
      toast.error("Failed to remove user");
    },
  });

  const activeScans = scanResults?.filter((s) => s.status === "running").length || 0;

  const stats = [
    { label: "TOTAL USERS", value: users?.length || 0, icon: Users, color: "text-primary" },
    { label: "TOTAL SCANS", value: scanResults?.length || 0, icon: Scan, color: "text-primary" },
    { label: "VULNERABILITIES", value: vulnCount, icon: Bug, color: "text-primary" },
    { label: "ACTIVE SCANS", value: activeScans, icon: Activity, color: "text-chart-4" },
  ];

  const handleGenerateInvite = async () => {
    if (!session?.access_token) {
      toast.error("Not authenticated");
      return;
    }
    try {
      const res = await fetch("/api/invitations", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${session.access_token}`,
        },
        body: JSON.stringify({ email: inviteEmail || null }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to generate invitation");
      const link = `${window.location.origin}/invite/${data.token}`;
      setGeneratedLink(link);
      toast.success("Invitation link generated");
    } catch (err: any) {
      toast.error(err.message || "Failed to generate invitation");
    }
  };

  const handleCopyLink = () => {
    navigator.clipboard.writeText(generatedLink);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
    toast.success("Link copied to clipboard");
  };

  const handleCloseInvite = () => {
    setShowInvite(false);
    setInviteEmail("");
    setGeneratedLink("");
    setCopied(false);
  };

  const formatDate = (dateStr: string) => {
    const d = new Date(dateStr);
    return d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
  };

  const formatDateTime = (dateStr: string) => {
    const d = new Date(dateStr);
    return `${d.toLocaleDateString("en-US", { month: "short", day: "numeric" })}, ${d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", hour12: false })}`;
  };

  return (
    <div className="flex h-screen overflow-hidden">
      <AppSidebar collapsed={collapsed} onToggle={() => setCollapsed(!collapsed)} activePage="admin" />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar />
        <main className="flex-1 overflow-y-auto p-8">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h1 className="text-2xl font-bold text-foreground mb-1">Admin Panel</h1>
              <p className="text-muted-foreground">System administration and user management</p>
            </div>
            <button
              onClick={() => setShowInvite(!showInvite)}
              className="flex items-center gap-2 bg-primary text-primary-foreground px-5 py-2.5 rounded-lg font-medium hover:bg-primary/90 transition-colors"
            >
              <UserPlus className="w-4 h-4" />
              Invite User
            </button>
          </div>

          {showInvite && (
            <div className="bg-card border border-border rounded-xl p-5 mb-6">
              {!generatedLink ? (
                <div className="flex items-end gap-4">
                  <div className="flex-1">
                    <label className="text-sm text-muted-foreground mb-1 block">Email (optional)</label>
                    <input
                      type="email"
                      placeholder="user@example.com"
                      value={inviteEmail}
                      onChange={(e) => setInviteEmail(e.target.value)}
                      className="w-full bg-background border border-border rounded-lg px-4 py-2.5 text-foreground focus:outline-none focus:border-primary"
                    />
                  </div>
                  <button
                    onClick={handleGenerateInvite}
                    className="flex items-center gap-2 bg-primary text-primary-foreground px-5 py-2.5 rounded-lg font-medium hover:bg-primary/90 transition-colors whitespace-nowrap"
                  >
                    <Send className="w-4 h-4" />
                    Generate Link
                  </button>
                  <button
                    onClick={handleCloseInvite}
                    className="px-4 py-2.5 rounded-lg border border-border text-muted-foreground hover:text-foreground transition-colors"
                  >
                    Cancel
                  </button>
                </div>
              ) : (
                <div className="space-y-3">
                  <p className="text-sm text-muted-foreground">Copy this link and send it to the user. It expires in 7 days.</p>
                  <div className="flex items-center gap-3">
                    <div className="flex-1 bg-background border border-border rounded-lg px-4 py-2.5 text-sm text-foreground font-mono overflow-hidden text-ellipsis whitespace-nowrap">
                      {generatedLink}
                    </div>
                    <button
                      onClick={handleCopyLink}
                      className="flex items-center gap-2 bg-primary text-primary-foreground px-4 py-2.5 rounded-lg font-medium hover:bg-primary/90 transition-colors whitespace-nowrap"
                    >
                      {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                      {copied ? "Copied!" : "Copy"}
                    </button>
                    <button
                      onClick={handleCloseInvite}
                      className="px-4 py-2.5 rounded-lg border border-border text-muted-foreground hover:text-foreground transition-colors"
                    >
                      Done
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

          <div className="grid grid-cols-4 gap-4 mb-6">
            {stats.map((stat) => {
              const Icon = stat.icon;
              return (
                <div key={stat.label} className="bg-card border border-border rounded-xl p-5">
                  <div className="flex items-center justify-between mb-3">
                    <p className="text-xs text-muted-foreground font-semibold tracking-wider">{stat.label}</p>
                    <Icon className={`w-5 h-5 ${stat.color}`} />
                  </div>
                  <p className="text-3xl font-bold text-foreground">{stat.value}</p>
                </div>
              );
            })}
          </div>

          <div className="bg-card border border-border rounded-xl p-5 mb-6">
            <h2 className="text-foreground font-semibold mb-4">User Management</h2>
            <table className="w-full">
              <thead>
                <tr className="text-muted-foreground text-xs uppercase tracking-wider">
                  <th className="text-left py-3 px-2">Name</th>
                  <th className="text-left py-3 px-2">Email</th>
                  <th className="text-left py-3 px-2">Role</th>
                  <th className="text-left py-3 px-2">Joined</th>
                  {userRole === "admin" && <th className="text-left py-3 px-2">Actions</th>}
                </tr>
              </thead>
              <tbody>
                {users?.map((user) => (
                  <tr key={user.id} className="border-t border-border">
                    <td className="py-3 px-2 text-foreground font-medium">{user.name}</td>
                    <td className="py-3 px-2 text-muted-foreground">{user.email}</td>
                    <td className="py-3 px-2">
                      <span
                        className={`text-xs px-2.5 py-1 rounded font-medium ${
                          user.role === "Admin"
                            ? "bg-primary/20 text-primary"
                            : "bg-green-500/20 text-green-400"
                        }`}
                      >
                        {user.role}
                      </span>
                    </td>
                    <td className="py-3 px-2 text-muted-foreground">{formatDate(user.joined_at)}</td>
                    {userRole === "admin" && (
                      <td className="py-3 px-2">
                        {user.role === "User" && (
                          <button
                            onClick={() => removeUserMutation.mutate(user.id)}
                            className="flex items-center gap-1.5 text-muted-foreground hover:text-red-400 transition-colors text-sm"
                          >
                            <Trash2 className="w-4 h-4" />
                            Remove
                          </button>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Recent Scans */}
          <div className="bg-card border border-border rounded-xl p-5 mb-6">
            <h2 className="text-foreground font-semibold mb-4">Recent Scans (All Users)</h2>
            <table className="w-full">
              <thead>
                <tr className="text-muted-foreground text-xs uppercase tracking-wider">
                  <th className="text-left py-3 px-2">Name</th>
                  <th className="text-left py-3 px-2">Target</th>
                  <th className="text-left py-3 px-2">Tool</th>
                  <th className="text-left py-3 px-2">Status</th>
                  <th className="text-left py-3 px-2">Created By</th>
                  <th className="text-left py-3 px-2">Date</th>
                </tr>
              </thead>
              <tbody>
                {scanResults?.map((scan) => (
                  <tr key={scan.id} className="border-t border-border">
                    <td className="py-3 px-2 text-foreground font-medium">{scan.name}</td>
                    <td className="py-3 px-2 text-muted-foreground text-sm">{scan.target}</td>
                    <td className="py-3 px-2 text-primary font-semibold text-sm">{scan.tool.toUpperCase()}</td>
                    <td className="py-3 px-2">
                      <span className="flex items-center gap-1.5 text-sm">
                        <span className="w-2 h-2 rounded-full bg-green-500" />
                        <span className="text-green-400">Low</span>
                      </span>
                    </td>
                    <td className="py-3 px-2 text-muted-foreground text-sm">jehanmoshle@gmail.com</td>
                    <td className="py-3 px-2 text-muted-foreground text-sm">{formatDateTime(scan.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* System Logs */}
          <div className="bg-card border border-border rounded-xl p-5">
            <div className="flex items-center gap-2 mb-4">
              <FileText className="w-4 h-4 text-muted-foreground" />
              <h2 className="text-foreground font-semibold">System Logs</h2>
            </div>
            <div className="bg-[#0a0a0a] rounded-lg p-4 font-mono text-sm space-y-1">
              {systemLogs?.map((log) => (
                <p key={log.id}>
                  <span className="text-green-400">[{new Date(log.timestamp).toISOString()}]</span>{" "}
                  <span className="text-muted-foreground">{log.message}</span>
                </p>
              ))}
            </div>
          </div>
        </main>
      </div>
    </div>
  );
};

export default AdminPanel;
